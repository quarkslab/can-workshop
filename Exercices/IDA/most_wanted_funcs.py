import ida_funcs
import idautils
import idaapi
import operator



###
FunctionsPools = list()
XrefPools = list()
###


###
PODIUM_LEN = 10
###

def GetXrefCount(f_ea):
    xref_g=idautils.XrefsTo(f_ea)
    count=0
    while True:
        try:
            next(xref_g)
            count +=1
        except StopIteration:
            break

    return count


inf = idaapi.get_inf_structure()
ea = inf.min_ea

while True:
    f = ida_funcs.get_next_func(ea)
    if f == None:
        break
    FunctionsPools.append(f.start_ea)
    ea = f.start_ea

print('[+] find %d function'%len(FunctionsPools)) 

XrefPools = [(f_ea,GetXrefCount(f_ea)) for f_ea in FunctionsPools] 

XrefPools = sorted(XrefPools,key=operator.itemgetter(1),reverse=True)

for xp in XrefPools[:PODIUM_LEN]:
    print('%x with %d xref'%(xp[0],xp[1]))


