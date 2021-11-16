import ida_search
import ida_segment
import ida_funcs
import idaapi



def search_text(regex,start_ea,end_ea):

    occurences = []

    nea=start_ea
    while True:
            nea = ida_search.find_text(nea,0,0,regex,
                                       ida_search.SEARCH_DOWN|ida_search.SEARCH_REGEX)
            if nea == idaapi.BADADDR or nea >= end_ea:
                break
            else:
                try:
                    occurences.append(ida_funcs.get_func_name(nea))
                except:
                    print('[!] Warning %x not belongs to a function.')

    return occurences


if __name__ == '__main__':

    s = ida_segment.get_segm_by_name('ProgramFlash')

    ida_
    occ_cmp_10 = search_text('.*0x10.*',s.start_ea, s.end_ea)
    occ_cmp_20 = search_text('.*0x20.*',s.start_ea, s.end_ea)

    results = filter(lambda fname: fname not in occ_cmp_20, occ_cmp_10)

    for r in results: 
        print('[+] found %d results'%len(r))
        print('\t %s'%r)

