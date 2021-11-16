from ida_ua import * 
from ida_idaapi import * 
import ida_segment


PUSH_ITYPE = 0x2B


def get_itype(ea):
    insn = insn_t() 
    try:
        decode_insn(insn,ea) 
        return insn.itype 
    except: 
        return -1 




def process_segment(s):

    sta_addr = nea = s.start_ea
    sto_addr = s.end_ea


    # first search on code defined areas
    while nea < sto_addr:

        # TODO: find defined not belonging to a function
        #       then try to create a func
        pass
        
    sta_addr = nea = s.start_ea
    sto_addr = s.end_ea

    while nea < sto_addr:

        # TODO: no search on every unknown areas
        #       use heuristic to see if it could be code, 
        #       disassemble and then try to create a function. 
        pass
       
if __name__ == '__main__': 


    s = ida_segment.get_first_seg()
    while (s!=None):
        if (s.perm & ida_segment.SEGPERM_EXEC):
            print('(+) processing segment %s '%ida_segment.get_segm_name(s))
            process_segment(s) 
        s = ida_segment.get_next_seg(s.start_ea)

