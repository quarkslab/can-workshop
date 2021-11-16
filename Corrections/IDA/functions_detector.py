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


    print('(+) processing defined data')
    while nea < sto_addr:

        nea = find_defined(nea,SEARCH_DOWN)
        eaf = ida_bytes.get_flags(nea)
        if ida_bytes.is_code(eaf):
            try:
                if ida_funcs.get_func(nea)==None:
                    add_func(nea)
                    print('(+) successfully created function at %x'%nea)
            except: 
                print('[!] could not create function at %x'%nea)

    sta_addr = nea = s.start_ea
    sto_addr = s.end_ea

    print('(+) processing undefined data')
    while nea < sto_addr:

        nea = find_unknown(nea,SEARCH_DOWN)
        itype = get_itype(nea)
        if itype == PUSH_ITYPE:
            create_insn(ea)
            try: 
                add_func(nea)
                print('(+) successfully created function at %x'%nea)
            except: 
                print('[!] could not create function at %x'%nea)

if __name__ == '__main__': 


    s = ida_segment.get_first_seg()
    while (s!=None):
        if (s.perm & ida_segment.SEGPERM_EXEC):
            print('(+) processing segment %s '%ida_segment.get_segm_name(s))
            process_segment(s) 
        s = ida_segment.get_next_seg(s.start_ea)

