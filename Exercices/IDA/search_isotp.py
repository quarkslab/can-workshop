import ida_search
import ida_segment
import ida_funcs
import idaapi



def search_text(regex,start_ea,end_ea):

    occurences = []

    nea=start_ea
    while True:

        # TODO: write here code to search regex accross areas

        pass

    return occurences

if __name__ == '__main__':

    s = ida_segment.get_segm_by_name('ProgramFlash')

    occ_cmp_10 = search_text('.*0x10.*',s.start_ea, s.end_ea)
    occ_cmp_20 = search_text('.*0x20.*',s.start_ea, s.end_ea)

    # TODO: cross results

    results = filter(lambda fname: fname not in occ_cmp_20, occ_cmp_10)


