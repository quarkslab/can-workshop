from unicorn import * 
from unicorn.arm_const import *
from capstone import * 
from capstone.arm_const import *
import json
import hexdump
import argparse



segments = {
    #base_addr:size,
}


engine = None
disas = None

def print_excption(message,e):
    print('[-] ',message)
    for l in e.__str__().split('\n'):
            print('\t[-] ',l)


def handler_instruction(engine,addr,size,user_data):
    # complete here 
    pass

def handler_read_error(uc,access,addr,value,size,user_data):
    # complete here 
    return False

def handler_write_error(uc,access,addr,size,value,user_data):
    # complete here 
    return False

def init_capstone():

    global disas

    disas = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    disas.detail = True


def configure_unicorn_handlers():

    global engine, disas

    engine.hook_add(UC_HOOK_CODE,
                    handler_instruction,
                    user_data=disas)

    engine.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                    handler_read_error,
                    user_data=None)
    engine.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                    handler_write_error,
                    user_data=None)



def init_unicorn(firmware_path,base_addr):

    global engine, segments

    engine = None # Instantiate unicorn engine 

    page_size = 0 # Get page size information from unicorn engine

    for addr,size in segments.items():
        # compute here the base address 
        # and the segment size for each entry. 

        # unicorn require with a base address and a size
        # aligned on the page size.

        
        try:
            #map here your segment with their correct parameters (base address and size)
            pass
        except UcError as e:
            print_excption("Error in mapping",e)

        # don't forget to write the firmware inside the engine memory


def emulate(start,stop,count=0,timeout=0.10):

    global engine

    # configure here the registers.

    try:
        # start the engine here 
        pass
    except UcError as e:
        print_excption("Error in execution",e)



def post_emulation():
    # here you can perform operation 
    # once the execution has been achieved
    pass


if __name__ == '__main__':



    argparser = argparse.ArgumentParser()
    argparser.add_argument("-f","--firmware", help="firmware path",required=True)
    argparser.add_argument("-b","--baseaddr", help="firmware base address",required=True)
    argparser.add_argument("-s","--start", help="emulation start address",required=True)
    argparser.add_argument("-e","--end", help="emulation end address",required=True)
    argparser.add_argument("-r","--registers", help="registers json file path",required=True)
    argparser.add_argument("-t","--trace", help="generate a trace",action='store_true')

    args = argparser.parse_args()

    init_unicorn(args.firmware,int(args.baseaddr,16))

    if args.trace:
        init_capstone()
        configure_unicorn_handlers()


    emulate(int(args.start,16),
            int(args.end,16),
            regs_conf=args.registers)

    post_emulation()







