from unicorn import * 
from unicorn.arm_const import *
from capstone import * 
from capstone.arm_const import *
import json
import hexdump
import argparse



segments = {
    0:0x7ffffff,
    0x10000000:0x3FFFFFF,
    0x14000000:0x17FFFFFF,
    0x40000000:0x7FFFF,
    0x40080000:0x7efff,
    0x400FF000:0xFFFF,
    0x42000000:0x1FFFFFF,
    0xE0000000:0xFFFFF
}


engine = None
disas = None

def print_excption(message,e):
    print('[-] ',message)
    for l in e.__str__().split('\n'):
            print('\t[-] ',l)


def handler_instruction(engine,addr,size,user_data):
    
    opline = engine.mem_read(addr,size)
    insn_cpst=next(user_data.disasm(opline,addr,count=1))
    print("0x%x:\t%s\t%s" %(insn_cpst.address, insn_cpst.mnemonic, insn_cpst.op_str))
#    print_regs()


def handler_read_error(uc,access,addr,value,size,user_data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        print('[%x][!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(pc,addr,size))
        return False

def handler_write_error(uc,access,addr,size,value,user_data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        print('[%x][!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(pc,value,addr))
        return False

def handler_write(uc,access,addr,size,value,user_data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        print('[%x]Write addr : write value 0x%.8X at address 0x%.8X '%(pc,value,addr))
        return False

def handler_read(uc,access,addr,value,size,user_data):

        pc=uc.reg_read(UC_ARM_REG_PC)
        print('[%x] Read Access : read value at 0x%.8X for size %d'%(pc,addr,size))
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
                    user_data=disas)
    engine.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                    handler_write_error,
                    user_data=disas)

    engine.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                    handler_write_error,
                    user_data=disas)

    engine.hook_add(UC_HOOK_MEM_WRITE,
                    handler_write,
                    user_data=disas)

    engine.hook_add(UC_HOOK_MEM_READ,
                    handler_read,
                    user_data=disas)





def init_unicorn(mapping_path:str):

    global engine, segments

    engine = Uc(UC_ARCH_ARM,UC_MODE_THUMB)

    page_size = engine.query(UC_QUERY_PAGE_SIZE)

    for addr,size in segments.items():

        base_mapping = addr & ~(page_size-1)
        delta = base_mapping - addr
        nb_pages, more_required = divmod(size+delta,page_size)
        if more_required: nb_pages+=1

        try:
            engine.mem_map(base_mapping,nb_pages*page_size)
            print('[+] mapped [%x:%x]'%(base_mapping,(base_mapping+nb_pages*page_size)))
        except UcError as e:
            print_excption("Error in mapping %x %d"%(base_mapping,nb_pages*page_size),e)



    with open(mapping_path) as fmap:
        mappings = json.load(fmap)

    for k,v in dict(mappings).items():
        with open(v,'rb') as fbin:
            print(k)
            engine.mem_write(int(k,16),
                             fbin.read())


def print_regs():

    global engine

    print('r0: %.8X r1: %.8X r2: %.8X r3 %.8X'%(engine.reg_read(UC_ARM_REG_R0),
                                         engine.reg_read(UC_ARM_REG_R1),
                                         engine.reg_read(UC_ARM_REG_R2),
                                         engine.reg_read(UC_ARM_REG_R3)))

    
    print('r4: %.8X r5: %.8X r6: %.8X r7 %.8X'%(engine.reg_read(UC_ARM_REG_R4),
                                         engine.reg_read(UC_ARM_REG_R5),
                                         engine.reg_read(UC_ARM_REG_R6),
                                         engine.reg_read(UC_ARM_REG_R7)))



    print('r8: %.8X r9: %.8X r10: %.8X r11 %.8X'%(engine.reg_read(UC_ARM_REG_R8),
                                         engine.reg_read(UC_ARM_REG_R9),
                                         engine.reg_read(UC_ARM_REG_R10),
                                         engine.reg_read(UC_ARM_REG_R11)))

    print('r12: %.8X r12: %.8X r13: %.8X r14 %.8X'%(engine.reg_read(UC_ARM_REG_R12),
                                         engine.reg_read(UC_ARM_REG_R12),
                                         engine.reg_read(UC_ARM_REG_R13),
                                         engine.reg_read(UC_ARM_REG_R14)))


def emulate(start,stop,count=0,timeout=0.10,regs_conf=None):

    global engine

    print(regs_conf)

    if regs_conf:

        with open(regs_conf) as f_regs:
            jsonf_regs = json.load(f_regs)

        engine.reg_write(UC_ARM_REG_R0,int(jsonf_regs['r0'],16))
        engine.reg_write(UC_ARM_REG_R1,int(jsonf_regs['r1'],16))
        engine.reg_write(UC_ARM_REG_R2,int(jsonf_regs['r2'],16))
        engine.reg_write(UC_ARM_REG_R3,int(jsonf_regs['r3'],16))
        engine.reg_write(UC_ARM_REG_R4,int(jsonf_regs['r4'],16))
        engine.reg_write(UC_ARM_REG_R5,int(jsonf_regs['r5'],16))
        engine.reg_write(UC_ARM_REG_R6,int(jsonf_regs['r6'],16))
        engine.reg_write(UC_ARM_REG_R7,int(jsonf_regs['r7'],16))
        engine.reg_write(UC_ARM_REG_R8,int(jsonf_regs['r8'],16))
        engine.reg_write(UC_ARM_REG_R9,int(jsonf_regs['r9'],16))
        engine.reg_write(UC_ARM_REG_R10,int(jsonf_regs['r10'],16))
        engine.reg_write(UC_ARM_REG_R11,int(jsonf_regs['r11'],16))
        engine.reg_write(UC_ARM_REG_R12,int(jsonf_regs['r12'],16))
        engine.reg_write(UC_ARM_REG_R13,int(jsonf_regs['r13'],16))
        engine.reg_write(UC_ARM_REG_R14,int(jsonf_regs['r14'],16))
        engine.reg_write(UC_ARM_REG_R15,start|1)

    try:
        engine.emu_start(begin=start|1,until=stop,count=0)
    except UcError as e:
        print_excption("Error in start()",e)

    print('\n\n')

def post_emulation():

    pass

    
if __name__ == '__main__':



    argparser = argparse.ArgumentParser()
    argparser.add_argument("-s","--start", help="emulation start address",required=True)
    argparser.add_argument("-e","--end", help="emulation end address",required=True)
    argparser.add_argument("-r","--registers", help="registers json file path",required=True)
    argparser.add_argument("-t","--trace", help="generate a trace",action='store_true')
    argparser.add_argument("-m","--mappings", help='mapping information json record {"addr":"path"}',required=True)

    args = argparser.parse_args()

    init_unicorn(args.mappings)

    if args.trace:
        init_capstone()
        configure_unicorn_handlers()


    emulate(int(args.start,16),
            int(args.end,16),
            regs_conf=args.registers)

    post_emulation()







