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


def handler_read_error(uc,access,addr,value,size,user_data):
        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('[!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(addr,size))
        return False

def handler_write_error(uc,access,addr,size,value,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('[!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(value,addr))
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



def init_unicorn(firmware_path,base_addr):

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

    with open(firmware_path,'rb') as f_firmware:
        engine.mem_write(base_addr,f_firmware.read())


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

    global engine

#    hexdump.hexdump(engine.mem_read(0x1FFFA0B4,0x200))
    with open('../Triton/can_struct.bin','wb+') as fout:
        fout.write(engine.mem_read(0x1FFFA0B8,0x200))


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







