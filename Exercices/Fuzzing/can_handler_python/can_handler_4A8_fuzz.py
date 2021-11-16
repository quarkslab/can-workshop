from capstone import *
from capstone.arm_const import *
import json
import hexdump
import argparse
import struct
from keystone.arm_const import  *
from keystone import *




DEBUG = True

REGISTERS="./registers.json"

FIRMWARE=""

DRIVER_MSG_PULL = 0x50000000

# Trilogy
engine  = None
disas   = None
ks      = None

# argparser 
args = None

# Limit of execution being executed (0 <=> no limit)
INSN_COUNT = 0

tracing_file = open('/tmp/traces','w+')



# explaination of PSP and MSP : 
# https://gradot.wordpress.com/2018/06/04/psp-et-msp-sur-arm-cortex-m/ (french material)

# xPSR, Return address, LR (R14), R12, R3, R2, R1, R0) 
# are pushed at MSP or PSP (according the current execution mode SPSEL.Control)

"""
0x0: mov lr, 0x1 <---------
0x4: push{lr}             |
0x6: bl 0x4A8             |
0x8: pop{pc} --------------
"""

TRAMPOLINE_ADDR=0x0

FUZZING = 1

if FUZZING:
    from unicornafl import *
    from unicornafl.arm_const import *
else:
    from unicorn import *
    from unicorn.arm_const import *



def print_excption(message,e):
    print('[-] ',message)
    for l in e.__str__().split('\n'):
            print('\t[-] ',l)


def display_registers(engine):

    print('r0: 0x%.8x\tr1: 0x%.8x\tr2: 0x%.8x\tr3: 0x%.8x'%(engine.reg_read(UC_ARM_REG_R0),
                                                    engine.reg_read(UC_ARM_REG_R1),
                                                    engine.reg_read(UC_ARM_REG_R2),
                                                    engine.reg_read(UC_ARM_REG_R3)))

    print('r4: 0x%.8x\tr5: 0x%.8x\tr6: 0x%.8x\tr7: 0x%.8x'%(engine.reg_read(UC_ARM_REG_R4),
                                                    engine.reg_read(UC_ARM_REG_R5),
                                                    engine.reg_read(UC_ARM_REG_R6),
                                                    engine.reg_read(UC_ARM_REG_R7)))

    print('r8: 0x%.8x\tr9: 0x%.8x\tr10: 0x%.8x\tr11: 0x%.8x'%(engine.reg_read(UC_ARM_REG_R8),
                                                    engine.reg_read(UC_ARM_REG_R9),
                                                    engine.reg_read(UC_ARM_REG_R10),
                                                    engine.reg_read(UC_ARM_REG_R11)))

    print('r12: 0x%.8x\tr13: 0x%.8x\tr14: 0x%.8x'%(engine.reg_read(UC_ARM_REG_R12),
                                                    engine.reg_read(UC_ARM_REG_R13),
                                                    engine.reg_read(UC_ARM_REG_R14)))

def handler_instruction(engine,addr,size,user_data):

    (disas, tracing_file) = user_data
    opline = engine.mem_read(addr,size)
    insn_cpst=next(disas.disasm(opline,addr,count=1))
    print("0x%x:\t%s\t%s" %(insn_cpst.address, insn_cpst.mnemonic, insn_cpst.op_str))
    tracing_file.write('0x%x\n'%addr)
    display_registers(engine)

def handler_read_error(uc,access,addr,value,size,user_data):
        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('[!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(addr,size))
        return False

def handler_write_error(uc,access,addr,size,value,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('[!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(value,addr))
        return False

def handler_write(uc,access,addr,size,value,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('Write addr : write value 0x%.8X at address 0x%.8X '%(value,addr))
        return False

def handler_read(uc,access,addr,value,size,user_data):
        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('[!] Read Access : cannot read 0x%.8X for size %d)'%(addr,size))
        return False


def handler_invalid_insn(uc,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('Invalid fetch, thumb mode : %s'%uc.query(UC_QUERY_MODE))


def init_keystone():

    global ks
    
    ks=Ks(KS_ARCH_ARM,KS_MODE_THUMB)


def init_capstone():

    global disas

    disas = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    disas.detail = True


def configure_unicorn_handlers():

    global engine, disas, tracing_file


    if not DEBUG:
        return

    engine.hook_add(UC_HOOK_CODE,
                    handler_instruction,
                    user_data=(disas,tracing_file))

    engine.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                    handler_read_error,
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

    engine.hook_add(UC_HOOK_INSN_INVALID,
                    handler_invalid_insn,
                    user_data=disas)
def init_unicorn():

    global engine, ks

    engine = Uc(UC_ARCH_ARM,UC_MODE_THUMB)

    page_size = engine.query(UC_QUERY_PAGE_SIZE)

    # TODO: do your mappings here
    #       do not forget to setup the proper protections

    # maybe some patching might help here to skip unecessary
    # os related functions. 

def fill_input(engine, input, persistent_round,data):
    # TODO: prepare the inputs here (get from command line args.input_file)
    pass

def emulate(start,stop,count=0,timeout=0.10,regs_conf=None):

    global engine


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
        engine.emu_start(begin=start|1,until=stop,count=INSN_COUNT)
    except UcError as e:
        print_excption("Error in start()",e)

    print('\n\n')

def fuzz(start,stop,count=0,timeout=0.10,regs_conf=None):

    global engine, args


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
        # TODO: fuzz here (see afl_fuzz)
    except UcError as e:
        print_excption("Error in start()",e)

    print('\n\n')


if __name__ == '__main__':


    init_keystone()

    init_unicorn()

    parser = argparse.ArgumentParser(description="fuzzing CAN handler")
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )

    args = parser.parse_args()
    if True:
        init_capstone()
        configure_unicorn_handlers()


    if FUZZING:

        fuzz(TRAMPOLINE_ADDR,
             TRAMPOLINE_ADDR+0x14,
             regs_conf=REGISTERS)
    else:

        fill_input(engine,args.input_file,[],[])


        emulate(TRAMPOLINE_ADDR,
                TRAMPOLINE_ADDR+0x14,
                regs_conf=REGISTERS)

