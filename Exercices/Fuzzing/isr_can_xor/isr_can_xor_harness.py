from unicorn import * 
from unicorn.arm_const import *
from capstone import * 
from capstone.arm_const import *
import json
import hexdump
import argparse
import struct
from keystone.arm_const import  *
from keystone import *


DEBUG = 1

REGISTERS="./registers.json"

FIRMWARE=""

# trilogy 
engine = None  # emulator
disas  = None  # disassembler 
ks     = None  # assembler


# see ressources for interrupt in corresponding Cortex folder.
# explaination of PSP and MSP : 
# https://gradot.wordpress.com/2018/06/04/psp-et-msp-sur-arm-cortex-m/ (french material)

# xPSR, Return address, LR (R14), R12, R3, R2, R1, R0) 
# are pushed at MSP or PSP (according the current execution mode SPSEL.Control)

"""
0x0: mov lr, 0x1<-----
0x4: push{lr}         |
0x6: bl 0x1378        |
0x8: pop{pc} ---------
"""

TRAMPOLINE_ADDR=0x0

# Arbitrary address 
DRIVER_BUFFER_ADDR = 0x50000000

# Instruction limit (0 <=> no limit)
INSN_COUNT = 0

def init_keystone():
    global ks

    ks=Ks(KS_ARCH_ARM,KS_MODE_THUMB)

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

def handler_write(uc,access,addr,size,value,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('Write addr : write value 0x%.8X at address 0x%.8X '%(value,addr))
        return False


def handler_invalid_insn(uc,user_data):

        print('pc at : %x'%uc.reg_read(UC_ARM_REG_PC))
        print('Invalid fetch, thumb mode : %s'%uc.query(UC_QUERY_MODE))


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

    engine.hook_add(UC_HOOK_MEM_WRITE,
                    handler_write,
                    user_data=disas)


    engine.hook_add(UC_HOOK_INSN_INVALID,
                    handler_invalid_insn,
                    user_data=disas)


def init_unicorn():

    global engine, ks

    engine = Uc(UC_ARCH_ARM,UC_MODE_THUMB)

    page_size = engine.query(UC_QUERY_PAGE_SIZE)


    # TODO: map firmware
    
    # TODO: map sections with proper permissions 

    # add section content (see Mappings/)
    
    # TODO: add trampoline to loop the isr


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


if __name__ == '__main__':

    init_keystone()

    init_unicorn()

    if DEBUG:
        init_capstone()
        configure_unicorn_handlers()


    # loops the ISR handler 
    # to see how the driver buffers reacts. 

    emulate(TRAMPOLINE_ADDR,
            TRAMPOLINE_ADDR+0x14,
            regs_conf=REGISTERS)








