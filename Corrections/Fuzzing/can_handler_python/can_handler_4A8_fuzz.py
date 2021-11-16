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

FIRMWARE="/home/d33d34rt/Confs/GreHack/2021/can-workshop/Firmwares/Teensy32/GrehackFinal/Grehack_VirtECU.ino.hex.raw"

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

FUZZING = 0

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
        pc = uc.reg_read(UC_ARM_REG_PC)
        print('[%x][!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(pc,addr,size))
        return False

def handler_write_error(uc,access,addr,size,value,user_data):

        pc = uc.reg_read(UC_ARM_REG_PC)
        print('[%x][!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(pc,value,addr))
        return False

def handler_write(uc,access,addr,size,value,user_data):

        pc = uc.reg_read(UC_ARM_REG_PC)
        print('[%x]Write addr : write value 0x%.8X at address 0x%.8X '%(pc,value,addr))
        return False

def handler_read(uc,access,addr,size,value,user_data):

        pc = uc.reg_read(UC_ARM_REG_PC)
        print('[%x][!] Read Access : read 0x%.8X for size %d)'%(pc, addr,size))
        return False


def handler_invalid_insn(uc,user_data):

        pc = uc.reg_read(UC_ARM_REG_PC)
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


    # map firmware
    engine.mem_map(0,0x8000000,perms=UC_PROT_READ+UC_PROT_EXEC)
    with open(FIRMWARE,"rb") as fbin:
        engine.mem_write(0,fbin.read())

    # SRAM
    engine.mem_map(0x1C0000000,0x20000000-0x1C000000)
    engine.mem_write(0x1C0000000,b'\xba\xda'*(0x4000000//2-1))

    engine.mem_map(0x1FFFA000,0x400)
    with open("./Mappings/can_struct.bin","rb") as fbin:
        engine.mem_write(0x1FFFA0B8,fbin.read())


    #Flex RAM (3 Pages)
    engine.mem_map(0x40024000,0x400*3)
    with open('./Mappings/mb_examples.bin', 'rb') as fbin:
        engine.mem_write(0x40024080,fbin.read())
    with open('./Mappings/FlexCAN_IFLAG1.bin', 'rb') as fbin:
        engine.mem_write(0x40024030,fbin.read())

    # Stack (32 PAGES)
    engine.mem_map(0x20000000,0x8000)


    # (ISOTP is 4096)
    engine.mem_map(DRIVER_MSG_PULL,0x3000)
    engine.mem_write(0x1FFFA0B8+0xA4+8,struct.pack('<I',DRIVER_MSG_PULL))


    # Map M4PrivatePerip
    engine.mem_map(0xE0000000,0x100000)

    # patch the memory at TRAMPOLINE_ADDR to put the loop
    trampoline= list(ks.asm('mov lr,0x%x\npush{lr}\nbl 0x4A8\npop{pc}'%(TRAMPOLINE_ADDR|1),
                        addr=0x0,
                        as_bytes=True))[0]
    engine.mem_write(TRAMPOLINE_ADDR,trampoline)

    # patch CBNZ to unconditionnal branchment 
    # skip M4 ISR Flags logical 
    patch =  list(ks.asm('b 0x4FC',addr=0x4B2,as_bytes=True))[0]
    engine.mem_write(0x4B2,patch)


    # patch instruction to trigger the read function
    # skip again M4 ISR Flags logical 
    patch =  list(ks.asm('b 0xEF6',addr=0xEF4,as_bytes=True))[0]
    engine.mem_write(0xEF4,patch)

def fill_input(engine, input, persistent_round,data):


    if not FUZZING:

        with open(input,"rb") as fbin:
            data=fbin.read()
    else:
        data = input

    if len(data) < 4096:
        return False

    engine.mem_write(DRIVER_MSG_PULL,data)

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

        sp = engine.reg_read(UC_ARM_REG_R13)
        print('sp : %X'%sp)

    try:
        engine.afl_fuzz(args.input_file, fill_input, [stop])
#        engine.emu_start(begin=start|1,until=stop,count=INSN_COUNT)
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

