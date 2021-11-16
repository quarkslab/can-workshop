from __future__ import print_function
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE,OPCODE
import triton
import json
import argparse
import  sys
import hexdump
from capstone import *
from capstone.arm_const import*


ALIGN_SIZE = 4

stop_points = []

symbolized_area = {}

triton_ctx = TritonContext()

capstone = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
capstone.detail = True


def print_regs():
    global triton_ctx

    r0 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r0)
    r1 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r1)
    r2 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r2)
    r3 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r3)
    r4 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r4)
    r5 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r5)
    r6 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r6)
    r7 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r7)
    r8 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r8)
    r9 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r9)
    r10 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r10)
    r11 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r11)
    r12 = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r12)
    sp = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.sp)
    lr = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.r14)

    print('r0[%4x] r1[%4x] r2[%4x] r3[%4x]'% (r0,r1,r2,r3))
    print('r4[%4x] r5[%4x] r6[%4x] r7[%4x]'% (r4,r5,r6,r7))
    print('r8[%4x] r9[%4x] r10[%4x] r11[%4x]'% (r8,r9,r10,r11))
    print('r12[%4x] sp[%4x] lr[%4x] '% (r12,sp,lr))



def loadbin(mapping_file):

    global triton_ctx

    with open(mapping_file) as fmap:
        mappings = json.load(fmap)

    for k,v in dict(mappings).items():
        with open(v,'rb') as fbin:

            # TODO: load binary here

            pass



def init_exec(mapping_file,
              reg_file=None,
              taint_info=None):

    global seed, triton_ctx, symbolized_area

    triton_ctx.concretizeAllMemory()
    triton_ctx.concretizeAllRegister()

    if reg_file:
        configure_registers(reg_file)

    if mapping_file:
        loadbin(mapping_file)

    if taint_info:
        v = taint_info.split(':')
        if v[0] == 'r':
            raise Exception('Tainting register not yet supported')
        elif v[0] == 'm':
            area_addr = int(v[1],16)
            area_size = int(v[2],16)
            # init taint engine 
        else:
            raise Exception("Incorrect taint type.")




def configure_registers(reg_file):


    with open(reg_file) as f_regs:
        jsonf_regs = json.load(f_regs)

    # TODO: configure register here 


    pass


def emulate(pc):

    global triton_ctx, stop_points

    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.pc,pc)

    count = 0
    handled = False
    conditional=False

    while (pc not in stop_points) :


        # TODO: get opcode (reading memory can be a good idea)

        pass

        instruction = Instruction()
         
        # TODO: fill instruction object (setting address and opcode worth it)

        pass

        # TODO: process the instruction 

        pass

        # TODO: evaluate (is instruction tainted)

        pass


        # TODO: get next pc value (next address to be executed)

        pc = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.pc)

        count += 1

    print('[+] stopping exec at %x'%pc)

    return count




if __name__ == '__main__':


    argparser = argparse.ArgumentParser()
    argparser.add_argument("-s", "--start", help="emulation start address", required=True)
    argparser.add_argument("-e", "--end", help="emulation stop addresses (coma separated)",
                           required=True)
    argparser.add_argument("-m", "--mappings", help="mapping files",required=True)
    argparser.add_argument('-r', "--registers", help="register conf file",default=None)
    argparser.add_argument("-t", "--taint", help="taint information: m:0x1234:8",
                           default=None)
    args = argparser.parse_args()

    triton_ctx.setArchitecture(ARCH.ARM32)

    triton_ctx.setMode(MODE.ALIGNED_MEMORY,False)

    triton_ctx.setThumb(True)

    for stop in args.end.split(','):
        stop_points.append(int(stop,16))

    init_exec(mapping_file=args.mappings,
              reg_file=args.registers,
              taint_info=args.taint)

    nb_insn = emulate(int(args.start,16))

    print('[+] executed %d insn'% nb_insn)


