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

# ast=triton_ctx.getAstContext()ast.unroll(triton_ctx.getSymbolicExpression(triton_ctx.registers.rcx).getAst())
#ctx.getModel(rcx = maVariable)

stop_points = []

symbolized_area = {}

triton_ctx = TritonContext()

capstone = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
capstone.detail = True


class IT():
    def __init__(self):
        self.logic=[]
        self.cond=''

it_struct = IT()

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

            triton_ctx.setConcreteMemoryAreaValue(int(k,16),fbin.read())
            print('[+] mapped %x'%int(k,16))



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
            d,r = divmod(area_size,ALIGN_SIZE)
            if r: d+=1
#            triton_ctx.symbolizeMemory(MemoryAccess(area_addr,d*ALIGN_SIZE*CPUSIZE))
            triton_ctx.setTaintMemory(MemoryAccess(area_addr,d*ALIGN_SIZE*CPUSIZE.BYTE),True)
            print('[+] taint activated for %x (size %d) '%(area_addr,d*ALIGN_SIZE))

            symbolized_area[area_addr] = d*ALIGN_SIZE*CPUSIZE.BYTE
        else:
            raise Exception("Incorrect taint type.")
    


#    triton_ctx.setTaintMemory(MemoryAccess(INPUT_ADDR,(INPUT_SIZE-2)*CPUSIZE.BYTE),True)


def configure_registers(reg_file):


    with open(reg_file) as f_regs:
        jsonf_regs = json.load(f_regs)

    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r0,
                                        int(jsonf_regs['r0'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r1,
                                        int(jsonf_regs['r1'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r2,
                                        int(jsonf_regs['r2'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r3,
                                        int(jsonf_regs['r3'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r4,
                                        int(jsonf_regs['r4'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r5,
                                        int(jsonf_regs['r5'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r6,
                                        int(jsonf_regs['r6'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r7,
                                        int(jsonf_regs['r7'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r8,
                                        int(jsonf_regs['r8'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r9,
                                        int(jsonf_regs['r9'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r10,
                                        int(jsonf_regs['r10'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r11,
                                        int(jsonf_regs['r11'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r12,
                                        int(jsonf_regs['r12'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.sp,
                                        int(jsonf_regs['r13'],16))
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.r14,
                                        int(jsonf_regs['r14'],16))

def is_symbolized(addr,size=1):

    global symbolized_area

    for k,v in symbolized_area.items():
        if addr in range(k,k+v+1) and addr+size in range(k,k+v+1):
            return True
    return False


def handle_unsupported_insn(instruction):

    global triton_ctx, capstone, it_struct

    handled = False

    itype = instruction.getType()

    if itype == triton.OPCODE.ARM32.SMLABB:
        operands = instruction.getOperands()
        dst = operands[0]
        mul1 = operands[1]
        mul2 = operands[2]
        const = operands[3]

        mul1_val = triton_ctx.getConcreteRegisterValue(mul1)
        mul2_val = triton_ctx.getConcreteRegisterValue(mul2)
        const_val = triton_ctx.getConcreteRegisterValue(const)


        dst_val = mul1_val * mul2_val + const_val

        triton_ctx.setConcreteRegisterValue(dst,dst_val)

        if is_symbolized(mul1) or is_symbolized(mul2) or is_symbolized(const_val) \
                or is_symbolized(dst_val): 
            print('[+] executing tainted insn at %x'%instruction.getAddress())

        handled = True


    elif itype == triton.OPCODE.ARM32.MLS: 
        operands = instruction.getOperands()
        dst = operands[0]
        mul1 = operands[1]
        mul2 = operands[2]
        const = operands[3]

        mul1_val = triton_ctx.getConcreteRegisterValue(mul1)
        mul2_val = triton_ctx.getConcreteRegisterValue(mul2)
        const_val = triton_ctx.getConcreteRegisterValue(const)

        dst_val = (mul1_val * mul2_val - const_val) & 0xFFFFFFFF

        print('%x %x - %x'%(mul1_val, mul2_val, const_val))

        triton_ctx.setConcreteRegisterValue(dst,dst_val)

        if is_symbolized(mul1) or is_symbolized(mul2) or is_symbolized(const_val) \
                or is_symbolized(dst_val): 
            print('[+] executing tainted insn at %x'%instruction.getAddress())

        handled = True

    elif  itype == triton.OPCODE.ARM32.IT:
        operands = instruction.getOperands()
        cs_insn = next(capstone.disasm(instruction.getOpcode(),
                                       offset=instruction.getAddress(),
                                       count=1))
        if cs_insn.mnemonic == 'it':
            it_struct.logic.append('i')
        elif cs_insn.mnemonic ==  'itt':
            it_struct.logic.append('i')
            it_struct.logic.append('i')
        elif cs_insn.mnemonic == 'ite':
            it_struct.logic.append('e')
            it_struct.logic.append('i')
        elif cs_insn.mnemonic == 'itte':
            it_struct.logic.append('e')
            it_struct.logic.append('i')
            it_struct.logic.append('i')
        elif cs_insn.mnemonic == 'ittee':
            it_struct.logic.append('e')
            it_struct.logic.append('e')
            it_struct.logic.append('i')
            it_struct.logic.append('i')

        op_str = cs_insn.op_str
        if op_str == 'eq':
            it_struct.cond='eq'
            handled = True
        elif op_str == 'ne':
            it_struct.cond='ne'
            handled = True
        elif op_str == 'lo':
            handled = False
        elif op_str == 'hi':
            handled = False
    else:
        pass

    return handled

def handle_conditional(instruction):

    global triton_ctx, it_struct

    logic = it_struct.logic.pop()


    if it_struct.cond == 'eq' and \
            triton_ctx.getConcreteRegisterValue(triton_ctx.registers.z):
        return False
    elif it_struct.cond == 'eq' and \
            not triton_ctx.getConcreteRegisterValue(triton_ctx.registers.z):
        return True
    elif it_struct.cond == 'ne' and \
            triton_ctx.getConcreteRegisterValue(triton_ctx.registers.z):
        return True
    elif it_struct.cond == 'ne' and \
            not triton_ctx.getConcreteRegisterValue(triton_ctx.registers.z):
        return False

    else:
        raise Exception('Unhandled CPU state')


def emulate(pc):

    global triton_ctx, stop_points

    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.pc,pc)

    count = 0
    handled = False
    conditional=False

    while (pc not in stop_points) :

        opcode = triton_ctx.getConcreteMemoryAreaValue(pc,4)
#        print(opcode)

        instruction = Instruction()
        instruction.setOpcode(opcode)
        instruction.setAddress(pc)
        conditional = skip = False


        if len(it_struct.logic) > 0:
            conditional=True


        if conditional:
            skip = handle_conditional(instruction)


        if skip:
            print('[+] skipping instruction')
            triton_ctx.setConcreteRegisterValue(triton_ctx.registers.pc,
                                                     instruction.getAddress() + \
                                                     instruction.getSize())
            continue

        try:
            handled = triton_ctx.processing(instruction)
        except Exception as e:
            break

#        print_regs()
        print(instruction)


        if not handled:
#            print('[!] warning unhandled instruction, trying to resolve it by hand')
            if not handle_unsupported_insn(instruction):
#                print('[!] could not handle "by hand", stopping execution')
                break
            triton_ctx.setConcreteRegisterValue(triton_ctx.registers.pc,
                                                instruction.getAddress() + \
                                                instruction.getSize())

        else:

#           for x in instruction.getSymbolicExpressions():
#                print(x)

           if instruction.isTainted():
                print('[+] executing tainted insn at %x'%pc)
           if instruction.isBranch():
                print('[+] branch instruction at %x'%pc)
                print_regs()

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


