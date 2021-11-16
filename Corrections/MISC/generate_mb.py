import struct

CAN_ID = 0x123
NUM_MB = 8
TS = 0x2222
CODE=0x2
DATA=b'\xAA'*8

with open('/tmp/mb_examples.bin','wb+') as fout:
    for i in range(NUM_MB):
        fout.write(struct.pack('<I',len(DATA)<<16|CODE<<24|TS))
        fout.write(struct.pack('<I',CAN_ID<<18))
        
        fout.write(DATA)


