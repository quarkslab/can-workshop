import collections

import idaapi
import ida_segment
import ida_name
import idc
import ida_idp
import ida_segregs
import idautils
import ida_bytes
import ida_entry

"""
This is an IDA Pro loader for RH850 memory dump.
"""

MAGIC_VALUE = b'\x00\x80\x00\x20'

"""
FlexCAN registers memory mapping, part 1
"""
FlexCAN_AREA_REG_P1_START = 0x40024000 # May be split part for registers and FIFO / MB ranges?  
FlexCAN_AREA_REG_P1_SIZE =  0x50

"""
FlexCAN mailbox and/or FIFO memory area
"""
FlexCAN_Mailbox_Fifo_START = 0x40024050
FlexCAN_Mailbox_Fifo_SIZE = 0x830

"""
FlexCAN registers memory mapping, part 2
"""
FlexCAN_AREA_REG_P2_START = 0x40024880 # May be split part for registers and FIFO / MB ranges?  
FlexCAN_AREA_REG_P2_SIZE =  0x40

"""
Nested Interrupt Vector memory mapping
"""
NVIC_START=0x0
NVIC_SIZE= 0x1C0-4

"""
Internal MCU program flash
"""
ProgramFlash_START = NVIC_SIZE
ProgramFlash_SIZE =  0x07FFFFFF-NVIC_SIZE

"""
Flex NVM
"""
FlexNVM_START= 0x1000_0000
FlexNVM_SIZE= 0x3FFFFFF

"""
Flex RAM
"""
FlexRAM_START = 0x14000000 
FlexRAM_SIZE = 0x17FFFFFF

"""
SRAM_L
"""
SRAML_START = 0x1C000000 
SRAML_SIZE = 0x3ffffff

"""
SRAM_U
"""
SRAMU_START = 0x20000000
SRAMU_SIZE = 0xFFFFF

"""
SRAM_U2
"""
SRAMU2_START=0x22000000 
SRAMU2_SIZE=0x3FFFFFF

"""
AIPS_Lite0 Peripheral Bridge
"""
AIPS0_START=0x40000000
AIPS0_SIZE = 0x7FFFF

"""
AIPS_Lite1 Peripheral Bridge
"""
AIPS1_START=0x40080000
AIPS1_SIZE = 0x7efff

"""
GPIO
"""
GPIOReg1_START =0x400FF000
GPIOReg1_SIZE =0xFFFF

"""
GPIO AIPS
"""

GPIOAIDS_START=0x42000000
GPIOAIDS_SIZE =0x1FFFFFF

"""
Cortex M4 Private Peripheral Access
"""
M4PrivPeriph_START = 0xE0000000
M4PrivPeriph_SIZE = 0xFFFFF





entry_p = idaapi.BADADDR

SEGMENT = collections.namedtuple(
    'Segment', ['load', 'size', 'name', 'type'])

SEGMENTS = [
  #SEGMENT(NVIC_START, NVIC_SIZE, 'NVIC', 'CODE'),
  #SEGMENT(ProgramFlash_START, ProgramFlash_SIZE, 'ProgramFlash', 'CODE'),
  SEGMENT(FlexCAN_AREA_REG_P1_START, FlexCAN_AREA_REG_P1_SIZE, 'FlexCAN_Regs_P1', 'DATA'),
  SEGMENT(FlexCAN_Mailbox_Fifo_START,FlexCAN_Mailbox_Fifo_SIZE,'FlexCAN_MB_Fifo','DATA'),
  SEGMENT(FlexCAN_AREA_REG_P2_START,FlexCAN_AREA_REG_P2_SIZE,'FlexCAN_Regs_P2', 'DATA'),
  SEGMENT(FlexNVM_START,FlexNVM_SIZE,'FlexNVM', 'DATA'),
  SEGMENT(FlexRAM_START,FlexRAM_SIZE,'FlexRAM', 'DATA'),
  SEGMENT(SRAML_START,SRAML_SIZE,'SRAML','DATA'),
  SEGMENT(SRAMU_START,SRAMU_SIZE,'SRAMU','DATA'),
  SEGMENT(SRAMU2_START,SRAMU2_SIZE,'SRAMU2','DATA'),
  SEGMENT(AIPS0_START,AIPS0_SIZE,'AIPS0','DATA'),
  SEGMENT(AIPS1_START,AIPS1_SIZE,'AIPS1','DATA'),
  SEGMENT(GPIOReg1_START,GPIOReg1_SIZE,'GPIOReg1','DATA'),
  SEGMENT(GPIOAIDS_START,GPIOAIDS_SIZE,'GPIOAids','DATA'),
    SEGMENT(M4PrivPeriph_START,M4PrivPeriph_SIZE,'M4PrivatePeriph', 'DATA')
 ]

REGISTER = collections.namedtuple(
    'Register', [ 'address', 'name', 'comment'])
FlexCAN_registers = [
REGISTER(0x40024000, "CAN0_MCR", "Module Configuration"),
REGISTER(0x40024004, "CAN0_CTRL1","Control 1 register" ),
REGISTER(0x40024008, "CAN0_TIMER", "Free running timer"), 
REGISTER(0x40024010, "CAN0_RXMGMASK", "Rx Mailboxes Global Mask Registe"),
REGISTER(0x40024014, "CAN0_RX14MASK", "Rx 14 Mask Register" ),
REGISTER(0x40024018, "CAN0_RX15MASK", "Rx 15 Mask Register" ),
REGISTER(0x4002401C, "CAN0_ECR", "Error counter"), 
REGISTER(0x40024020, "CAN0_ESR1", "Error and Status Register 1"),
REGISTER(0x40024028, "CAN0_IMASK1", "Interrupt Mask  1 register"),
REGISTER(0x40024030, "CAN0_IFLAG1", "Interrupt Flag 1 register"),
REGISTER(0x40024034, "CAN0_CTRL2" , "Control 2 register"),
REGISTER(0x40024038, "CAN0_ESR2", "Error and Status Register 2"),
REGISTER(0x40024044, "CAN0_CRC", "CRC register"),
REGISTER(0x40024048, "CAN0_RXFGMASK", "General Fifo Rx Mask"), 
REGISTER(0x4002404C, "CAN0_FXFIR", "Fifo Rx Information Register"),
REGISTER(0x40024880, "CAN0_RXIMR0", "Rx Individual Mask Registers"), 
REGISTER(0x40024884, "CAN0_RXIMR1" ,"Rx Individual Mask Registers"), 
REGISTER(0x40024888, "CAN0_RXIMR2", "Rx Individual Mask Registers"), 
REGISTER(0x4002488C, "CAN0_RXIMR3", "Rx Individual Mask Registers"), 
REGISTER(0x40024890, "CAN0_RXIMR4", "Rx Individual Mask Registers"), 
REGISTER(0x40024894, "CAN0_RXIMR5", "Rx Individual Mask Registers"), 
REGISTER(0x40024898, "CAN0_RXIMR6", "Rx Individual Mask Registers"), 
REGISTER(0x4002489C, "CAN0_RXIMR7", "Rx Individual Mask Registers"), 
REGISTER(0x400248A0, "CAN0_RXIMR8", "Rx Individual Mask Registers"), 
REGISTER(0x400248A4, "CAN0_RXIMR9", "Rx Individual Mask Registers"), 
REGISTER(0x400248A8, "CAN0_RXIMR10", "Rx Individual Mask Registers"), 
REGISTER(0x400248AC, "CAN0_RXIMR11", "Rx Individual Mask Registers"), 
REGISTER(0x400248B0, "CAN0_RXIMR12", "Rx Individual Mask Registers"), 
REGISTER(0x400248B4, "CAN0_RXIMR13", "Rx Individual Mask Registers"), 
REGISTER(0x400248B8, "CAN0_RXIMR14", "Rx Individual Mask Registers"), 
REGISTER(0x400248BC, "CAN0_RXIMR15", "Rx Individual Mask Registers") 
]


NVIC_Registers=[
REGISTER(0, 'init_stack', 'Initial Stack value'),
REGISTER(0x4, 'initial_pc', 'Initial PC value'),
REGISTER(0x8, 'NMI', 'Non-Maskable interruption'),
REGISTER(0xC, 'HardFault', 'Hard-Fault'),
REGISTER(0x10, 'MemFault', 'Memory Management Fault'),
    REGISTER(0x14,'BusFault', 'Bus Fault'),
    REGISTER(0x18, 'UsageFault', 'Usage Fault'),
    REGISTER(0x2C, 'SVCHandler', 'Supervisor Call handler'),
    REGISTER(0x30, 'DebugMonitor', 'Debug Monitor'),
    REGISTER(0x38, 'PendableSrvReq', 'Pendable request for system service'),
    REGISTER(0x3C, 'SysTick', 'System tick Timer'),
    REGISTER(0x40, 'DMA0', 'DMA channel 0 transfer complete'),
    REGISTER(0x44, 'DMA1', 'DMA channel 1 transfer complete'),
    REGISTER(0x48, 'DMA2', 'DMA channel 2 transfer complete'),
    REGISTER(0x4C, 'DMA3', 'DMA channel 3 transfer complete'),
    REGISTER(0x50, 'DMA4', 'DMA channel 4 transfer complete'),
    REGISTER(0x54, 'DMA5', 'DMA channel 5 transfer complete'),
    REGISTER(0x58, 'DMA6', 'DMA channel 6 transfer complete'),
    REGISTER(0x5C, 'DMA7', 'DMA channel 7 transfer complete'),
    REGISTER(0x60, 'DMA8', 'DMA channel 8 transfer complete'),
    REGISTER(0x64, 'DMA9', 'DMA channel 9 transfer complete'),
    REGISTER(0x68, 'DMA10', 'DMA channel 10 transfer complete'),
    REGISTER(0x6C, 'DMA11', 'DMA channel 11 transfer complete'),
    REGISTER(0x70, 'DMA12', 'DMA channel 12 transfer complete'),
    REGISTER(0x74, 'DMA13', 'DMA channel 13 transfer complete'),
    REGISTER(0x78, 'DMA14', 'DMA channel 14 transfer complete'),
    REGISTER(0x7C, 'DMA15', 'DMA channel 15 transfer complete'),
    REGISTER(0x80, 'DMAError', 'DMA error on channel 0-15'),
    REGISTER(0x88, 'FlashMem', 'Flash memory command complete'),
    REGISTER(0x8C, 'FlashReadCollision', 'Flash read collision'),
    REGISTER(0x90, 'LowVolt', 'Low Voltage detected'),
    REGISTER(0x94 , 'LowVoltLeak', 'Low Voltage Leakage'),
    REGISTER(0x98 , 'Watchdog', 'Watchdog interrupt'),
    REGISTER(0xA0, 'I2C0', 'undocummented'),
    REGISTER(0xA4, 'I2C1', 'undocummented'),
    REGISTER(0xA8, 'SPI0', 'Single Interrupt Vector for all sources'),
    REGISTER(0xAC, 'SPI1', 'Single Interrupt Vector for all sources'),
    REGISTER(0xB4, 'CAN0_Ored', 'Ored message buffer'),
    REGISTER(0xB8, 'CAN0_BusOff', 'Bus Off'),
    REGISTER(0xBC, 'CAN0_Error', 'Can error'),
    REGISTER(0xC0, 'CAN0_TxWarn', 'Can Tx warning'),
    REGISTER(0xC4, 'CAN1_RxWarn', 'Can Rx warning'),
    REGISTER(0xC8, 'CAN1_WakeUp', 'CAN Wake up'),
    REGISTER(0xCC, 'I2S0_Tx', 'I2S Tx'),
    REGISTER(0xC8, 'I2S0_Rx', 'I2S Rx'),
    REGISTER(0xF0, 'UART0_LON', 'UART interrupt vector LON'),
    REGISTER(0xF4, 'UART0_Status', 'UART interrupt vector status'),
    REGISTER(0xF8, 'UART0_Error', 'UART interrupt vector error'),
    REGISTER(0xFC, 'UART1_LON', 'UART1 interrupt vector LON'),
    REGISTER(0x100, 'UART1_Status', 'UART1 interrupt vector status'),
    REGISTER(0x104, 'UART1_Error', 'UART1 interrupt vector error'),
    REGISTER(0x100, 'UART2_Status', 'UART2 interrupt vector status'),
    REGISTER(0x104, 'UART2_Error', 'UART2 interrupt vector error'),
    REGISTER(0x124, 'ADC0', ' Analog Digital Converter interruption: undocummented'),
    REGISTER(0x128, 'ADC1', 'Analog Digital Converter interruption:undocummented'),
    REGISTER(0x12C, 'CMP0', 'Compare Register: undocummented'),
    REGISTER(0x130, 'CMP1', 'Compare Register: undocummented'),
    REGISTER(0x134, 'CMP2', 'Compare Register: undocummented'),
    REGISTER(0x138, 'FTM0', 'FTM: undocummented'),
    REGISTER(0x13C, 'FTM1', 'FTM: undocummented'),
    REGISTER(0x140, 'FTM2', 'FTM: undocummented'),
    REGISTER(0x144, 'CMT', 'CMT: undocummented'),
    REGISTER(0x148, 'RTC_Alarm1', 'Alarm Interrupt'),
    REGISTER(0x14C, 'RTC_Alarm2', 'Alarm Interrupt'),
    REGISTER(0x150, 'PIT_Chan0', 'PIT Channel 0'),
    REGISTER(0x154, 'PIT_Chan1', 'PIT Channel 1'),
    REGISTER(0x158, 'PIT_Chan2', 'PIT Channel 2'),
    REGISTER(0x15C, 'PIT_Chan3', 'PIT Channel 3'),
    REGISTER(0x160, 'PDB', 'PDB'),
    REGISTER(0x164, 'USB_OTG', 'USB_OTG'),
    REGISTER(0x168, 'USB_ChargerDetected', 'Charger Detected'),
    REGISTER(0x184, 'DAC0', 'Undocumented'),
    REGISTER(0x18C, 'TSI', 'Undocumented'),
    REGISTER(0x190, 'MCG', 'MCG'),
    REGISTER(0x19C, 'PortCtrl_A', 'Pin Detect port A'),
    REGISTER(0x1A0, 'PortCtrl_B', 'Pin Detect port B'),
    REGISTER(0x1A4, 'PortCtrl_C', 'Pin Detect port C'),
    REGISTER(0x1A8, 'PortCtrl_D', 'Pin Detect port D'),
    REGISTER(0x1AC, 'PortCtrl_E', 'Pin Detect port E'),
    REGISTER(0x1B8, 'Software_Interrupt', 'Software Interrupt'),
]

NVIC_ControlRegs= [

      REGISTER(0xE000E100, "NVIC_ISER0","Interrupt Set-enable Registers 0"),
REGISTER(0xE000E104, "NVIC_ISER1","Interrupt Set-enable Registers 1"),
REGISTER(0xE000E108, "NVIC_ISER2","Interrupt Set-enable Registers 2"),
REGISTER(0xE000E10C, "NVIC_ISER3","Interrupt Set-enable Registers 3"),
REGISTER(0xE000E110, "NVIC_ISER4","Interrupt Set-enable Registers 4"),
REGISTER(0xE000E114, "NVIC_ISER5","Interrupt Set-enable Registers 5"),
REGISTER(0xE000E118, "NVIC_ISER6","Interrupt Set-enable Registers 6"),
REGISTER(0xE000E11C, "NVIC_ISER7","Interrupt Set-enable Registers 7"), 
REGISTER(0xE000E180, "NVIC_ICER0","Interrupt Clear-enable Registers 0"),
REGISTER(0xE000E184, "NVIC_ICER1","Interrupt Clear-enable Registers 1"),
REGISTER(0xE000E188, "NVIC_ICER2","Interrupt Clear-enable Registers 2"),
REGISTER(0xE000E18C, "NVIC_ICER3","Interrupt Clear-enable Registers 3"),
REGISTER(0xE000E190, "NVIC_ICER4","Interrupt Clear-enable Registers 4"),
REGISTER(0xE000E194, "NVIC_ICER5","Interrupt Clear-enable Registers 5"),
REGISTER(0xE000E198, "NVIC_ICER6","Interrupt Clear-enable Registers 6"),
REGISTER(0xE000E19C, "NVIC_ICER7","Interrupt Clear-enable Registers 7"),
REGISTER(0xE000E200, "NVIC_ISPR0","Interrupt Set-pending Registers 0"),
REGISTER(0xE000E204, "NVIC_ISPR1","Interrupt Set-pending Registers 1"),
REGISTER(0xE000E208, "NVIC_ISPR2","Interrupt Set-pending Registers 2"),
REGISTER(0xE000E20C, "NVIC_ISPR3","Interrupt Set-pending Registers 3"),
REGISTER(0xE000E210, "NVIC_ISPR4","Interrupt Set-pending Registers 4"),
REGISTER(0xE000E214, "NVIC_ISPR5","Interrupt Set-pending Registers 5"),
REGISTER(0xE000E218, "NVIC_ISPR6","Interrupt Set-pending Registers 6"),
REGISTER(0xE000E21C, "NVIC_ISPR7","Interrupt Set-pending Registers 7"),
REGISTER(0xE000E280, "NVIC_ICPR0","Interrupt Clear-pending Registers 0"),
REGISTER(0xE000E284, "NVIC_ICPR1","Interrupt Clear-pending Registers 1"),
REGISTER(0xE000E288, "NVIC_ICPR2","Interrupt Clear-pending Registers 2"),
REGISTER(0xE000E28C, "NVIC_ICPR3","Interrupt Clear-pending Registers 3"),
REGISTER(0xE000E290, "NVIC_ICPR4","Interrupt Clear-pending Registers 4"),
REGISTER(0xE000E294, "NVIC_ICPR5","Interrupt Clear-pending Registers 5"),
REGISTER(0xE000E298, "NVIC_ICPR6","Interrupt Clear-pending Registers 6"),
REGISTER(0xE000E29C, "NVIC_ICPR7","Interrupt Clear-pending Registers 7"),
REGISTER(0xE000E300, "NVIC_IABR0","Interrupt Active Bit Register 0"),
REGISTER(0xE000E304, "NVIC_IABR1","Interrupt Active Bit Register 1"),
REGISTER(0xE000E308, "NVIC_IABR2","Interrupt Active Bit Register 2"),
REGISTER(0xE000E30C, "NVIC_IABR3","Interrupt Active Bit Register 3"),
REGISTER(0xE000E310, "NVIC_IABR4","Interrupt Active Bit Register 4"),
REGISTER(0xE000E314, "NVIC_IABR5","Interrupt Active Bit Register 5"),
REGISTER(0xE000E318, "NVIC_IABR6","Interrupt Active Bit Register 6"),
REGISTER(0xE000E31C, "NVIC_IABR7","Interrupt Active Bit Register 7"),
REGISTER(0xE000E400, "NVIC_IPR0","Interrupt Priority Register 0"),
REGISTER(0xE000E404, "NVIC_IPR1","Interrupt Priority Register 1"),
REGISTER(0xE000E408, "NVIC_IPR2","Interrupt Priority Register 2"),
REGISTER(0xE000E40C, "NVIC_IPR3","Interrupt Priority Register 3"),
REGISTER(0xE000E410, "NVIC_IPR4","Interrupt Priority Register 4"),
REGISTER(0xE000E414, "NVIC_IPR5","Interrupt Priority Register 5"),
REGISTER(0xE000E418, "NVIC_IPR6","Interrupt Priority Register 6"),
REGISTER(0xE000E41C, "NVIC_IPR7","Interrupt Priority Register 7"),
REGISTER(0xE000E420, "NVIC_IPR8","Interrupt Priority Register 8"),
REGISTER(0xE000E424, "NVIC_IPR9","Interrupt Priority Register 9"),
REGISTER(0xE000E428, "NVIC_IPR10","Interrupt Priority Register 10"),
REGISTER(0xE000E42C, "NVIC_IPR11","Interrupt Priority Register 11"),
REGISTER(0xE000E430, "NVIC_IPR12","Interrupt Priority Register 12"),
REGISTER(0xE000E434, "NVIC_IPR13","Interrupt Priority Register 13"),
REGISTER(0xE000E438, "NVIC_IPR14","Interrupt Priority Register 14"),
REGISTER(0xE000E43C, "NVIC_IPR15","Interrupt Priority Register 15"),
REGISTER(0xE000E440, "NVIC_IPR16","Interrupt Priority Register 16"),
REGISTER(0xE000E444, "NVIC_IPR17","Interrupt Priority Register 17"),
REGISTER(0xE000E448, "NVIC_IPR18","Interrupt Priority Register 18"),
REGISTER(0xE000E44C, "NVIC_IPR19","Interrupt Priority Register 19"),
REGISTER(0xE000E450, "NVIC_IPR20","Interrupt Priority Register 20"),
REGISTER(0xE000E454, "NVIC_IPR21","Interrupt Priority Register 21"),
REGISTER(0xE000E458, "NVIC_IPR22","Interrupt Priority Register 22"),
REGISTER(0xE000E45C, "NVIC_IPR23","Interrupt Priority Register 23"),
REGISTER(0xE000E460, "NVIC_IPR24","Interrupt Priority Register 24"),
REGISTER(0xE000E464, "NVIC_IPR25","Interrupt Priority Register 25"),
REGISTER(0xE000E468, "NVIC_IPR26","Interrupt Priority Register 26"),
REGISTER(0xE000E46C, "NVIC_IPR27","Interrupt Priority Register 27"),
REGISTER(0xE000E470, "NVIC_IPR28","Interrupt Priority Register 28"),
REGISTER(0xE000E474, "NVIC_IPR29","Interrupt Priority Register 29"),
REGISTER(0xE000E478, "NVIC_IPR30","Interrupt Priority Register 30"),
REGISTER(0xE000E47C, "NVIC_IPR31","Interrupt Priority Register 31"),
REGISTER(0xE000E480, "NVIC_IPR32","Interrupt Priority Register 32"),
REGISTER(0xE000E484, "NVIC_IPR33","Interrupt Priority Register 33"),
REGISTER(0xE000E488, "NVIC_IPR34","Interrupt Priority Register 34"),
REGISTER(0xE000E48C, "NVIC_IPR35","Interrupt Priority Register 35"),
REGISTER(0xE000E490, "NVIC_IPR36","Interrupt Priority Register 36"),
REGISTER(0xE000E494, "NVIC_IPR37","Interrupt Priority Register 37"),
REGISTER(0xE000E498, "NVIC_IPR38","Interrupt Priority Register 38"),
REGISTER(0xE000E49C, "NVIC_IPR39","Interrupt Priority Register 39"),
REGISTER(0xE000E4A0, "NVIC_IPR40","Interrupt Priority Register 40"),
REGISTER(0xE000E4A4, "NVIC_IPR41","Interrupt Priority Register 41"),
REGISTER(0xE000E4A8, "NVIC_IPR42","Interrupt Priority Register 42"),
REGISTER(0xE000E4AC, "NVIC_IPR43","Interrupt Priority Register 43"),
REGISTER(0xE000E4B0, "NVIC_IPR44","Interrupt Priority Register 44"),
REGISTER(0xE000E4B4, "NVIC_IPR45","Interrupt Priority Register 45"),
REGISTER(0xE000E4B8, "NVIC_IPR46","Interrupt Priority Register 46"),
REGISTER(0xE000E4BC, "NVIC_IPR47","Interrupt Priority Register 47"),
REGISTER(0xE000E4C0, "NVIC_IPR48","Interrupt Priority Register 48"),
REGISTER(0xE000E4C4, "NVIC_IPR49","Interrupt Priority Register 49"),
REGISTER(0xE000E4C8, "NVIC_IPR50","Interrupt Priority Register 50"),
REGISTER(0xE000E4CC, "NVIC_IPR51","Interrupt Priority Register 51"),
REGISTER(0xE000E4D0, "NVIC_IPR52","Interrupt Priority Register 52"),
REGISTER(0xE000E4D4, "NVIC_IPR53","Interrupt Priority Register 53"),
REGISTER(0xE000E4D8, "NVIC_IPR54","Interrupt Priority Register 54"),
REGISTER(0xE000E4DC, "NVIC_IPR55","Interrupt Priority Register 55"),
REGISTER(0xE000E4E0, "NVIC_IPR56","Interrupt Priority Register 56"),
REGISTER(0xE000E4E4, "NVIC_IPR57","Interrupt Priority Register 57"),
REGISTER(0xE000E4E8, "NVIC_IPR58","Interrupt Priority Register 58"),
REGISTER(0xE000E4EC, "NVIC_IPR59","Interrupt Priority Register 59"),
REGISTER(0xE000EF00, 'STIR', 'Software Trigger Interrupt Register' )
]

"""
System Control Block Registers
"""

SCB_Registers=[
 REGISTER(0xE000E008,'ACTLR', 'Auxiliary Control Register (R/W)'),
REGISTER(0xE000ED00,'CPUIDR', 'CPUID Base Register'),
    REGISTER(0xE000ED04,'ICSR','Interrupt Control and State Register'),
    REGISTER(0xE000ED08,'VTOR','Vector Table Offset Register'),
    REGISTER(0xE000ED0C, 'AIRCR','Application Interrupt and Reset Control Register'),
    REGISTER(0xE000ED10,'SCR','System Control Register'),
    REGISTER(0xE000ED14,'CCR','Configuration and Control Register'),
    REGISTER(0xE000ED18,'SHPR1','System Handler Priority Register 1' ),
    REGISTER(0xE000ED1C,'SHPR2','System Handler Priority Register 2' ),
    REGISTER(0xE000ED20,'SHPR3','System Handler Priority Register 3'),
    REGISTER(0xE000ED24,'SHCRS','System Handler Control and State Register '),
    REGISTER(0xE000ED28,'CFSR','Configurable Fault Status Register'),
    REGISTER(0xE000ED2C,'HFSR','HardFault Status Register'),
     REGISTER(0xE000ED34,'MMAR','MemManage Fault Address Register'),
     REGISTER(0xE000ED38,'BFAR','BusFault Address Register'),
     REGISTER(0xE000ED3C,'AFSR','Auxiliary Fault Status Register')
             ]

"""
System Tick Register
"""
SystemTick_Registers=[
    REGISTER(0xE000E010,'SYST_CSR','SysTick Control and Status Register'),
    REGISTER(0xE000E014,'SYST_RVR','SysTick Reload Value Register'),
    REGISTER(0xE000E018,'SYST_CVR','SysTick Current Value Register' ),
    REGISTER(0xE000E01C,'SYST_CALIB','SysTick Calibration Value Register' )
]

"""
MPU
"""

MPU_Registers = [
    REGISTER(0xE000ED90,'MPU_TYPE','MPU Type Register'),
    REGISTER(0xE000ED94,'MPU_CTRL','MPU Control Register'),
    REGISTER(0xE000ED98,'MPU_RNR','MPU Region Number Register' ),
    REGISTER(0xE000ED9C,'MPU_RBAR','MPU Region Base Address Register'),
    REGISTER(0xE000EDA0,'MPU_RASR','MPU Region Attribute and Size Register'),
    REGISTER(0xE000EDA4,'MPU_RBAR_A1','Alias of RBAR' ),
    REGISTER(0xE000EDA8,'MPU_RASR_A1','Alias of RASR' ),
    REGISTER(0xE000EDAC,'MPU_RBAR_A2','Alias of RBAR' ),
    REGISTER(0xE000EDB0,'MPU_RASR_A2','Alias of RASR' ),
    REGISTER(0xE000EDB4,'MPU_RBAR_A3','Alias of RBAR' ),
    REGISTER(0xE000EDB8,'MPU_RASR_A3','Alias of RASR' )
]

"""
FPU
"""

FPU_Registers=[
REGISTER(0xE000ED88,'CPACR','Coprocessor Access Control Register'),
REGISTER(0xE000EF34,'FPCCR','Floating-point Context Control Register'),
REGISTER(0xE000EF38,'FPCAR','Floating-point Context Address Register'),
REGISTER(0xE000EF3C, 'FPDSCR','Floating-point Default Status Control Register')
]


R=4
RX=5
RW=6
RWX=7

def fix_perm(addr,perm):
     s=ida_segment.getseg(addr) 
     s.perm=perm
     ida_segment.update_segm(s)


def add_address_inf():
    for r in FlexCAN_registers:
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)
    for r in NVIC_ControlRegs:
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)
    for r in SCB_Registers:
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)
    for r in SystemTick_Registers:
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)
    for r in MPU_Registers: 
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)
    for r in FPU_Registers: 
        ida_name.set_name(r.address,r.name,0)
        ida_bytes.set_cmt(r.address,r.comment,False)

    





def accept_file(file, n):

    global entry_p
    # Check if the dump contains the magic value at the beginning of the memory.
    found=1
    file.seek(0)
    if file.read(4) == MAGIC_VALUE:
        found -=1
    if found == 0:
        return 'Teensy32 loader'
    return 0


    # get the entry point 
    file.seek(4)
    entry_p = struct.unpack('<I',file.read(4))[0]
    file.seek(0)

def load_file(li, neflags, format):
    global entry_p

    # Set the processor type to ARM Little Endian 
    idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    
    # Load manually the segment contained in the file 
    idaapi.add_segm(0, 
                    NVIC_START, 
                    NVIC_SIZE, 
                    'NVIC', 
                    'DATA')

    # This is not true but only to trick the loader 
    # to not disassemble data from this address
    # (even if we already told it that its data area :/)
    fix_perm(NVIC_START,R)
    li.file2base(NVIC_START, 
                 NVIC_START, 
                 NVIC_START + NVIC_SIZE,
                 True)

    for nv in NVIC_Registers:
        ida_bytes.create_dword(nv.address,4,True)
        ida_name.set_name(nv.address,nv.name,0)
        ida_bytes.set_cmt(nv.address,nv.comment,False)


    
    fix_perm(NVIC_START,ida_segment.SEGPERM_READ|ida_segment.SEGPERM_WRITE)
    seg = ida_segment.get_segm_by_name('NVIC')
    ida_segregs.set_default_sreg_value(seg,
                                       ida_idp.str2reg('DS'),
                                       1)

    idaapi.add_segm(0, 
                    ProgramFlash_START, 
                    ProgramFlash_SIZE+NVIC_SIZE, 
                    'ProgramFlash', 
                    'CODE')


    seg = ida_segment.get_segm_by_name('ProgramFlash')
    ida_segregs.set_default_sreg_value(seg,
                                       ida_idp.str2reg('T'),
                                       1)
#    ida_segregs.set_sreg_at_next_code(ProgramFlash_START,
#                ProgramFlash_START+li.size() -NVIC_SIZE,
#                ida_idp.str2reg('T'),
#                1)
#

    ida_entry.add_entry(NVIC_START,NVIC_START,"NVIC",False,0)
    ida_entry.add_entry(entry_p,entry_p,"reset_handler",True,0)
    print('[entry _ p = %x]'%entry_p)
    li.file2base(ProgramFlash_START, 
                 ProgramFlash_START, 
                 ProgramFlash_START + li.size() - NVIC_SIZE , 
                 True)

    # Map each segment into memory according to the pre-defined layout
    for seg in SEGMENTS:
        # pos in file, start_ea in idb, end_ea in idb, active linear translation 
        idaapi.add_segm(0, seg.load, seg.load + seg.size, seg.name, seg.type)  
    print('Teensy32 firmare loaded.')
    add_address_inf()
    return 1
