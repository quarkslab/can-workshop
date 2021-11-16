enum ISOTP_FRAMES {
 N_PCI_SF = 0x00,  /* single frame */
 N_PCI_FF = 0x10, /* first frame */
 N_PCI_CF = 0x20, /* consecutive frame */
 N_PCI_FC = 0x30  /* flow control */
};

enum UDS_SID {
 SESSION_CONTROL = 0x10,
 SECURITY_SESSION = 0x27, 
 READ_DATA_BY_ID  = 0x22,
 ROUTINE_CONTROL = 0x31,
 REQUEST_UPLOAD = 0x35,
 TRANSFER_DATA = 0x36,
 REQUEST_TRANSFER_EXIT = 0x37,

 DEFAULT_SESSION = 0x1,
 PROGRAMMING_SESSION =  0x2,
 EXTENDED_DIAGNOSTIC_SESSION = 0x3,
 OEM_SESSION = 0x42,
 TIER1_SESSION = 0x70
};

enum UDS_NRC{
    generalReject = 0x10,
    serviceNotSupported = 0x11,
    subfunctionNotSupported = 0x12,
    incorrectMessageLengthOrInvalidFormat = 0x13,
    conditionsNotCorrect = 0x22, 
    requestSequenceError = 0x24, 
    requestOutOfRange = 0x31, 
    securityAccessDenied = 0x33, 
    invalidKey = 0x35, 
    exceededNumberOfAttempts = 0x36,
    requiredTimeDelayNotExpired = 0x37, 
    uploadDownloadNotAccepted = 0x70, 
    transferDataSuspended = 0x71, 
    generalProgrammingFailure = 0x72, 
    wrongBlockSequenceCounter = 0x73,
    subfunctionNotSupportedInActiveSession = 0x7e, 
    serviceNotSupportedInActiveSession = 0x7f,
    vehiculeSpeedTooHigh = 0x88, 
    voltageTooHigh = 0x92, 
    voltageTooLow = 0x93
}; 

enum MB_STATUS {
  INACTIVE=0,
  BUSY=1,
  FULL=2,
  EMPTY=4,
  OVERRUN=6,
  RANSWER=10 /* Remote Answer*/
};
