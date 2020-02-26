from winapi.defines import *

THREADINFOCLASS         = DWORD

# THREAD_INFORMATION_CLASS
ThreadBasicInformation              = 0
ThreadTimes                         = 1
ThreadPriority                      = 2
ThreadBasePriority                  = 3
ThreadAffinityMask                  = 4
ThreadImpersonationToken            = 5
ThreadDescriptorTableEntry          = 6
ThreadEnableAlignmentFaultFixup     = 7
ThreadEventPair                     = 8
ThreadQuerySetWin32StartAddress     = 9
ThreadZeroTlsCell                   = 10
ThreadPerformanceCount              = 11
ThreadAmILastThread                 = 12
ThreadIdealProcessor                = 13
ThreadPriorityBoost                 = 14
ThreadSetTlsArrayAddress            = 15
ThreadIsIoPending                   = 16
ThreadHideFromDebugger              = 17

#--- PEB and TEB structures, constants and data types -------------------------

# From http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
#
# typedef struct _CLIENT_ID
# {
#     PVOID UniqueProcess;
#     PVOID UniqueThread;
# } CLIENT_ID, *PCLIENT_ID;


class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess",   PVOID),
        ("UniqueThread",    PVOID),
]

#--- THREAD_BASIC_INFORMATION structure ---------------------------------------

# From http://undocumented.ntinternals.net/UserMode/Structures/THREAD_BASIC_INFORMATION.html
#
# typedef struct _THREAD_BASIC_INFORMATION {
#   NTSTATUS ExitStatus;
#   PVOID TebBaseAddress;
#   CLIENT_ID ClientId;
#   KAFFINITY AffinityMask;
#   KPRIORITY Priority;
#   KPRIORITY BasePriority;
# } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",      NTSTATUS),
        ("TebBaseAddress",  PVOID),     # PTEB
        ("ClientId",        CLIENT_ID),
        ("AffinityMask",    KAFFINITY),
        ("Priority",        SDWORD),
        ("BasePriority",    SDWORD),
]


def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformationLength = None):
    _NtQueryInformationThread = windll.ntdll.NtQueryInformationThread
    _NtQueryInformationThread.argtypes = [HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG]
    _NtQueryInformationThread.restype = NTSTATUS
    if ThreadInformationLength is not None:
        ThreadInformation = ctypes.create_string_buffer("", ThreadInformationLength)
    else:
        if   ThreadInformationClass == ThreadBasicInformation:
            ThreadInformation = THREAD_BASIC_INFORMATION()
        elif ThreadInformationClass == ThreadHideFromDebugger:
            ThreadInformation = BOOLEAN()
        elif ThreadInformationClass == ThreadQuerySetWin32StartAddress:
            ThreadInformation = PVOID()
        elif ThreadInformationClass in (ThreadAmILastThread, ThreadPriorityBoost):
            ThreadInformation = DWORD()
        elif ThreadInformationClass == ThreadPerformanceCount:
            ThreadInformation = LONGLONG()  # LARGE_INTEGER
        else:
            raise Exception("Unknown ThreadInformationClass, use an explicit ThreadInformationLength value instead")
        ThreadInformationLength = sizeof(ThreadInformation)
    ReturnLength = ULONG(0)
    ntstatus = _NtQueryInformationThread(ThreadHandle, ThreadInformationClass, byref(ThreadInformation), ThreadInformationLength, byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError( RtlNtStatusToDosError(ntstatus) )
    if   ThreadInformationClass == ThreadBasicInformation:
        retval = ThreadInformation
    elif ThreadInformationClass == ThreadHideFromDebugger:
        retval = bool(ThreadInformation.value)
    elif ThreadInformationClass in (ThreadQuerySetWin32StartAddress, ThreadAmILastThread, ThreadPriorityBoost, ThreadPerformanceCount):
        retval = ThreadInformation.value
    else:
        retval = ThreadInformation.raw[:ReturnLength.value]
    return retval

# ULONG WINAPI RtlNtStatusToDosError(
#   __in  NTSTATUS Status
# );


def RtlNtStatusToDosError(Status):
    _RtlNtStatusToDosError = windll.ntdll.RtlNtStatusToDosError
    _RtlNtStatusToDosError.argtypes = [NTSTATUS]
    _RtlNtStatusToDosError.restype = ULONG
    return _RtlNtStatusToDosError(Status)