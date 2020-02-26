from winapi.defines import *

# Token access rights
TOKEN_ASSIGN_PRIMARY    = 0x0001
TOKEN_DUPLICATE         = 0x0002
TOKEN_IMPERSONATE       = 0x0004
TOKEN_QUERY             = 0x0008
TOKEN_QUERY_SOURCE      = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS     = 0x0040
TOKEN_ADJUST_DEFAULT    = 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID)

#--- GetTokenInformation enums and structures ---------------------------------

# typedef enum _TOKEN_INFORMATION_CLASS {
#   TokenUser                              = 1,
#   TokenGroups,
#   TokenPrivileges,
#   TokenOwner,
#   TokenPrimaryGroup,
#   TokenDefaultDacl,
#   TokenSource,
#   TokenType,
#   TokenImpersonationLevel,
#   TokenStatistics,
#   TokenRestrictedSids,
#   TokenSessionId,
#   TokenGroupsAndPrivileges,
#   TokenSessionReference,
#   TokenSandBoxInert,
#   TokenAuditPolicy,
#   TokenOrigin,
#   TokenElevationType,
#   TokenLinkedToken,
#   TokenElevation,
#   TokenHasRestrictions,
#   TokenAccessInformation,
#   TokenVirtualizationAllowed,
#   TokenVirtualizationEnabled,
#   TokenIntegrityLevel,
#   TokenUIAccess,
#   TokenMandatoryPolicy,
#   TokenLogonSid,
#   TokenIsAppContainer,
#   TokenCapabilities,
#   TokenAppContainerSid,
#   TokenAppContainerNumber,
#   TokenUserClaimAttributes,
#   TokenDeviceClaimAttributes,
#   TokenRestrictedUserClaimAttributes,
#   TokenRestrictedDeviceClaimAttributes,
#   TokenDeviceGroups,
#   TokenRestrictedDeviceGroups,
#   TokenSecurityAttributes,
#   TokenIsRestricted,
#   MaxTokenInfoClass
# } TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;


TokenUser                               = 1
TokenGroups                             = 2
TokenPrivileges                         = 3
TokenOwner                              = 4
TokenPrimaryGroup                       = 5
TokenDefaultDacl                        = 6
TokenSource                             = 7
TokenType                               = 8
TokenImpersonationLevel                 = 9
TokenStatistics                         = 10
TokenRestrictedSids                     = 11
TokenSessionId                          = 12
TokenGroupsAndPrivileges                = 13
TokenSessionReference                   = 14
TokenSandBoxInert                       = 15
TokenAuditPolicy                        = 16
TokenOrigin                             = 17
TokenElevationType                      = 18
TokenLinkedToken                        = 19
TokenElevation                          = 20
TokenHasRestrictions                    = 21
TokenAccessInformation                  = 22
TokenVirtualizationAllowed              = 23
TokenVirtualizationEnabled              = 24
TokenIntegrityLevel                     = 25
TokenUIAccess                           = 26
TokenMandatoryPolicy                    = 27
TokenLogonSid                           = 28
TokenIsAppContainer                     = 29
TokenCapabilities                       = 30
TokenAppContainerSid                    = 31
TokenAppContainerNumber                 = 32
TokenUserClaimAttributes                = 33
TokenDeviceClaimAttributes              = 34
TokenRestrictedUserClaimAttributes      = 35
TokenRestrictedDeviceClaimAttributes    = 36
TokenDeviceGroups                       = 37
TokenRestrictedDeviceGroups             = 38
TokenSecurityAttributes                 = 39
TokenIsRestricted                       = 40
MaxTokenInfoClass                       = 41

SE_PRIVILEGE_ENABLED            = 0x00000002
SE_PRIVILEGE_REMOVED            = 0x00000004
#--- TOKEN_PRIVILEGE structure ------------------------------------------------
# typedef struct _LUID {
#   DWORD LowPart;
#   LONG HighPart;
# } LUID,
#  *PLUID;
class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

PLUID = POINTER(LUID)

# typedef struct _LUID_AND_ATTRIBUTES {
#   LUID Luid;
#   DWORD Attributes;
# } LUID_AND_ATTRIBUTES,
#  *PLUID_AND_ATTRIBUTES;
class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

# typedef struct _TOKEN_PRIVILEGES {
#   DWORD PrivilegeCount;
#   LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
# } TOKEN_PRIVILEGES,
#  *PTOKEN_PRIVILEGES;
class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
##        ("Privileges",      LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]
    # See comments on AdjustTokenPrivileges about this structure

PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

# BOOL WINAPI OpenThreadToken(
#   __in   HANDLE ThreadHandle,
#   __in   DWORD DesiredAccess,
#   __in   BOOL OpenAsSelf,
#   __out  PHANDLE TokenHandle
# );
def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf = False):
    _OpenThreadToken = windll.advapi32.OpenThreadToken
    _OpenThreadToken.argtypes = [HANDLE, DWORD, BOOL, PHANDLE]
    _OpenThreadToken.restype  = bool
    _OpenThreadToken.errcheck = RaiseIfZero

    NewTokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, byref(NewTokenHandle))
    return NewTokenHandle.value


# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess = TOKEN_ALL_ACCESS):
    _OpenProcessToken = windll.advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
    _OpenProcessToken.restype  = bool
    _OpenProcessToken.errcheck = RaiseIfZero

    NewTokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenProcessToken(ProcessHandle, DesiredAccess, byref(NewTokenHandle))
    return NewTokenHandle.value

# BOOL WINAPI LookupPrivilegeValue(
#   __in_opt  LPCTSTR lpSystemName,
#   __in      LPCTSTR lpName,
#   __out     PLUID lpLuid
# );
def LookupPrivilegeValueA(lpSystemName, lpName):
    _LookupPrivilegeValueA = windll.advapi32.LookupPrivilegeValueA
    _LookupPrivilegeValueA.argtypes = [LPSTR, LPSTR, PLUID]
    _LookupPrivilegeValueA.restype  = bool
    _LookupPrivilegeValueA.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueA(lpSystemName, lpName, byref(lpLuid))
    return lpLuid

def LookupPrivilegeValueW(lpSystemName, lpName):
    _LookupPrivilegeValueW = windll.advapi32.LookupPrivilegeValueW
    _LookupPrivilegeValueW.argtypes = [LPWSTR, LPWSTR, PLUID]
    _LookupPrivilegeValueW.restype  = bool
    _LookupPrivilegeValueW.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueW(lpSystemName, lpName, byref(lpLuid))
    return lpLuid

LookupPrivilegeValue = GuessStringType(LookupPrivilegeValueA, LookupPrivilegeValueW)

# BOOL WINAPI AdjustTokenPrivileges(
#   __in       HANDLE TokenHandle,
#   __in       BOOL DisableAllPrivileges,
#   __in_opt   PTOKEN_PRIVILEGES NewState,
#   __in       DWORD BufferLength,
#   __out_opt  PTOKEN_PRIVILEGES PreviousState,
#   __out_opt  PDWORD ReturnLength
# );
def AdjustTokenPrivileges(TokenHandle, NewState = ()):
    _AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
    _AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, LPVOID, DWORD, LPVOID, LPVOID]
    _AdjustTokenPrivileges.restype  = bool
    _AdjustTokenPrivileges.errcheck = RaiseIfZero
    #
    # I don't know how to allocate variable sized structures in ctypes :(
    # so this hack will work by using always TOKEN_PRIVILEGES of one element
    # and calling the API many times. This also means the PreviousState
    # parameter won't be supported yet as it's too much hassle. In a future
    # version I look forward to implementing this function correctly.
    #
    if not NewState:
        _AdjustTokenPrivileges(TokenHandle, TRUE, NULL, 0, NULL, NULL)
    else:
        success = True
        for (privilege, enabled) in NewState:
            if not isinstance(privilege, LUID):
                privilege = LookupPrivilegeValue(NULL, privilege)
            if enabled == True:
                flags = SE_PRIVILEGE_ENABLED
            elif enabled == False:
                flags = SE_PRIVILEGE_REMOVED
            elif enabled == None:
                flags = 0
            else:
                flags = enabled
            laa = LUID_AND_ATTRIBUTES(privilege, flags)
            tp  = TOKEN_PRIVILEGES(1, laa)
            _AdjustTokenPrivileges(TokenHandle, FALSE, byref(tp), sizeof(tp), NULL, NULL)