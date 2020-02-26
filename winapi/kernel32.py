from winapi.defines import *
from winapi.version import NTDDI_VERSION, NTDDI_VISTA

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD            = 0x100
PAGE_NOCACHE          = 0x200
PAGE_WRITECOMBINE     = 0x400
MEM_COMMIT           = 0x1000
MEM_RESERVE          = 0x2000
MEM_DECOMMIT         = 0x4000
MEM_RELEASE          = 0x8000
MEM_FREE            = 0x10000
MEM_PRIVATE         = 0x20000
MEM_MAPPED          = 0x40000
MEM_RESET           = 0x80000
MEM_TOP_DOWN       = 0x100000
MEM_WRITE_WATCH    = 0x200000
MEM_PHYSICAL       = 0x400000
MEM_LARGE_PAGES  = 0x20000000
MEM_4MB_PAGES    = 0x80000000
SEC_FILE           = 0x800000
SEC_IMAGE         = 0x1000000
SEC_RESERVE       = 0x4000000
SEC_COMMIT        = 0x8000000
SEC_NOCACHE      = 0x10000000
SEC_LARGE_PAGES  = 0x80000000
MEM_IMAGE         = SEC_IMAGE
WRITE_WATCH_FLAG_RESET = 0x01
FILE_MAP_ALL_ACCESS = 0xF001F

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

# Process access rights for OpenProcess
PROCESS_TERMINATE                 = 0x0001
PROCESS_CREATE_THREAD             = 0x0002
PROCESS_SET_SESSIONID             = 0x0004
PROCESS_VM_OPERATION              = 0x0008
PROCESS_VM_READ                   = 0x0010
PROCESS_VM_WRITE                  = 0x0020
PROCESS_DUP_HANDLE                = 0x0040
PROCESS_CREATE_PROCESS            = 0x0080
PROCESS_SET_QUOTA                 = 0x0100
PROCESS_SET_INFORMATION           = 0x0200
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_SUSPEND_RESUME            = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Thread access rights for OpenThread
THREAD_TERMINATE                 = 0x0001
THREAD_SUSPEND_RESUME            = 0x0002
THREAD_ALERT                     = 0x0004
THREAD_GET_CONTEXT               = 0x0008
THREAD_SET_CONTEXT               = 0x0010
THREAD_SET_INFORMATION           = 0x0020
THREAD_QUERY_INFORMATION         = 0x0040
THREAD_SET_THREAD_TOKEN          = 0x0080
THREAD_IMPERSONATE               = 0x0100
THREAD_DIRECT_IMPERSONATION      = 0x0200
THREAD_SET_LIMITED_INFORMATION   = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

# The values of PROCESS_ALL_ACCESS and THREAD_ALL_ACCESS were changed in Vista/2008
PROCESS_ALL_ACCESS_NT = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
PROCESS_ALL_ACCESS_VISTA = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
THREAD_ALL_ACCESS_NT = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)
THREAD_ALL_ACCESS_VISTA = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

#todo: add windows version check
if NTDDI_VERSION < NTDDI_VISTA:
    PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS_NT
    THREAD_ALL_ACCESS = THREAD_ALL_ACCESS_NT
else:
    PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS_VISTA
    THREAD_ALL_ACCESS = THREAD_ALL_ACCESS_VISTA

class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          LONG),
        ('tpDeltaPri',         LONG),
        ('dwFlags',            DWORD),
    ]
LPTHREADENTRY32 = POINTER(THREADENTRY32)


# typedef struct tagMODULEENTRY32 {
#   DWORD dwSize;
#   DWORD th32ModuleID;
#   DWORD th32ProcessID;
#   DWORD GlblcntUsage;
#   DWORD ProccntUsage;
#   BYTE* modBaseAddr;
#   DWORD modBaseSize;
#   HMODULE hModule;
#   TCHAR szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR szExePath[MAX_PATH];
# } MODULEENTRY32,  *PMODULEENTRY32;
class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   LPVOID),  # BYTE*
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]
LPMODULEENTRY32 = POINTER(MODULEENTRY32)


class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ('BaseAddress',         DWORD),         # remote pointer
        ('AllocationBase',      DWORD),         # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          DWORD),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]


class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ('BaseAddress',         ULONGLONG),     # remote pointer
        ('AllocationBase',      ULONGLONG),     # remote pointer
        ('AllocationProtect',   DWORD),
        ('__alignment1',        DWORD),
        ('RegionSize',          ULONGLONG),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
        ('__alignment2',        DWORD),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress',         SIZE_T),    # remote pointer
        ('AllocationBase',      SIZE_T),    # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          SIZE_T),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)


# typedef struct _SECURITY_ATTRIBUTES {
#     DWORD nLength;
#     LPVOID lpSecurityDescriptor;
#     BOOL bInheritHandle;
# } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength',                 DWORD),
        ('lpSecurityDescriptor',    LPVOID),
        ('bInheritHandle',          BOOL),
    ]
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

class MemoryBasicInformation (object):
    """
    Memory information object returned by L{VirtualQueryEx}.
    """

    READABLE = (
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READONLY           |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    COPY_ON_WRITE = (
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_WRITECOPY
    )

    EXECUTABLE = (
                PAGE_EXECUTE            |
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    EXECUTABLE_AND_WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    def __init__(self, mbi=None):
        """
        @type  mbi: L{MEMORY_BASIC_INFORMATION} or L{MemoryBasicInformation}
        @param mbi: Either a L{MEMORY_BASIC_INFORMATION} structure or another
            L{MemoryBasicInformation} instance.
        """
        if mbi is None:
            self.BaseAddress        = None
            self.AllocationBase     = None
            self.AllocationProtect  = None
            self.RegionSize         = None
            self.State              = None
            self.Protect            = None
            self.Type               = None
        else:
            self.BaseAddress        = mbi.BaseAddress
            self.AllocationBase     = mbi.AllocationBase
            self.AllocationProtect  = mbi.AllocationProtect
            self.RegionSize         = mbi.RegionSize
            self.State              = mbi.State
            self.Protect            = mbi.Protect
            self.Type               = mbi.Type

            # Only used when copying MemoryBasicInformation objects, instead of
            # instancing them from a MEMORY_BASIC_INFORMATION structure.
            if hasattr(mbi, 'content'):
                self.content = mbi.content
            if hasattr(mbi, 'filename'):
                self.content = mbi.filename

    def __contains__(self, address):
        """
        Test if the given memory address falls within this memory region.
        @type  address: int
        @param address: Memory address to test.
        @rtype:  bool
        @return: C{True} if the given memory address falls within this memory
            region, C{False} otherwise.
        """
        return self.BaseAddress <= address < (self.BaseAddress + self.RegionSize)

    def is_free(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is free.
        """
        return self.State == MEM_FREE

    def is_reserved(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is reserved.
        """
        return self.State == MEM_RESERVE

    def is_commited(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is commited.
        """
        return self.State == MEM_COMMIT

    def is_image(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region belongs to an executable
            image.
        """
        return self.Type == MEM_IMAGE

    def is_mapped(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region belongs to a mapped file.
        """
        return self.Type == MEM_MAPPED

    def is_private(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is private.
        """
        return self.Type == MEM_PRIVATE

    def is_guard(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are guard pages.
        """
        return self.is_commited() and bool(self.Protect & PAGE_GUARD)

    def has_content(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region has any data in it.
        """
        return self.is_commited() and not bool(self.Protect & (PAGE_GUARD | PAGE_NOACCESS))

    def is_readable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are readable.
        """
        return self.has_content() and bool(self.Protect & self.READABLE)

    def is_writeable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are writeable.
        """
        return self.has_content() and bool(self.Protect & self.WRITEABLE)

    def is_copy_on_write(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are marked as
            copy-on-write. This means the pages are writeable, but changes
            are not propagated to disk.
        @note:
            Tipically data sections in executable images are marked like this.
        """
        return self.has_content() and bool(self.Protect & self.COPY_ON_WRITE)

    def is_executable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are executable.
        @note: Executable pages are always readable.
        """
        return self.has_content() and bool(self.Protect & self.EXECUTABLE)

    def is_executable_and_writeable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are executable and
            writeable.
        @note: The presence of such pages make memory corruption
            vulnerabilities much easier to exploit.
        """
        return self.has_content() and bool(self.Protect & self.EXECUTABLE_AND_WRITEABLE)




# DWORD WINAPI GetLastError(void);

def GetLastError():
    _GetLastError = windll.kernel32.GetLastError
    _GetLastError.argtypes = []
    _GetLastError.restype  = DWORD
    return _GetLastError()

# void WINAPI SetLastError(
#   __in  DWORD dwErrCode
# );
def SetLastError(dwErrCode):
    _SetLastError = windll.kernel32.SetLastError
    _SetLastError.argtypes = [DWORD]
    _SetLastError.restype  = None
    _SetLastError(dwErrCode)

def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    _CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    _CreateToolhelp32Snapshot.restype  = HANDLE

    hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        return None
    return hSnapshot


# BOOL WINAPI Thread32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPTHREADENTRY32 lpte
# );

def Thread32First(hSnapshot):
    _Thread32First = windll.kernel32.Thread32First
    _Thread32First.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32First.restype  = bool

    te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32First(hSnapshot, byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Thread32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPTHREADENTRY32 lpte
# );


def Thread32Next(hSnapshot, te = None):
    _Thread32Next = windll.kernel32.Thread32Next
    _Thread32Next.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32Next.restype  = bool

    if te is None:
        te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32Next(hSnapshot, byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te


# HANDLE WINAPI OpenThread(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwThreadId
# );


def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    _OpenThread = windll.kernel32.OpenThread
    _OpenThread.argtypes = [DWORD, BOOL, DWORD]
    _OpenThread.restype  = HANDLE

    hThread = _OpenThread(dwDesiredAccess, bool(bInheritHandle), dwThreadId)
    if hThread == NULL:
        raise ctypes.WinError()
    return hThread

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );


def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
    _OpenProcess = windll.kernel32.OpenProcess
    _OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    _OpenProcess.restype  = HANDLE

    hProcess = _OpenProcess(dwDesiredAccess, bool(bInheritHandle), dwProcessId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return hProcess

# SIZE_T WINAPI VirtualQueryEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPCVOID lpAddress,
#   __out     PMEMORY_BASIC_INFORMATION lpBuffer,
#   __in      SIZE_T dwLength
# );


def VirtualQueryEx(hProcess, lpAddress):
    _VirtualQueryEx = windll.kernel32.VirtualQueryEx
    _VirtualQueryEx.argtypes = [HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
    _VirtualQueryEx.restype  = SIZE_T

    lpBuffer  = MEMORY_BASIC_INFORMATION()
    dwLength  = sizeof(MEMORY_BASIC_INFORMATION)
    success   = _VirtualQueryEx(hProcess, lpAddress, byref(lpBuffer), dwLength)
    if success == 0:
        raise ctypes.WinError()
    return MemoryBasicInformation(lpBuffer)

# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );


def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
    _ReadProcessMemory = windll.kernel32.ReadProcessMemory
    _ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    _ReadProcessMemory.restype  = bool

    lpBuffer            = ctypes.create_string_buffer(b'', nSize)
    lpNumberOfBytesRead = SIZE_T(0)
    success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, byref(lpNumberOfBytesRead))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return lpBuffer.raw[:lpNumberOfBytesRead.value]

# BOOL WINAPI QueryFullProcessImageName(
#   __in     HANDLE hProcess,
#   __in     DWORD dwFlags,
#   __out    LPTSTR lpExeName,
#   __inout  PDWORD lpdwSize
# );


def QueryFullProcessImageNameA(hProcess, dwFlags = 0):
    _QueryFullProcessImageNameA = windll.kernel32.QueryFullProcessImageNameA
    _QueryFullProcessImageNameA.argtypes = [HANDLE, DWORD, LPSTR, PDWORD]
    _QueryFullProcessImageNameA.restype  = bool

    dwSize = MAX_PATH
    while 1:
        lpdwSize = DWORD(dwSize)
        lpExeName = ctypes.create_string_buffer(b'', lpdwSize.value + 1)
        success = _QueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, byref(lpdwSize))
        if success and 0 < lpdwSize.value < dwSize:
            break
        error = GetLastError()
        if error != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        dwSize = dwSize + 256
        if dwSize > 0x1000:
            # this prevents an infinite loop in Windows 2008 when the path has spaces,
            # see http://msdn.microsoft.com/en-us/library/ms684919(VS.85).aspx#4
            raise ctypes.WinError(error)
    return lpExeName.value


def QueryFullProcessImageNameW(hProcess, dwFlags = 0):
    _QueryFullProcessImageNameW = windll.kernel32.QueryFullProcessImageNameW
    _QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, PDWORD]
    _QueryFullProcessImageNameW.restype  = bool

    dwSize = MAX_PATH
    while 1:
        lpdwSize = DWORD(dwSize)
        lpExeName = ctypes.create_unicode_buffer('', lpdwSize.value + 1)
        success = _QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, byref(lpdwSize))
        if success and 0 < lpdwSize.value < dwSize:
            break
        error = GetLastError()
        if error != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        dwSize = dwSize + 256
        if dwSize > 0x1000:
            # this prevents an infinite loop in Windows 2008 when the path has spaces,
            # see http://msdn.microsoft.com/en-us/library/ms684919(VS.85).aspx#4
            raise ctypes.WinError(error)
    return lpExeName.value

QueryFullProcessImageName = GuessStringType(QueryFullProcessImageNameA, QueryFullProcessImageNameW)

# BOOL WINAPI CloseHandle(
#   __in  HANDLE hObject
# );


def CloseHandle(hHandle):
    _CloseHandle = windll.kernel32.CloseHandle
    _CloseHandle.argtypes = [HANDLE]
    _CloseHandle.restype  = bool
    _CloseHandle.errcheck = RaiseIfZero
    _CloseHandle(hHandle)


# Python Class which is converted to a C struct
# It encapsulates Time data, with a low and high number
# We use it to get Process/Thread times (user/system/etc.)
class _FILETIME(Structure):
    _fields_ = [('dwLowDateTime', DWORD),
                ('dwHighDateTime', DWORD)]


def GetThreadTimes(handle):
    # Create all the structures needed to make API Call
    creation_time = _FILETIME()
    exit_time = _FILETIME()
    kernel_time = _FILETIME()
    user_time = _FILETIME()
    _GetThreadTimes = windll.kernel32.GetThreadTimes
    _GetThreadTimes(handle, byref(creation_time), byref(exit_time), byref(kernel_time), byref(user_time))
    return (FileTimeToSystemTime(creation_time), FileTimeToSystemTime(exit_time), FileTimeToSystemTime(kernel_time), FileTimeToSystemTime(user_time))


class SYSTEMTIME(Structure):
    _fields_ = [
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD),
    ]


def FileTimeToSystemTime(ftime):
    _FileTimeToSystemTime = windll.kernel32.FileTimeToSystemTime
    _FileTimeToSystemTime.restype = BOOL
    system_time = SYSTEMTIME()
    _FileTimeToSystemTime(byref(ftime), byref(system_time))
    formatted_date = "{day}-{month}-{year} {hour}:{minute}:{seconds}.{mili}".format(day=system_time.wDay, month=system_time.wMonth, year=system_time.wYear, hour=system_time.wHour, minute=system_time.wMinute, seconds=system_time.wSecond, mili=system_time.wMilliseconds)
    return formatted_date

# BOOL WINAPI Module32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPMODULEENTRY32 lpme
# );
def Module32First(hSnapshot):
    _Module32First = windll.kernel32.Module32First
    _Module32First.argtypes = [HANDLE, LPMODULEENTRY32]
    _Module32First.restype  = bool

    me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = _Module32First(hSnapshot, byref(me))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return me

# BOOL WINAPI Module32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPMODULEENTRY32 lpme
# );
def Module32Next(hSnapshot, me = None):
    _Module32Next = windll.kernel32.Module32Next
    _Module32Next.argtypes = [HANDLE, LPMODULEENTRY32]
    _Module32Next.restype  = bool

    if me is None:
        me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = _Module32Next(hSnapshot, byref(me))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return me

# BOOL WINAPI WriteProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __in   LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesWritten
# );
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer):
    _WriteProcessMemory = windll.kernel32.WriteProcessMemory
    _WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    _WriteProcessMemory.restype  = bool

    nSize                   = len(lpBuffer)
    lpBuffer                = ctypes.create_string_buffer(lpBuffer)
    lpNumberOfBytesWritten  = SIZE_T(0)
    success = _WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, byref(lpNumberOfBytesWritten))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return lpNumberOfBytesWritten.value

# LPVOID WINAPI VirtualAllocEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPVOID lpAddress,
#   __in      SIZE_T dwSize,
#   __in      DWORD flAllocationType,
#   __in      DWORD flProtect
# );
def VirtualAllocEx(hProcess, lpAddress = 0, dwSize = 0x1000, flAllocationType = MEM_COMMIT, flProtect = PAGE_EXECUTE_READWRITE):
    _VirtualAllocEx = windll.kernel32.VirtualAllocEx
    _VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
    _VirtualAllocEx.restype  = LPVOID

    lpAddress = _VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if lpAddress == NULL:
        raise ctypes.WinError()
    return lpAddress


# HANDLE WINAPI CreateRemoteThread(
#   __in   HANDLE hProcess,
#   __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   __in   SIZE_T dwStackSize,
#   __in   LPTHREAD_START_ROUTINE lpStartAddress,
#   __in   LPVOID lpParameter,
#   __in   DWORD dwCreationFlags,
#   __out  LPDWORD lpThreadId
# );
def CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags):
    _CreateRemoteThread = windll.kernel32.CreateRemoteThread
    _CreateRemoteThread.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
    _CreateRemoteThread.restype  = HANDLE

    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = byref(lpThreadAttributes)
    dwThreadId = DWORD(0)
    hThread = _CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, byref(dwThreadId))
    if not hThread:
        raise ctypes.WinError()
    return hThread