from ctypes import WinError
from winapi.advapi32 import TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, OpenProcessToken, LookupPrivilegeValue, \
    SE_PRIVILEGE_ENABLED, AdjustTokenPrivileges
from winapi.kernel32 import CreateToolhelp32Snapshot, TH32CS_SNAPMODULE, Module32First, Module32Next
from winapi.version import GetCurrentProcess



def adjust_privileges():
    '''
    enabling seDebugPrivilege for debugging remote processes
    '''
    try:
        flags = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        h_token = OpenProcessToken(GetCurrentProcess(), flags)
        id = LookupPrivilegeValue(None, "seDebugPrivilege")
        new_privs = [(id, SE_PRIVILEGE_ENABLED)]
        AdjustTokenPrivileges(h_token, new_privs)
        return True
    except WinError:
        return False


def get_loaded_modules(pid):
    '''
    enumerates process loaded modules (DLLs)
    :param pid: target process id
    '''
    modules = []
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if hModuleSnap:
        me = Module32First(hModuleSnap)
        modules.append((me.szModule.decode(encoding='utf-8'), me.modBaseAddr, me.modBaseSize))
        while Module32Next(hModuleSnap, me):
            modules.append((me.szModule.decode(encoding='utf-8'), me.modBaseAddr, me.modBaseSize))
        return modules
    return None


def get_thread_module_from_addr(thread_base_address, modules):
        if modules:
            for mod_name, mod_base, mod_size in modules:
                if thread_base_address > mod_base and thread_base_address < (mod_base + mod_size):
                    return mod_name, mod_base, mod_size
        return None, None, None
