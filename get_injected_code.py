import json
import traceback
import os
import psutil
from base64 import b64encode
from utils import adjust_privileges, get_loaded_modules, get_thread_module_from_addr
from winapi.version import GetSystemInfo
from winapi.ntdll import NtQueryInformationThread, ThreadQuerySetWin32StartAddress
from winapi.advapi32 import OpenThreadToken, TOKEN_ALL_ACCESS
from constants import BLACKLIST_PROCESSES, BUFFER_SIZE, MEMORY_PROTECTION_CONSTANTS, MEMORY_STATES_CONSTANTS, \
    MEMORY_TYPE_CONSTANTS, MEMORY_PROTECTION_MODIFIERS_CONSTANTS
from winapi.kernel32 import PAGE_EXECUTE_READWRITE, CreateToolhelp32Snapshot, Thread32First, TH32CS_SNAPTHREAD, \
    Thread32Next, \
    OpenThread, THREAD_ALL_ACCESS_VISTA, OpenProcess, PROCESS_ALL_ACCESS_VISTA, VirtualQueryEx, MEM_COMMIT, MEM_IMAGE, \
    ReadProcessMemory, QueryFullProcessImageName, GetThreadTimes, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, \
    MEM_RESERVE


processes = {p.pid: p for p in psutil.process_iter() if p != os.getpid()}

def get_injected_threads():
    """
    # https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2

    """

    skipped_threads_access_denied = 0
    injected_threads_list = []
    skipped_threads_exceptions = []
    analyzed_threads = 0


    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)  # Create snapshot of all the running threads
    thread = Thread32First(h_snapshot)  # get the first thread

    while Thread32Next(h_snapshot, thread):  # return 0 if no more threads
        try:
            if thread.th32OwnerProcessID in BLACKLIST_PROCESSES or thread is None:
                thread = Thread32Next(h_snapshot, thread)
                continue
            h_thread = OpenThread(THREAD_ALL_ACCESS_VISTA, False, thread.th32ThreadID)  # get thread handle

            thread_base_address = NtQueryInformationThread(h_thread, ThreadQuerySetWin32StartAddress)  # query thread for base\start address
            h_process = OpenProcess(PROCESS_ALL_ACCESS_VISTA, 0, thread.th32OwnerProcessID)  # get thread related process

            memory_basic_info = VirtualQueryEx(h_process, thread_base_address)  # get process memory protection info on thread base address
            allocated_memory_protection = memory_basic_info.AllocationProtect
            memory_protection = memory_basic_info.Protect
            memory_state = memory_basic_info.State
            memory_type = memory_basic_info.Type

            # if memory section is reserved(COMMIT) and not from the PE sections that on disk(MEM_IMAGE)
            # OR memory section permissions are READ WRITE AND EXECUTE
            # Then thread is suspicious as injected.
            if ((memory_state == MEM_COMMIT or memory_state == MEM_COMMIT | MEM_RESERVE) and memory_type != MEM_IMAGE) or memory_protection == PAGE_EXECUTE_READWRITE:
                proc = processes.get(thread.th32OwnerProcessID)
                if proc:
                    kernel_path = QueryFullProcessImageName(h_process)
                    # check if thread has unique token
                    try:
                        # get thread unique token in the future
                        OpenThreadToken(h_thread, DesiredAccess=TOKEN_ALL_ACCESS)
                        is_unique_thread_token = True
                    except OSError as e:
                        # if not check process token in the future
                        is_unique_thread_token = False

                    creation_time, exit_time, kernel_time, user_time = GetThreadTimes(h_thread)

                    path = proc.exe()
                    kernel_path = kernel_path.decode()
                    buf = ReadProcessMemory(h_process, thread_base_address, BUFFER_SIZE)  # dump thread content (1024 bytes)


                    thread_dict = {
                        'name': proc.name(),
                        'pid': proc.pid,
                        'thread_creation_time': creation_time,
                        'parent_id': proc.ppid(),
                        'path': path,
                        'kernel_path': kernel_path,
                        'cmdline': proc.cmdline(),
                        'thread_id': thread.th32ThreadID,
                        'allocated_memory_protecion': MEMORY_PROTECTION_CONSTANTS[allocated_memory_protection],
                        'memory_protection': MEMORY_PROTECTION_CONSTANTS[memory_protection] if memory_protection in MEMORY_PROTECTION_CONSTANTS else memory_protection,
                        'memory_state': MEMORY_STATES_CONSTANTS[memory_state] if memory_state in MEMORY_STATES_CONSTANTS else memory_state,
                        'memory_type': MEMORY_TYPE_CONSTANTS[memory_type] if memory_type in MEMORY_TYPE_CONSTANTS else memory_type,
                        'base_priority': thread.tpBasePri,
                        'is_unique_thread_token': is_unique_thread_token,
                        'username': proc.username(),
                        'base_address': thread_base_address,
                        'size': memory_basic_info.RegionSize,
                        'bytes': b64encode(buf).decode(encoding='utf-8'),
                        "path_mismatch": path != kernel_path,
                    }
                    modules = get_loaded_modules(thread.th32OwnerProcessID)
                    if modules:
                        mod_name, mod_base, mod_size = get_thread_module_from_addr(thread_base_address, modules)
                        thread_dict['module'] = {'name': mod_name,
                                                 'mod_base_address': mod_base,
                                                 'mod_size': mod_size
                                                 }
                    injected_threads_list.append(thread_dict)
        except OSError:  # Access denied
            skipped_threads_access_denied += 1
            continue
        except Exception as e:
            skipped_threads_exceptions.append("{}\n{}".format(e, traceback.format_exc()))
            continue
        analyzed_threads += 1

    return {"injected_threads": injected_threads_list,
            "skipped_threads_access_denied": skipped_threads_access_denied,
            "skipped_threads_exceptions": skipped_threads_exceptions,
            "analyzed_threads": analyzed_threads}


def get_rwx_memory_regions():
    """
    Scans processes memory and looks for memory regions with RWX permissions.

    """
    rwx_memory_regions = []
    skipped_memory_regions = []

    si = GetSystemInfo()
    proc_max_address = si.lpMaximumApplicationAddress


    for pid in processes:
        proc_min_address = si.lpMinimumApplicationAddress
        try:
            h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
        except OSError:
            continue
        while proc_min_address < proc_max_address:
            try:
                memory_basic_info = VirtualQueryEx(h_process, proc_min_address)

                memory_protection = None
                if memory_basic_info.Protect not in MEMORY_PROTECTION_CONSTANTS:
                    for modifier in MEMORY_PROTECTION_MODIFIERS_CONSTANTS:
                        try:
                            memory_protection = memory_basic_info.Protect - modifier
                            if memory_protection in MEMORY_PROTECTION_CONSTANTS:
                                memory_protection = "{protect}|{modifier}".format(protect=MEMORY_PROTECTION_CONSTANTS[memory_protection],
                                                                          modifier=MEMORY_PROTECTION_MODIFIERS_CONSTANTS[modifier])
                        except KeyError:
                            continue
                else:
                    memory_protection = MEMORY_PROTECTION_CONSTANTS[memory_basic_info.Protect]

                if memory_basic_info.Protect == PAGE_EXECUTE_READWRITE:
                    buf = ReadProcessMemory(h_process, memory_basic_info.BaseAddress, BUFFER_SIZE)
                    rwx_memory_regions.append({
                        'name': processes[pid].name(),
                        'pid': pid,
                        'parent_id': processes[pid].ppid(),
                        'path': processes[pid].exe(),
                        'cmdline': processes[pid].cmdline(),
                        'username': processes[pid].username(),
                        'base_address': memory_basic_info.BaseAddress,
                        'memory_protection': memory_protection,
                        'memory_state':  MEMORY_STATES_CONSTANTS[memory_basic_info.State],
                        'memory_type': MEMORY_TYPE_CONSTANTS[memory_basic_info.Type] if memory_basic_info.Type in MEMORY_TYPE_CONSTANTS else memory_basic_info.Type,
                        'size': memory_basic_info.RegionSize,
                        'bytes': b64encode(buf).decode(encoding='utf-8'),
                    })
            except KeyError:
                if memory_basic_info.Protect == 0:
                    proc_min_address += memory_basic_info.RegionSize
                    continue
            except PermissionError:
                skipped_memory_regions.append(f'process: {processes[pid].name()}; addr: {proc_min_address}')
            proc_min_address += memory_basic_info.RegionSize

    return {'rwx_memory_regions': rwx_memory_regions,
            'skipped_memory_regions': skipped_memory_regions
            }

if __name__ == "__main__":
    adjust_privileges()  # enable seDebugPrivilege

    injected_threads = get_injected_threads()
    rwx_regions = get_rwx_memory_regions()

    with open("injected_threads.json", "w") as outfd:
        json.dump(injected_threads, outfd)
    with open("rwx_memory_regions.json", "w") as outfd:
        json.dump(rwx_regions, outfd)
