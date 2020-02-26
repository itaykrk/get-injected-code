import json
import os
import psutil
from test.shellcode import get_shellcode
from get_injected_code import get_injected_threads, get_rwx_memory_regions
from winapi.kernel32 import OpenProcess, PROCESS_ALL_ACCESS, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
from winapi.version import IsWow64Process
from time import sleep

def inject_thread():
    buf = get_shellcode()
    proc_arch = os.environ['PROCESSOR_ARCHITECTURE']
    proc_arch_w6432 = os.environ.get('PROCESSOR_ARCHITEW6432')

    if proc_arch == 'x86' and proc_arch_w6432 is None:
        os_arch = '32-bit'
    else:
        os_arch = '64-bit'

    processses = {p.name(): p for p in psutil.process_iter()}
    target_process = None
    if os_arch == '64-bit':
        for p in processses:
            try:
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, processses[p].pid)
                if IsWow64Process(hProcess) and processses[p].pid != os.getpid():
                    target_process = processses[p]
                    break
            except OSError:
                continue
    else:
        target_process = processses.get("explorer.exe")

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, target_process.pid)
    start_addr = VirtualAllocEx(hProcess, 0, len(buf))
    WriteProcessMemory(hProcess, start_addr, buf)
    hThread = CreateRemoteThread(hProcess, None, 0, start_addr, 0, 0)
    return target_process, start_addr, hThread


if __name__ == "__main__":
    target_process, start_addr, hThread = inject_thread()
    print(f'{target_process.name()} pid: {target_process.pid}')

    sleep(1)
    injected_threads = get_injected_threads()
    rwx_regions = get_rwx_memory_regions()

    print(json.dumps(injected_threads, indent=2))
    print(json.dumps(rwx_regions, indent=2))