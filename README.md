# Get injected code

Python version of [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2). This script is also looks for any memory regions in user space processes with RWX permissions. Written 2 years ago so don't judge :)

Support python 3.6 and above.

# Usage

`python get-injected_code.py`

Outputs two json files `injected_threads.json` for injected threads and `rwx_memory_regions.json` memory regions with RWX permissions.

# Credits

- [@jaredcatkinson](https://twitter.com/jaredcatkinson?s=20) - [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) 
- [@Mario_Vilas](https://twitter.com/Mario_Vilas?s=20) - part of [winappdbg](https://github.com/MarioVilas/winappdbg) code was converted to python 3 and used for winapi calls.