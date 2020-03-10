# Get injected code

Python version of [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2). This script also looks for any memory regions in user space processes with RWX permissions. Written 2 years ago so don't judge :)

Support python 3.6 and above.

# Usage

`python get-injected_code.py`

Outputs one json file `injected_code.json` with the injected threads and suspicious memory regions information.


# Credits

- [@jaredcatkinson](https://twitter.com/jaredcatkinson?s=20) - [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) 
- [@Mario_Vilas](https://twitter.com/Mario_Vilas?s=20) - part of [winappdbg](https://github.com/MarioVilas/winappdbg) code was converted to python 3 and used for winapi calls.