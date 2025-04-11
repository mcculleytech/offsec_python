# overview

This repository consists of the python projects as laid out by the [Python 201](https://academy.tcm-sec.com/p/python-201-for-hackers) training by TCM Security with a focus on utilizing the [`ctypes`](https://docs.python.org/3/library/ctypes.html) python library to interact with the Win32 API. 

---

## remote dll execution
This script allows for loading and executing an external DLL into an existing process based on it's PID.

## process creation and shellcode execution
Spawns a process, reserves memory in the created process, inject shellcode (in the example a window with hello world will spawn) into the process, then execute. Note that the way it works changes the permissions on the memory space allocated. It first creates the space with read-write access, then changes that to read-execute in order to be a little more stealthy than simply having read-write-execute on the memory space allocated. 

## keylogger
Utilizes the `user32` dll to record keyboard events. While this is possible in a more 'pythonic' way, using the Win32 API allows for more control. 

## buffer overflow
Utilizes the 'An Executable Stack' challenge from [247CTF](https://247ctf.com/) to demonstrate how python can be used for binary exploitation. Requires the binary from the ctf website, a linux host, and `pwntools` to run properly. 

## encrypted bind shell
A bind shell (socket to connect to for RCE) with encrypted communication. Note that the encryption is not proper, just a PoC. It does support multiple users.

## burp suite extension
A burp extention. Requires Jython installation.

### next steps
Utilize the `pyinstaller` module to create exe binaries for more usefulness. 