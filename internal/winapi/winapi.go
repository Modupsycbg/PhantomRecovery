//go:build windows

package winapi

import (
	"syscall"
	"unsafe"
)

// =========================================================================
// DLL handles
// =========================================================================

var (
	User32   = syscall.NewLazyDLL("user32.dll")
	Kernel32 = syscall.NewLazyDLL("kernel32.dll")
	Crypt32  = syscall.NewLazyDLL("crypt32.dll")
)

// =========================================================================
// user32.dll procedures
// =========================================================================

var (
	// Keyboard hook
	SetWindowsHookExW        = User32.NewProc("SetWindowsHookExW")
	UnhookWindowsHookEx      = User32.NewProc("UnhookWindowsHookEx")
	CallNextHookEx           = User32.NewProc("CallNextHookEx")

	// Message loop
	GetMessageW              = User32.NewProc("GetMessageW")
	TranslateMessage         = User32.NewProc("TranslateMessage")
	DispatchMessageW         = User32.NewProc("DispatchMessageW")

	// Window queries
	GetForegroundWindow      = User32.NewProc("GetForegroundWindow")
	GetWindowTextW           = User32.NewProc("GetWindowTextW")
	GetWindowThreadProcessId = User32.NewProc("GetWindowThreadProcessId")
	EnumWindows              = User32.NewProc("EnumWindows")

	// Keyboard state / translation
	GetKeyboardState         = User32.NewProc("GetKeyboardState")
	GetAsyncKeyState         = User32.NewProc("GetAsyncKeyState")
	ToUnicodeEx              = User32.NewProc("ToUnicodeEx")
	GetKeyboardLayout        = User32.NewProc("GetKeyboardLayout")

	// Clipboard
	OpenClipboard            = User32.NewProc("OpenClipboard")
	CloseClipboard           = User32.NewProc("CloseClipboard")
	GetClipboardData         = User32.NewProc("GetClipboardData")
)

// =========================================================================
// kernel32.dll procedures
// =========================================================================

var (
	// Process / memory
	OpenProcess              = Kernel32.NewProc("OpenProcess")
	ReadProcessMemory        = Kernel32.NewProc("ReadProcessMemory")
	VirtualQueryEx           = Kernel32.NewProc("VirtualQueryEx")
	CloseHandle              = Kernel32.NewProc("CloseHandle")

	// Global memory (clipboard support)
	GlobalLock               = Kernel32.NewProc("GlobalLock")
	GlobalUnlock             = Kernel32.NewProc("GlobalUnlock")
	LocalFree                = Kernel32.NewProc("LocalFree")

	// Toolhelp process enumeration
	CreateToolhelp32Snapshot = Kernel32.NewProc("CreateToolhelp32Snapshot")
	Process32FirstW          = Kernel32.NewProc("Process32FirstW")
	Process32NextW           = Kernel32.NewProc("Process32NextW")

	// Timing
	GetTickCount64           = Kernel32.NewProc("GetTickCount64")
)

// =========================================================================
// crypt32.dll procedures
// =========================================================================

var (
	CryptUnprotectData = Crypt32.NewProc("CryptUnprotectData")
)

// =========================================================================
// Constants — keyboard hook
// =========================================================================

const (
	WH_KEYBOARD_LL = 13

	WM_KEYDOWN    = 0x0100
	WM_KEYUP      = 0x0101
	WM_SYSKEYDOWN = 0x0104
)

// =========================================================================
// Constants — virtual key codes
// =========================================================================

const (
	VK_BACK    = 0x08
	VK_TAB     = 0x09
	VK_RETURN  = 0x0D
	VK_SHIFT   = 0x10
	VK_CONTROL = 0x11
	VK_MENU    = 0x12 // Alt
	VK_CAPITAL = 0x14
	VK_ESCAPE  = 0x1B
	VK_SPACE   = 0x20
	VK_DELETE  = 0x2E
	VK_LWIN    = 0x5B
	VK_RWIN    = 0x5C

	VK_LSHIFT   = 0xA0
	VK_RSHIFT   = 0xA1
	VK_LCONTROL = 0xA2
	VK_RCONTROL = 0xA3
	VK_LMENU    = 0xA4
	VK_RMENU    = 0xA5

	LLKHF_UP = 0x80 // KBDLLHOOKSTRUCT.Flags — key is being released
)

// =========================================================================
// Constants — process access rights
// =========================================================================

const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

// =========================================================================
// Constants — clipboard formats
// =========================================================================

const (
	CF_UNICODETEXT = 13
)

// =========================================================================
// Constants — memory protection / state
// =========================================================================

const (
	MEM_COMMIT = 0x1000

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100
)

// =========================================================================
// Constants — Toolhelp32
// =========================================================================

const (
	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH           = 260
)

// =========================================================================
// Structs — keyboard hook
// =========================================================================

// KBDLLHOOKSTRUCT is the lParam data for WH_KEYBOARD_LL callbacks.
type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

// MSG is the Win32 MSG structure used by GetMessageW / DispatchMessageW.
type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

// =========================================================================
// Structs — process enumeration
// =========================================================================

// PROCESSENTRY32W is used with CreateToolhelp32Snapshot / Process32FirstW.
type PROCESSENTRY32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [MAX_PATH]uint16
}

// =========================================================================
// Structs — memory scanning
// =========================================================================

// MEMORY_BASIC_INFORMATION is returned by VirtualQueryEx.
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// =========================================================================
// Structs — DPAPI
// =========================================================================

// CRYPTOAPI_BLOB (DATA_BLOB) is used by CryptUnprotectData.
type CRYPTOAPI_BLOB struct {
	Size uint32
	Data *byte
}

// =========================================================================
// Helpers
// =========================================================================

// UTF16PtrToString converts a pointer to a null-terminated UTF-16 string
// into a Go string, reading at most maxLen uint16 code units.
func UTF16PtrToString(p *uint16, maxLen int) string {
	if p == nil || maxLen <= 0 {
		return ""
	}
	buf := make([]uint16, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		ch := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*2))
		if ch == 0 {
			break
		}
		buf = append(buf, ch)
	}
	return syscall.UTF16ToString(buf)
}
