# GPG Commit Signing Setup

## Required Setup for Verified Commits

To ensure all commits are verified on GitHub, follow these steps:

### 1. Generate GPG Key (Interactive)
```bash
# Generate new GPG key (requires interactive terminal)
gpg --full-generate-key

# Select options:
# - Type: (1) RSA and RSA (default)
# - Key size: 4096
# - Expiration: 0 (no expiration)
# - Real name: Fahd Murtaza  
# - Email: info@fahdmurtaza.com (must match GitHub verified email)
# - Passphrase: [secure passphrase]
```

### 2. Get GPG Key ID
```bash
# List GPG keys and copy the key ID
gpg --list-secret-keys --keyid-format=long

# Example output:
# sec   rsa4096/YOUR_KEY_ID 2025-10-15 [SC]
#       [full key fingerprint]
# uid                 [ultimate] Fahd Murtaza <info@fahdmurtaza.com>
# ssb   rsa4096/[subkey] 2025-10-15 [E]
```

### 3. Export Public Key
```bash
# Export public key (replace YOUR_KEY_ID with actual key ID)
gpg --armor --export YOUR_KEY_ID

# Copy the entire output from -----BEGIN PGP PUBLIC KEY BLOCK----- 
# to -----END PGP PUBLIC KEY BLOCK-----
```

### 4. Add to GitHub
1. Go to GitHub.com → Settings → SSH and GPG keys
2. Click "New GPG key"
3. Paste the exported public key
4. Save

### 5. Configure Git
```bash
# Configure Git to use GPG key for signing
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Configure GPG program (if needed)
git config --global gpg.program gpg
```

### 6. Enable Vigilant Mode
1. Go to GitHub.com → Settings → SSH and GPG keys
2. Under "Vigilant mode" section
3. Check "Flag unsigned commits as unverified"
4. Save changes

### 7. Test GPG Signing
```bash
# Test commit signing
echo "test" > test_gpg.txt
git add test_gpg.txt
git commit -S -m "test: GPG signing verification"

# Verify signature
git log --show-signature -1
```

### 8. Verify on GitHub
- Push a signed commit
- Check that it shows "Verified" badge on GitHub
- All future commits should be automatically signed

## Troubleshooting

### GPG Agent Issues
```bash
# Restart GPG agent
gpg-connect-agent reloadagent /bye

# Kill and restart
pkill gpg-agent
```

### Pinentry Issues on macOS
```bash
# Install pinentry-mac
brew install pinentry-mac

# Configure GPG agent
echo "pinentry-program /opt/homebrew/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf

# Restart GPG agent
gpg-connect-agent reloadagent /bye
```

### Permission Issues
```bash
# Fix GPG directory permissions
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

## IMPORTANT NOTES

- **ALL future commits MUST be signed** for verification
- Use `git commit -S` to explicitly sign commits
- Set up automatic signing with `git config --global commit.gpgsign true`
- Verify commits show "Verified" badge on GitHub before merging PRs
- If commits show "Unverified", they must be re-signed before merging

## Current Status

- ❌ GPG key generation pending (requires interactive terminal)
- ❌ GitHub GPG key addition pending
- ❌ Git configuration pending
- ❌ Vigilant mode enablement pending

**Action Required**: Complete GPG setup before next commit to ensure all future commits are verified.