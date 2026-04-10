# Security Tiers

ChaosKB encrypts all your data before it leaves your device. You choose how the encryption key is protected.

## Overview

| Tier | Setup | Recovery | Server can read your data? |
|------|-------|----------|---------------------------|
| **Standard** (default) | Nothing to do | SSH private key | No |
| **Enhanced** | Write down 24 words | Recovery key OR SSH private key | No |
| **Maximum** | Create a passphrase | Passphrase only | No |

All tiers encrypt your data with the same strong encryption (XChaCha20-Poly1305). The difference is who can recover your key.

## Standard (default)

Best for most users. Zero setup — just start using ChaosKB.

Your encryption key (master key) is generated on your device and wrapped with your SSH public key before being stored on the server. The server cannot unwrap it — only your SSH private key can decrypt the master key. This makes Standard tier genuinely end-to-end encrypted.

**Recovery:** Use your SSH private key on a new device. The wrapped master key is downloaded from the server and unwrapped locally.

## Enhanced

For users who want an additional recovery path beyond their SSH key.

During setup, you're shown 24 words (a recovery key). Write them down on paper and store them somewhere safe. This gives you a second way to recover your data if you lose your SSH key.

**What this adds:** A recovery key that works independently of your SSH key. If your SSH key is lost or compromised, the recovery key can still unlock your data.

**Recovery:** Enter your 24-word recovery key on a new device, OR use your SSH private key (same as Standard tier).

**Risk:** If you lose your recovery key AND your SSH private key AND all your devices, your data is gone forever. There is no reset, no support ticket, no backdoor. The app will periodically remind you to verify your recovery key is still safe.

## Maximum

For journalists, activists, or anyone facing targeted threats.

Your encryption key is derived from a passphrase you choose (minimum 5 words or 25 characters). The passphrase is never stored anywhere. After a period of inactivity, you must re-enter it.

**What this adds:** Even physical theft of your unlocked device doesn't give persistent access — the key is cleared after the inactivity timeout (configurable: 1 hour to 7 days).

**Recovery:** Enter your passphrase on a new device.

**Risk:** Forgotten passphrase = permanent data loss. No recovery path exists. The app shows an estimated crack time for your passphrase and rejects weak ones.

## Adding a new device

On your existing device, ask your agent to generate a link code:

> "I want to add a new device to ChaosKB"

This calls `device_link_start` and returns a short-lived link code. On the new device, confirm the link:

> "Link this device with code ABC123"

| Tier | How to add a device |
|------|-------------------|
| Standard | Generate a link code on existing device, confirm on new device |
| Enhanced | Generate a link code on existing device, confirm on new device |
| Maximum | Enter your passphrase on the new device |

## Changing tiers

You can change your security tier at any time in Settings.

**Upgrading to Enhanced:** Your existing master key is encoded as a 24-word recovery key. The SSH-wrapped backup on the server is retained as a second recovery path. Write down the recovery key.

**Upgrading to Maximum:** A 24-hour cooling-off period begins. Your data is re-encrypted with a key derived from your new passphrase. During this period, you can cancel and revert. After 24 hours, the upgrade is final.

**Downgrading:** Your master key is re-wrapped with your SSH public key and uploaded to the server (Standard) or encoded as a recovery key (Enhanced). Immediate, no waiting period.

## What to do if you lose access

| Situation | Standard | Enhanced | Maximum |
|-----------|----------|----------|---------|
| Lost one device | Use SSH private key on another device | Use another device | Enter passphrase on another device |
| Lost all devices | Use SSH private key on a new device | Enter 24-word recovery key OR use SSH private key | Enter passphrase |
| Lost SSH key | Data is permanently lost | Enter 24-word recovery key | N/A (passphrase-based) |
| Forgot passphrase | N/A | N/A | Data is permanently lost |
| Lost recovery key + SSH key | N/A | Data is permanently lost | N/A |

## Recommendation

- **Most users:** Standard. It's genuinely end-to-end encrypted (the server cannot read your data) and recoverable with your SSH key.
- **Privacy-conscious:** Enhanced. Write down the recovery key and store it separately from your devices (e.g., a safe, a bank deposit box).
- **High-risk situations:** Maximum. Use a strong, memorable passphrase (5+ random words). Practice entering it regularly.
