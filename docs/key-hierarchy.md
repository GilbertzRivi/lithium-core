# Key catalog and hierarchy

The at-rest key management that `lithium_core` provides: where the 
keys come from, where they live, how long they last, and what they 
protect. All labels are pinned by tests 
(`registry_values_are_pinned`).

## The `.keyf` wrapping

```
master key (from MkProvider) -> KEK = HKDF(MK, file_salt, "kek/v1") -> DEK (random per file) -> payload (private keys / secrets)
```

Double wrapping: the payload is sealed under a per-file DEK, and 
the DEK is sealed under the KEK derived from the master key. The 
master key never touches the payload directly.

## At-rest keys

| Key | Type | Derivation / source | Storage | Lifetime / rotation | Protects |
|-----|------|--------------------|---------|--------------------|----------|
| Master Key (MK) | 32 B random | supplied/sealed by an `MkProvider` (see below) | provider-specific (see below) | rotated every 1 h (`MkRotator`, 30 s tick) | every `.keyf` file (through the KEK) |
| KEK | 32 B | `HKDF(MK, file_salt, info="kek/v1")` | not stored (derived on use) | with the MK | wrapping the DEK in a `.keyf` |
| `.keyf` DEK | 32 B random | random per file | in the `.keyf`, wrapped under the KEK | rewrapped on MK rotation (value unchanged) | the key/secret payload in the file |

The caller can also derive application-specific 32-byte secrets 
straight from the MK with its own label (`derive_secret32(label)`); 
those outputs and their labels are the caller's responsibility.

## MkProvider

The master key source is a trait, `MkProvider`, so the storage of 
the MK is the caller's choice:

- **`PlainFileMkProvider`** is the one built-in provider. The MK 
  lives in a file. This is the plain provider: it offers no 
  protection beyond the file's own permissions, so the caller is 
  expected to wrap it, for example 
  `AES-256-GCM-SIV(MK, Argon2id(passphrase, salt), aad="lithium/mkfile/v1")` 
  stored at `keystore/user/mk.enc`.
- A caller that needs hardware-backed protection implements its 
  own `MkProvider` (for example sealing the MK into a secure 
  element or TPM) and passes it to `KeyManager::start`. The library 
  never sees the MK except through `load_mk`/`store_mk`.

## Rotation

`MkRotator` wakes every 30 s and rotates the MK once the interval 
passes (1 h by default). Rotation rewraps each `.keyf` DEK under 
the new MK; the DEK values themselves don't change, so the payload 
is untouched. The rewrap is crash-safe.

## Secret types

`SecByte32`, `SecretBytes`, `SecretString`, `MasterKey32` all zeroize 
on drop, so key material doesn't linger in process memory after 
use.

## At-rest leak analysis

What the library's at-rest protection holds against:

| Compromise | What's exposed | What's still protected |
|------------|----------------|------------------------|
| The disk alone, without the MK (or whatever the `MkProvider` guards it with) | nothing, `.keyf` files are encrypted | all key material |
| Breaking ML-KEM **or** X25519 on its own | nothing, the other half of the hybrid still holds | message content (both must break) |
