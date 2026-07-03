# Key catalog and hierarchy

The at-rest key management that `lithium_core` provides: where the
keys come from, where they live, how long they last, and what they
protect. All labels are pinned by tests
(`registry_values_are_pinned`).

`lithium_core`'s `KeyManager` does not spawn a background rotator or own any
thread of its own. It provides the key manager and the crash-safe rotation
primitive; the caller decides when to invoke rotation. (The unrelated
`utils::store` helper does run its own background cleanup thread.)

## The `.keyf` wrapping

```text id="9x3p2k"
master key (from MkProvider)
  -> KEK = HKDF(MK, file_salt, info="kek/v1")
  -> DEK = random 32-byte key per .keyf file
  -> payload = private key / secret stored in that file
```

Double wrapping: the payload is sealed under a per-file DEK, and the DEK is
sealed under the KEK derived from the master key. The master key is not used
directly as the payload encryption key.

## At-rest keys

| Key             | Type        | Derivation / source                  | Storage                               | Lifetime / rotation                                                                                  | Protects                           |
| --------------- | ----------- | ------------------------------------ | ------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Master Key (MK) | 32 B random | supplied/sealed by an `MkProvider`   | provider-specific                     | rotated when the caller invokes `KeyManager::maybe_rotate_mk()` after the configured interval passes | every `.keyf` file through the KEK |
| KEK             | 32 B        | `HKDF(MK, file_salt, info="kek/v1")` | not stored; derived on use            | changes when the MK changes                                                                          | wrapping the DEK in a `.keyf`      |
| `.keyf` DEK     | 32 B random | random per file                      | in the `.keyf`, wrapped under the KEK | rewrapped on MK rotation; value unchanged                                                            | the key/secret payload in the file |

The caller can also derive application-specific 32-byte secrets straight from
the MK with its own label (`derive_secret32(label)`). Those outputs and their
labels are the caller's responsibility.

## MkProvider

The master key source is a trait, `MkProvider`, so the storage and protection
of the MK are the caller's choice:

* **`InsecurePlaintextMkProvider`** is the only built-in provider. The MK lives
  in a cleartext file with no protection beyond its permissions, so it is gated
  behind the non-default `insecure-plaintext-mk` feature and meant for dev,
  tests and examples only.
* A production caller implements its own `MkProvider` for password-backed,
  hardware-backed, TPM-backed, or other sealing and passes it to
  `KeyManager::start`. See `examples/password_mkprovider.rs` and
  [`mkprovider-examples.md`](mkprovider-examples.md).
* The library only accesses the MK through `load_mk` and `store_mk`.

Example caller-side wrapping strategy:

```text id="q1d8kz"
AES-256-GCM-SIV(
    MK,
    key = Argon2id(passphrase, salt),
    aad = "lithium/mkfile/v1"
) -> keystore/user/mk.enc
```

That wrapping is intentionally outside `lithium_core`; the core library only
requires an `MkProvider`.

## Rotation

`KeyManager` supports crash-safe MK rotation, but it does not run a background
task on its own. The caller is expected to call `maybe_rotate_mk()` periodically
from its own daemon, service loop, timer, or application lifecycle.

By default, the rotation interval is 1 hour. The caller may override it with
`set_rotate_interval(...)`.

Rotation rewraps each `.keyf` DEK under a KEK derived from the new MK. The DEK
values themselves do not change, so the encrypted payloads are not decrypted and
rewritten under new DEKs; only the DEK wrapping changes.

The rotation protocol is crash-safe:

1. Create the rotation staging directory.
2. Generate a new MK.
3. Store enough rotation state to recover after a crash.
4. Rewrap every `.keyf` DEK into staged files.
5. Write the ready marker.
6. Apply staged files to their live paths.
7. Store the new MK through the `MkProvider`.
8. Remove the rotation staging directory.

On startup, `KeyManager` checks for an unfinished rotation and either completes
or cleans it up before loading the key material.

## Secret types

`SecByte32`, `SecretBytes`, `SecretString`, and `MasterKey32` zeroize on drop,
so key material does not intentionally linger in process memory after use.

This is process-local hygiene, not a defense against a local attacker that can
read the process memory while the process is running.

## At-rest leak analysis

What the library's at-rest protection holds against:

| Compromise                                                                          | What's exposed                                             | What's still protected                           |
|-------------------------------------------------------------------------------------|------------------------------------------------------------|--------------------------------------------------|
| Disk alone, without the MK or whatever the `MkProvider` uses to guard it            | public keys and encrypted `.keyf` blobs                    | private keys and sealed secrets                  |
| Disk plus `InsecurePlaintextMkProvider` MK file                                     | all `.keyf` payloads can be decrypted                      | nothing protected by that MK                     |
| Disk plus a properly sealed MK provider, but without the provider's unlock material | public keys and encrypted `.keyf` blobs                    | private keys and sealed secrets                  |
| One old MK after a successful rotation                                              | `.keyf` files that were copied before the rotation         | current `.keyf` files rewrapped under the new MK |
| Breaking ML-KEM **or** X25519 on its own                                            | no message content from the hybrid encryption construction | message content, as both branches are required   |
