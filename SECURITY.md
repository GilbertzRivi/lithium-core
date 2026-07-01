# Security policy

> **Status: pre-audit.** The library has not gone through an independent
> cryptographic audit and has no production releases. You use it at your own
> risk - not to protect actually sensitive data before the audit.

## Reporting vulnerabilities

Send reports privately to **[oktawia.handerek@gmail.com](mailto:oktawia.handerek@gmail.com)**. Do not open a public
issue for vulnerabilities.

PGP for encrypted reports: `2C37 66D2 A252 A8AF 67DB  CC11 02BE F36D 035D 5C17`
(fetch from keys.openpgp.org). Encrypt any sensitive PoC to this key.

Please use coordinated disclosure: give time for a fix before disclosing details
publicly (default up to 90 days from confirmation). Report acknowledgement - as
soon as possible; this is a small project, there is no 24/7 on-call rotation.

## Before you report

`lithium_core` has conscious design trade-offs and a defined boundary: some
things are the caller's responsibility, not the library's. Before reporting,
check the library threat model in [`docs/threat-model.md`](docs/threat-model.md),
in particular:

* **Assumptions** - what the caller must provide (a CSPRNG, unique
  domain-separation labels, sound key storage). A failure caused by violating
  these is not a library vulnerability.
* **Out of scope** - the library's stated non-goals.

For the construction itself and the open questions an auditor should focus on,
see the audit guide in [`docs/index.md`](docs/index.md) and the combiner mapping
in [`docs/combiner.md`](docs/combiner.md).

## Scope

In scope: the cryptographic constructions (`crypto::kyberbox`, `crypto::sign`,
the KDF and AEAD wrappers), at-rest key management (`KeyManager`, keyfile
rotation, the `MkProvider` master-key sealing), the secret types, and the FFI
boundary to the vendored ML-KEM implementation. Out of scope: properties the
threat model consciously accepts as cost - no recovery for lost key material,
and anything the caller is responsible for under **Assumptions** above.

## Supported versions

Pre-audit project, no production releases. Only current `main` is supported.
