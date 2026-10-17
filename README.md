# crypto-suite

Kotlin Multiplatform crypto primitives and encoding helpers.

## KMP status

This module exposes common Base64 helpers plus common hash/digest contracts. AES, RSA, file/stream digests, HMAC, and GCM helpers currently have Android/JVM implementations only.

## Owns

- Raw AES, RSA, hash, digest, and Base64 helpers.
- Stateless crypto utility functions that do not depend on Android Keystore.
- Compatibility helpers that are generic enough for reuse.

## Boundaries

- Do not add Android Keystore behavior; that belongs in `core:security-kit`.
- Do not add app secrets, key aliases, certificates, or runtime security configuration.
- Do not add storage or database passphrase lifecycle logic.

## Usage

Use this module for raw crypto and encoding operations. Android-backed key storage should use `core:security-kit` or higher-level security modules.
