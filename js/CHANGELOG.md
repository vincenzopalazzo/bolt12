# Changelog

All notable changes to `bolt12-utils` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-06-26

### Fixed

- Payer proof reader: exclude the payer-proof data range (`1001..=999_999_999`)
  from invoice merkle reconstruction. An unknown TLV in that range was being
  mis-counted as an invoice leaf, which wrongly rejected the proof on the
  `proof_leaf_hashes` count. A record is now treated as an invoice field only
  when its type is `< 240` (normal) or `>= 1_000_000_000` (experimental),
  mirroring the rust-lightning reference (`tlv_stream_iter`).
- Payer proof reader: reject unknown **even** TLVs in the payer-proof data range
  per the BOLT "it's ok to be odd" rule; unknown **odd** types remain ignorable
  and stay committed by `proof_signature`.

## [0.1.1]

- Initial published release: BOLT 12 offer / invoice / payer-proof decoding,
  validation, signing, and verification utilities.
