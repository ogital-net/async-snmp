# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-01

### Changed

- **Breaking:** Unified `UdpTransport` and `SharedUdpTransport` into a single
  `UdpTransport` with `UdpHandle` pattern. The new design uses a background
  receiver task with sharded pending maps for correct concurrent request handling.
- **Breaking:** `Transport` trait changes:
  - Renamed `target()` to `peer_addr()` for consistency with std
  - Added `register_request(request_id, timeout)` for pre-send slot registration
  - `recv()` no longer takes a timeout parameter (uses registered deadline)
- Request IDs are now allocated from a global counter for process-wide uniqueness,
  preventing collisions when multiple transports exist

### Added

- Configurable retry strategies with backoff support:
  - `RetryStrategy::Fixed` - constant delay between retries (default)
  - `RetryStrategy::Exponential` - exponential backoff with configurable base and max
  - `RetryStrategy::None` - disable retries entirely
- `UdpTransport::shutdown()` for graceful termination of background receiver
- `ClientBuilder::build_with(&UdpTransport)` for convenient shared transport usage

### Fixed

- Concurrent UDP requests no longer cause false timeouts due to race conditions
  in response routing
- Memory leak from orphaned pending responses now prevented via periodic cleanup

### Removed

- `SharedUdpTransport` and `SharedUdpHandle` (functionality merged into `UdpTransport`)

## [0.1.2] - 2026-01-01

### Fixed

- `MasterKeys` can now be used without also specifying passwords. Previously,
  using `Auth::usm().with_master_keys()` would fail validation requiring
  `auth_password` even though keys were already derived.

### Documentation

- Significantly expanded rustdoc coverage across all modules with examples
- Added crate-level documentation sections for error handling, tracing,
  agent compatibility, and high-throughput SNMPv3 polling
- Improved examples to use test container credentials and RFC 5737 TEST-NET
  addresses

## [0.1.1] - 2025-12-31

### Added

- SNMPv1, v2c, and v3 client support
- GET, GETNEXT, GETBULK, SET operations
- WALK and BULKWALK streaming iterators
- SNMPv3 USM security:
  - Authentication: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
  - Privacy: DES, AES-128, AES-192, AES-256
- Transport implementations:
  - `UdpTransport` for single-target clients
  - `TcpTransport` for stream-based connections
  - `SharedUdpTransport` for high-throughput polling (thousands of targets)
- `NotificationReceiver` for trap/inform handling
- `Agent` with `MibHandler` trait for building SNMP agents
- VACM (View-Based Access Control Model) support
- Two-phase SET commit per RFC 3416
- `oid!` macro for compile-time OID parsing
- Zero-copy BER encoding/decoding
- CLI utilities: `asnmp-get`, `asnmp-walk`, `asnmp-set`

[Unreleased]: https://github.com/async-snmp/async-snmp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/async-snmp/async-snmp/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/async-snmp/async-snmp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/async-snmp/async-snmp/releases/tag/v0.1.1
