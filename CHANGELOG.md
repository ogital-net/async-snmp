# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/async-snmp/async-snmp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/async-snmp/async-snmp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/async-snmp/async-snmp/releases/tag/v0.1.1
