//! Formatting utilities for SNMP values.
//!
//! This module provides formatting functions for converting raw SNMP data
//! into human-readable strings.
//!
//! ## Display Hints
//!
//! The [`display_hint`] module implements RFC 2579 DISPLAY-HINT formatting
//! for OCTET STRING values. This is commonly used to format MAC addresses,
//! IP addresses, and other structured binary data.
//!
//! ```
//! use async_snmp::format::display_hint;
//!
//! // Format a MAC address
//! let mac = display_hint::apply("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
//! assert_eq!(mac, "00:1a:2b:3c:4d:5e");
//!
//! // Format an IPv4 address
//! let ip = display_hint::apply("1d.1d.1d.1d", &[192, 168, 1, 1]);
//! assert_eq!(ip, "192.168.1.1");
//! ```

pub mod display_hint;
