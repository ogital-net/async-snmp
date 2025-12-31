//! Internal utilities.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Create and bind a UDP socket with proper IPv6 configuration.
///
/// For IPv6 sockets, sets `IPV6_V6ONLY = true` to ensure the socket only
/// accepts IPv6 connections and does not use IPv4-mapped addresses.
///
/// # Arguments
///
/// * `addr` - The socket address to bind to. The domain (IPv4/IPv6) is
///   inferred from the address type.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to the specified address.
pub(crate) async fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // For IPv6 sockets, set IPV6_V6ONLY to true.
    // This ensures the socket only handles IPv6 traffic and doesn't accept
    // IPv4-mapped IPv6 addresses, providing cleaner and more predictable behavior.
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    // Allow address reuse for quick restarts
    socket.set_reuse_address(true)?;

    // Set non-blocking before converting to tokio socket
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;

    UdpSocket::from_std(socket.into())
}

/// Create an ephemeral UDP socket for connecting to a target.
///
/// Binds to `0.0.0.0:0` (IPv4) or `[::]:0` (IPv6) depending on the target
/// address family. For IPv6, sets `IPV6_V6ONLY = true`.
///
/// # Arguments
///
/// * `target` - The target address. Used to determine whether to create
///   an IPv4 or IPv6 socket.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to an ephemeral port.
pub(crate) async fn bind_ephemeral_udp_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    bind_udp_socket(bind_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_udp_socket_ipv4() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp_socket(addr).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_ipv6() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let socket = bind_udp_socket(addr).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_ephemeral_udp_socket_ipv4_target() {
        let target: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let socket = bind_ephemeral_udp_socket(target).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_ephemeral_udp_socket_ipv6_target() {
        let target: SocketAddr = "[2001:db8::1]:161".parse().unwrap();
        let socket = bind_ephemeral_udp_socket(target).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }
}
