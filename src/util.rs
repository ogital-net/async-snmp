//! Internal utilities.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Create and bind a dual-stack UDP socket.
///
/// Always binds to IPv6 with `IPV6_V6ONLY = false` to enable dual-stack mode,
/// allowing both IPv4 and IPv6 targets from a single socket. IPv4 addresses
/// are handled via IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
///
/// # Arguments
///
/// * `addr` - The socket address to bind to. For dual-stack, use `[::]:port`.
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

    // For IPv6 sockets, set IPV6_V6ONLY to false for dual-stack support.
    // This allows a single socket to handle both IPv4 and IPv6 traffic.
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }

    // Allow address reuse for quick restarts
    socket.set_reuse_address(true)?;

    // Set non-blocking before converting to tokio socket
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;

    UdpSocket::from_std(socket.into())
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
}
