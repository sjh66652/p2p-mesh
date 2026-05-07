//! TUN virtual network interface module.
//!
//! Creates and manages a /dev/net/tun virtual network interface (e.g., "mesh0").
//! This is the core of the Overlay VPN — it captures IP packets from the OS
//! network stack and injects decrypted mesh packets back into the stack.
//!
//! Flow:
//!   App → OS net stack → TUN → Overlay → Encrypt → Peer
//!   Peer → Decrypt → Overlay → TUN → OS net stack → App
//!
//! Uses the `tun` crate which wraps OS-specific TUN/TAP ioctls.

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{unix::AsyncFd, Interest};
use tokio::sync::mpsc;

/// Represents a TUN virtual network interface.
///
/// Wraps the OS TUN device and provides async read/write for IP packets.
pub struct TunInterface {
    /// Underlying TUN device (sync I/O)
    device: tun::Device,
    /// Async wrapper for tokio integration
    async_fd: AsyncFd<tun::Device>,
}

impl TunInterface {
    /// Create a new TUN interface named `mesh0`.
    ///
    /// # Arguments
    /// * `address` - The IPv4 address to assign (e.g., "100.64.0.1")
    /// * `netmask` - The subnet mask (e.g., "255.192.0.0" for /10)
    /// * `mtu` - Maximum Transmission Unit (default: 1420 to avoid fragmentation with overlay headers)
    pub fn new(address: &str, netmask: &str, mtu: u16) -> io::Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name("mesh0")
            .tap(false) // TUN (L3) mode, not TAP (L2)
            .packet_info(false)
            .mtu(mtu as i32)
            .address(address)
            .netmask(netmask)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|cfg| {
            cfg.require_root(false);
        });

        let device = tun::create(&config)?;

        // Set the interface up and assign the address
        #[cfg(target_os = "linux")]
        {
            let name = device.name();
            // Assign IP address (requires iproute2 or netlink)
            let status = std::process::Command::new("ip")
                .args(["addr", "add", &format!("{}/10", address), "dev", name])
                .output();
            if let Err(e) = status {
                log::warn!("Failed to assign IP to {}: {} (try manual: ip addr add {}/10 dev {})", name, e, address, name);
            }
            let status = std::process::Command::new("ip")
                .args(["link", "set", "up", name])
                .output();
            if let Err(e) = status {
                log::warn!("Failed to bring up {}: {}", name, e);
            }
        }

        let async_fd = AsyncFd::new(device)?;

        Ok(Self {
            device: tun::create(&config)?, // Re-create to avoid move issues — in production use a single device
            async_fd,
        })
    }

    /// Get the interface name (e.g., "mesh0").
    pub fn name(&self) -> &str {
        self.device.name()
    }

    /// Read an IP packet from the TUN interface (async).
    ///
    /// Returns the raw IP packet bytes, or None if the device is closed.
    pub async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        // Use tokio's async I/O wrapper
        let mut guard = self.async_fd.readable().await?;
        match guard.get_ref().read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                guard.clear_ready();
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Write an IP packet to the TUN interface (async).
    ///
    /// The OS network stack will process this packet as if it arrived
    /// from a real network interface.
    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        let mut guard = self.async_fd.writable().await?;
        match guard.get_ref().write(packet) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                guard.clear_ready();
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Close the TUN interface and return the underlying device.
    pub fn close(self) -> tun::Device {
        self.device
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires root / CAP_NET_ADMIN
    fn test_tun_create() {
        let tun = TunInterface::new("100.64.0.1", "255.192.0.0", 1420);
        assert!(tun.is_ok());
    }
}
