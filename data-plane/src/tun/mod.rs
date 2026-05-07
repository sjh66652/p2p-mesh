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

use tokio::io::unix::AsyncFd;

/// Platform-specific TUN device type.
/// On Linux, this is the posix Device implementation.
#[cfg(target_os = "linux")]
use tun::platform::posix::Device as TunDevice;
#[cfg(not(target_os = "linux"))]
use tun::platform::Device as TunDevice;

/// Represents a TUN virtual network interface.
///
/// Wraps the OS TUN device and provides async read/write for IP packets.
pub struct TunInterface {
    /// TUN device name (e.g., "mesh0")
    name: String,
    /// Async wrapper for tokio integration
    async_fd: AsyncFd<TunDevice>,
}

impl TunInterface {
    /// Create a new TUN interface named `mesh0`.
    ///
    /// # Arguments
    /// * `address` - The IPv4 address to assign (e.g., "100.64.0.1")
    /// * `netmask` - The subnet mask (e.g., "255.192.0.0" for /10)
    /// * `mtu` - Maximum Transmission Unit (default: 1420 to avoid fragmentation with overlay headers)
    pub fn new(address: &str, netmask: &str, mtu: u16) -> io::Result<Self> {
        // Try device names "mesh0" through "mesh9", falling back if the name is
        // in use. Creates TUN configuration on-the-fly for each attempt.
        const MAX_ATTEMPTS: u8 = 10;

        let device = (0..MAX_ATTEMPTS)
            .map(|i| {
                let dev_name = if i == 0 {
                    "mesh0".to_string()
                } else {
                    format!("mesh{}", i)
                };
                (dev_name, i)
            })
            .find_map(|(dev_name, _i)| {
                let mut config = tun::Configuration::default();
                config
                    .name(&dev_name)
                    .mtu(mtu as i32)
                    .address(address)
                    .netmask(netmask)
                    .up();

                match tun::create(&config) {
                    Ok(dev) => {
                        log::info!("TUN device created: {}", dev_name);
                        Some(dev)
                    }
                    Err(e) => {
                        log::warn!(
                            "TUN device name '{}' failed: {} — trying next",
                            dev_name,
                            e
                        );
                        None
                    }
                }
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "could not create any TUN device after {} attempts",
                        MAX_ATTEMPTS,
                    ),
                )
            })?;

        let name = device.name()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to get TUN device name: {}", e)))?;

        // Set the interface up and assign the address
        #[cfg(target_os = "linux")]
        {
            // Assign IP address (requires iproute2 or netlink)
            let status = std::process::Command::new("ip")
                .args(["addr", "add", &format!("{}/10", address), "dev", &name])
                .output();
            if let Err(e) = status {
                log::warn!("Failed to assign IP to {}: {} (try manual: ip addr add {}/10 dev {})", name, e, address, name);
            }
            let status = std::process::Command::new("ip")
                .args(["link", "set", "up", &name])
                .output();
            if let Err(e) = status {
                log::warn!("Failed to bring up {}: {}", name, e);
            }
        }

        // Move device into AsyncFd — this consumes device, so save name first
        let async_fd = AsyncFd::new(device)?;

        Ok(Self {
            name,
            async_fd,
        })
    }

    /// Get the interface name (e.g., "mesh0").
    pub fn name(&self) -> &str {
        &self.name
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
