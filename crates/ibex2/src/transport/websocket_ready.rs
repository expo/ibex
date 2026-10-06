//! The portable WebSocket pump's two-socket readiness wait.
//!
//! `poll(2)` and `WSAPoll` both understand sockets. A connected loopback UDP
//! socket therefore gives the bounded Rust channels a portable wake handle
//! without adding an executor or a readiness dependency.

use std::io;
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub(super) struct Wake {
    socket: Arc<UdpSocket>,
}

impl Wake {
    pub(super) fn notify(&self) -> io::Result<()> {
        loop {
            match self.socket.send(&[1]) {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                // A full local datagram queue already makes the wake socket
                // readable, so it has fulfilled this notification.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) struct Waiter {
    socket: UdpSocket,
}

#[derive(Default)]
pub(super) struct Ready {
    pub(super) socket_readable: bool,
    pub(super) socket_writable: bool,
    pub(super) woken: bool,
}

pub(super) fn pair() -> io::Result<(Wake, Waiter)> {
    let receiver = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let sender = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    sender.connect(receiver.local_addr()?)?;
    receiver.connect(sender.local_addr()?)?;
    // Exercise the exact connected loopback path before the pump can park on
    // it. A local firewall/filter therefore refuses the connection here
    // instead of silently stranding a later command.
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
    loop {
        match sender.send(&[1]) {
            Ok(1) => break,
            Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let mut byte = [0];
    loop {
        match receiver.recv(&mut byte) {
            Ok(1) => break,
            Ok(_) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    receiver.set_read_timeout(None)?;
    sender.set_nonblocking(true)?;
    receiver.set_nonblocking(true)?;
    Ok((
        Wake {
            socket: Arc::new(sender),
        },
        Waiter { socket: receiver },
    ))
}

impl Waiter {
    pub(super) fn wait(
        &self,
        tcp: &TcpStream,
        read: bool,
        write: bool,
        timeout: Option<Duration>,
    ) -> io::Result<Ready> {
        let ready = platform::wait(tcp, &self.socket, read, write, timeout)?;
        if ready.woken {
            let mut bytes = [0; 64];
            loop {
                match self.socket.recv(&mut bytes) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(ready)
    }
}

fn timeout_millis(timeout: Option<Duration>) -> i32 {
    match timeout {
        None => -1,
        Some(duration) if duration.is_zero() => 0,
        Some(duration) => duration
            .as_millis()
            .saturating_add(u128::from(duration.subsec_nanos() % 1_000_000 != 0))
            .min(i32::MAX as u128) as i32,
    }
}

#[cfg(unix)]
mod platform {
    use super::{timeout_millis, Ready};
    use std::io;
    use std::net::{TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    pub(super) fn wait(
        tcp: &TcpStream,
        wake: &UdpSocket,
        read: bool,
        write: bool,
        timeout: Option<Duration>,
    ) -> io::Result<Ready> {
        let mut descriptors = [
            libc::pollfd {
                fd: tcp.as_raw_fd(),
                events: (if read { libc::POLLIN } else { 0 })
                    | (if write { libc::POLLOUT } else { 0 }),
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let started = Instant::now();
        loop {
            for descriptor in &mut descriptors {
                descriptor.revents = 0;
            }
            let active = if read || write {
                &mut descriptors[..]
            } else {
                // Terminal flags are reported even when `events` is zero.
                // Omit the TCP descriptor while receive demand is paused so
                // Close+FIN remains available for the next requested read.
                &mut descriptors[1..]
            };
            let remaining = timeout.map(|limit| limit.saturating_sub(started.elapsed()));
            // SAFETY: both entries contain live descriptors for the duration
            // of the call, and the selected slice length is exact.
            let result = unsafe {
                libc::poll(
                    active.as_mut_ptr(),
                    active.len() as libc::nfds_t,
                    timeout_millis(remaining),
                )
            };
            if result >= 0 {
                let terminal = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
                return Ok(Ready {
                    socket_readable: descriptors[0].revents & (libc::POLLIN | terminal) != 0,
                    socket_writable: descriptors[0].revents & libc::POLLOUT != 0,
                    woken: descriptors[1].revents & libc::POLLIN != 0,
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
            // `remaining` is derived from the original absolute deadline, so
            // repeated signals cannot restart and extend a bounded wait.
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{timeout_millis, Ready};
    use std::io;
    use std::net::{TcpStream, UdpSocket};
    use std::os::windows::io::AsRawSocket;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, SOCKET_ERROR,
        WSAPOLLFD,
    };

    pub(super) fn wait(
        tcp: &TcpStream,
        wake: &UdpSocket,
        read: bool,
        write: bool,
        timeout: Option<Duration>,
    ) -> io::Result<Ready> {
        let mut descriptors = [
            WSAPOLLFD {
                fd: tcp.as_raw_socket() as _,
                events: (if read { POLLIN } else { 0 }) | (if write { POLLOUT } else { 0 }),
                revents: 0,
            },
            WSAPOLLFD {
                fd: wake.as_raw_socket() as _,
                events: POLLIN,
                revents: 0,
            },
        ];
        let started = Instant::now();
        loop {
            for descriptor in &mut descriptors {
                descriptor.revents = 0;
            }
            let active = if read || write {
                &mut descriptors[..]
            } else {
                // As with poll(2), terminal flags need no requested event.
                // Excluding the TCP socket preserves unread Close+FIN until
                // the next receive request on Windows as well.
                &mut descriptors[1..]
            };
            let remaining = timeout.map(|limit| limit.saturating_sub(started.elapsed()));
            // SAFETY: both entries contain live SOCKETs for the duration of
            // the call, and Winsock has already been initialized by `std::net`.
            let result = unsafe {
                WSAPoll(
                    active.as_mut_ptr(),
                    active.len() as u32,
                    timeout_millis(remaining),
                )
            };
            if result != SOCKET_ERROR {
                break;
            }
            // SAFETY: valid immediately after the failed Winsock call.
            let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        let terminal = POLLERR | POLLHUP | POLLNVAL;
        Ok(Ready {
            socket_readable: descriptors[0].revents & (POLLIN | terminal) != 0,
            socket_writable: descriptors[0].revents & POLLOUT != 0,
            woken: descriptors[1].revents & POLLIN != 0,
        })
    }
}
