//! rawsocket is a library for capturing raw traffic from interface on Linux.
//! The library could be ported to support other platforms, but it's main advantage is
//! not being dependenant on libpcap and async support.
//! It also provides predicate based BPF filter building (based on bs repository)

use std::os::unix::prelude::{AsRawFd, RawFd};

pub use bs_filter as filter;
use bs_filter::SocketFilterProgram;
use bytes::BytesMut;
use libc::sock_fprog;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

const PACKET_IGNORE_OUTGOING: libc::c_int = 23;

/// Helper macro to execute a system call that returns an `io::Result`.
/// from socket2
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

fn interface_index_to_sock_addr(index: i32) -> SockAddr {
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    unsafe {
        let sock_addr = std::ptr::addr_of_mut!(addr_storage) as *mut libc::sockaddr_ll;
        (*sock_addr).sll_family = libc::AF_PACKET as u16;
        (*sock_addr).sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        (*sock_addr).sll_ifindex = index;
    }

    unsafe { SockAddr::new(addr_storage, len) }
}

pub struct RawSocket {
    inner: Socket,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl RawSocket {
    fn next(&self, buffer: &mut BytesMut) -> Result<(), std::io::Error> {
        buffer.clear();

        let len = self
            .inner
            .recv_with_flags(buffer.spare_capacity_mut(), libc::MSG_TRUNC)?;

        if len > buffer.capacity() {
            // This should never really happen.
            Err(std::io::Error::other(format!(
                "Buffer too small: required {len} bytes, buffer size is {}",
                buffer.capacity()
            )))
        } else {
            unsafe {
                buffer.set_len(len);
            }

            Ok(())
        }
    }
}

pub struct RawCapture {
    inner: AsyncFd<RawSocket>,
    buffer: BytesMut,
}

impl RawCapture {
    /// Length of the buffer we use to receive packets.
    ///
    /// Should be enough to handle any Ethernet frame.
    const BUFFER_SIZE: usize = 655350;

    pub fn from_socket(socket: Socket) -> Result<Self, std::io::Error> {
        let inner = AsyncFd::new(RawSocket { inner: socket })?;

        Ok(Self {
            inner,
            buffer: BytesMut::with_capacity(Self::BUFFER_SIZE),
        })
    }

    pub fn from_interface_index(interface: i32) -> Result<Self, std::io::Error> {
        let socket = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(libc::ETH_P_ALL)),
        )?;
        let sock_addr = interface_index_to_sock_addr(interface);
        socket.bind(&sock_addr)?;
        socket.set_nonblocking(true)?;

        Self::from_socket(socket)
    }

    pub fn from_interface_name(interface: &str) -> Result<Self, std::io::Error> {
        let index = nix::net::if_::if_nametoindex(interface)?;

        Self::from_interface_index(index as i32)
    }

    /// Reads the next packet from the socket.
    ///
    /// Returns a reference to the internal buffer containing the packet.
    pub async fn next(&mut self) -> Result<&[u8], std::io::Error> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().next(&mut self.buffer)) {
                Ok(Ok(())) => return Ok(&self.buffer),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    pub fn set_filter(&self, filter: SocketFilterProgram) -> Result<(), std::io::Error> {
        let filter: sock_fprog = filter.into();
        syscall!(setsockopt(
            self.inner.get_ref().inner.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            std::ptr::addr_of!(filter).cast(),
            std::mem::size_of::<sock_fprog>() as libc::socklen_t
        ))
        .map(|_| ())
    }

    /// Sets the socket to ignore outgoing packets, that can cause issues when
    /// capturing loopback
    pub fn ignore_outgoing(&self) -> Result<(), std::io::Error> {
        let value: libc::c_int = 1;
        syscall!(setsockopt(
            self.inner.get_ref().inner.as_raw_fd(),
            libc::SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t
        ))
        .map(|_| ())
    }
}
