//! rawsocket is a library for capturing raw traffic from interface on Linux.
//! The library could be ported to support other platforms, but it's main advantage is
//! not being dependenant on libpcap and async support.
//! It also provides predicate based BPF filter building (based on bs repository)

use std::os::unix::prelude::{AsRawFd, RawFd};

pub use bs_filter as filter;
use bs_filter::SocketFilterProgram;
use libc::sock_fprog;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

const BUFFER_SIZE: usize = 1024 * 5;

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
        let mut sock_addr = std::ptr::addr_of_mut!(addr_storage) as *mut libc::sockaddr_ll;
        (*sock_addr).sll_family = libc::AF_PACKET as u16;
        (*sock_addr).sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        (*sock_addr).sll_ifindex = index;
    }

    unsafe { SockAddr::new(addr_storage, len) }
}

pub struct RawSocket {
    inner: Socket,
}

pub type Packet = Vec<u8>;

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl RawSocket {
    fn next(&self) -> Result<Packet, std::io::Error> {
        let mut buf = Vec::with_capacity(BUFFER_SIZE);
        let len = self
            .inner
            .recv_with_flags(buf.spare_capacity_mut(), libc::MSG_TRUNC)?;
        if len > BUFFER_SIZE {
            Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory))
        } else {
            unsafe {
                buf.set_len(len);
            }
            Ok(buf)
        }
    }
}

pub struct RawCapture {
    inner: AsyncFd<RawSocket>,
}

impl RawCapture {
    pub fn from_socket(socket: Socket) -> Result<Self, std::io::Error> {
        let inner = AsyncFd::new(RawSocket { inner: socket })?;
        Ok(Self { inner })
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

    pub async fn next(&self) -> Result<Packet, std::io::Error> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().next()) {
                Ok(result) => return result,
                Err(_would_block) => continue,
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
}
