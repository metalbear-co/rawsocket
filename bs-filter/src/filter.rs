use libc::IPPROTO_TCP;

use crate::{cbpf::{self, Instruction, Comparison, jump, load_u8_at, load_u16_at, store_a_in_m_at, load_u8_into_x_from_packet_at, load_u16_at_x_offset, load_u16_from_m_offset, teotology, contradiction}, program::Program, Result, consts::{OFFSET_ETHER_TYPE, ETH_P_IPV6, SIZE_ETHER_HEADER, OFFSET_IP6_NEXT_HEADER, SIZE_IPV6_HEADER, OFFSET_TCP_DST_PORT, OFFSET_TCP_SRC_PORT, ETH_P_IP, OFFSET_IP4_PROTO, OFFSET_IP4_FRAGMENT}, SocketFilterProgram};
use std::iter::FromIterator;

/// A concrete appicable socket filter
#[derive(Debug)]
pub struct Filter {
    inner: Vec<cbpf::Instruction>,
}

impl Filter {
    /// Transform the `Filter` into a `SocketOption` settable on a `Socket`
    pub fn build(self) -> Result<cbpf::SocketFilterProgram> {
        let prog: Program = self.into();
        prog.build()
    }
}

impl FromIterator<cbpf::Instruction> for Filter {
    fn from_iter<I: IntoIterator<Item = cbpf::Instruction>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl IntoIterator for Filter {
    type Item = cbpf::Instruction;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

#[allow(clippy::from_over_into)]
impl Into<Program> for Filter {
    fn into(self) -> Program {
        Program::from_iter(self.into_iter())
    }
}

pub fn build_tcp_port_filter(ports: &[u16]) -> SocketFilterProgram {
    let mut instructions = vec![];
    let ipv4_check = 6;
    let src_port_m_offset = 0;
    // Check EtherType is IPv6
    instructions.extend(load_u16_at(OFFSET_ETHER_TYPE));
    // If it's not IPv6, jump to check IPv4
    instructions.extend(jump(Comparison::Equal, ETH_P_IPV6, 0, ipv4_check));
    // Load protocol from IPv6
    instructions.extend(load_u8_at(SIZE_ETHER_HEADER + OFFSET_IP6_NEXT_HEADER));
    // Check if Protocol is TCP, if not jump to drop
    instructions.extend(jump(Comparison::Equal, IPPROTO_TCP as _, 0, 13 + ports.len() + 1 + ports.len() + 2));
    // Load src port into A then store it in M[0]
    instructions.extend(load_u16_at(SIZE_ETHER_HEADER + SIZE_IPV6_HEADER + OFFSET_TCP_SRC_PORT));
    instructions.extend(store_a_in_m_at(src_port_m_offset));
    // Load dst port into A
    instructions.extend(load_u16_at(SIZE_ETHER_HEADER + SIZE_IPV6_HEADER + OFFSET_TCP_DST_PORT));
    // Jump to port comparison check (having src port in M[0] and dst port in A)
    instructions.extend(jump(Comparison::Always, 0, 0, 10));
    // If we got here, it's from ether type check, so A has the ether type loaded
    // Check if it's IPv4, if not, drop
    instructions.extend(jump(Comparison::Equal, ETH_P_IP, 0, 8 + ports.len() + 1 + ports.len() + 2));
    // Check for TCP
    instructions.extend(load_u8_at(SIZE_ETHER_HEADER + OFFSET_IP4_PROTO));
    instructions.extend(jump(Comparison::Equal, IPPROTO_TCP as _, 0, 6 + ports.len() + 1 + ports.len() + 2));
    // Check for fragmentation
    instructions.extend(load_u16_at(SIZE_ETHER_HEADER + OFFSET_IP4_FRAGMENT));
    // Not sure how this check works but this is how it is..
    instructions.extend(jump(Comparison::AndMask, 0x1fff, 4 + ports.len() + 1 + ports.len() + 2, 0));
    // Load offset for tcp header - X = offset of fragment header in the packet, from there it's
    // 14 bytes for src port and 16 bytes to dst port.
    instructions.extend(load_u8_into_x_from_packet_at(14));
    // Load src port into A then store it in M[0]
    instructions.extend(load_u16_at_x_offset(14));
    instructions.extend(store_a_in_m_at(src_port_m_offset));

    // Load dst port into A
    instructions.extend(load_u16_at_x_offset(16));
    
    // Check dst port first (arleady in A)
    for (i, port) in ports.iter().enumerate() {
        let accept = ports.len() + ports.len() - i + 1 - 1;
        let drop = ports.len() + ports.len() - i + 2;
        instructions.extend(jump(Comparison::Equal, *port as _, accept, drop));
    }

    // Load src port into A then do the same check
    instructions.extend(load_u16_from_m_offset(src_port_m_offset));

    // Check dst port first (arleady in A)
    for (i, port) in ports.iter().enumerate() {
        let accept = ports.len() - i - 1;
        let drop = ports.len() - i + 1;
        instructions.extend(jump(Comparison::Equal, *port as _, accept, drop));
    }
    
    instructions.extend(teotology());
    instructions.extend(contradiction());

    SocketFilterProgram::from_vector(instructions)

}
