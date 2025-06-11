//! Classic BPF implementation
//!
//! Provides basic BPF building blocks used by [`bs-filter`] when used with the [`Classic`] backend.
//!
//! [`bs-filter`]: ../bs-filter/index.html
//! [`Classic`]: ../bs-filter/backend/struct.Classic.html

use crate::consts::*;
use std::hash::Hash;

/// `sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// `sock_filter` alias
pub type Instruction = SocketFilter;

impl SocketFilter {
    /// Creates a new `SocketFilter` with the given parameters
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Helper function, creates a new `SocketFilter` with given `code`
    /// other parameters (`jt`, `jf`, `k`) are set to 0
    pub const fn from_code(code: u16) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k: 0,
        }
    }
}

/// `sock_fprog`
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SocketFilterProgram {
    len: u16,
    filter: Box<[SocketFilter]>,
}

// https://github.com/rust-lang/rust-clippy/issues/7444
#[allow(clippy::from_over_into)]
impl Into<libc::sock_fprog> for SocketFilterProgram {
    fn into(self) -> libc::sock_fprog {
        libc::sock_fprog {
            len: self.len,
            filter: Box::into_raw(self.filter).cast(),
        }
    }
}

impl SocketFilterProgram {
    /// Creates a new `SocketFilterProgram` from the given `SocketFilter` vector
    pub fn from_vector(v: Vec<SocketFilter>) -> Self {
        let len = v.len() as u16;
        let filter = v.into_boxed_slice();
        Self { len, filter }
    }

    pub fn to_dump(&self) -> String {
        let mut output = format!("len: {}\n", self.len);
        for instruction in self.filter.iter() {
            output.push_str(&format!(
                "{} {} {} {},",
                instruction.code, instruction.jt, instruction.jf, instruction.k
            ));
        }
        output
    }
}

/// Different kinds of comparisons to perform upon `BPF_JMP` instructions
#[repr(u8)]
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    /// always true
    Always = 0x00,
    /// true if operands equal
    Equal = 0x10,
    /// true if the first operand is greater then the second
    GreaterThan = 0x20,
    /// true if the first operand is greater or equal to the second
    GreaterEqual = 0x30,
    /// true if the first operand bitmasked with second operand is greater then 0
    AndMask = 0x40,
    #[doc(hidden)]
    Unknown,
}

// TODO - use FromPrimitive instead
impl From<u8> for Comparison {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Always,
            0x10 => Self::Equal,
            0x20 => Self::GreaterThan,
            0x30 => Self::GreaterEqual,
            0x40 => Self::AndMask,
            _ => Self::Unknown,
        }
    }
}

const DROP: Instruction = Instruction::new((BPF_RET | BPF_K) as _, 0, 0, 0);
const RETURN_A: Instruction = Instruction::new((BPF_RET | BPF_A) as _, 0, 0, 0);
const LOAD_LENGTH: Instruction = Instruction::new((BPF_LD | BPF_LEN | BPF_W) as _, 0, 0, 0);

/// Generates a sequence of instructions that passes the entire packet.
pub fn teotology() -> Vec<Instruction> {
    vec![LOAD_LENGTH, RETURN_A]
}

/// Generates a sequence of instructions that drops the packet.
pub fn contradiction() -> Vec<Instruction> {
    vec![DROP]
}

/// Generates a sequence of instructions that implements a conditional jump.
pub fn jump(comparison: Comparison, operand: u32, jt: usize, jf: usize) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_JMP as u8 | comparison as u8 | BPF_K as u8) as _,
        jt as _,
        jf as _,
        operand,
    )]
}

/// Generates a sequence of instructions that loads one octet from a given offset in the packet.
pub fn load_u8_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        0,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads two octets from a given offset in the packet.
pub fn load_u16_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        0,
        0,
        offset,
    )]
}

/// Store register A in M[offset]
pub fn store_a_in_m_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new((BPF_ST) as _, 0, 0, offset)]
}

/// Generates a sequence of instructions that loads two octets from a given offset in the packet.
pub fn load_u8_into_x_from_packet_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_LDX | BPF_B | BPF_MSH) as _,
        0,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads 2 octets from X+offset in the packet.
pub fn load_u16_at_x_offset(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_LD | BPF_IND | BPF_H) as _,
        0,
        0,
        offset,
    )]
}

pub fn load_u16_from_m_offset(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new((BPF_LD | BPF_MEM) as _, 0, 0, offset)]
}
