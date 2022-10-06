use crate::cbpf;
use crate::consts::BPF_JEQ;
use crate::predicate::{Expr::*, Predicate};
use crate::Condition;

/// true iff the octet at offset `offset` equals `value`
pub fn offset_equals_u8(offset: u32, value: u8) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u8_at(offset),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value as u32,
    )))
}

/// true iff the octet at offset `offset + shift` equals `value`
// TODO - should `shift` be i32?
pub fn shift_offset_equals_u8(offset: u32, value: u8, shift: u32) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u8_at(offset + shift),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value as u32,
    )))
}

/// true iff the u16 at offset `offset` equals `value`
pub fn offset_equals_u16(offset: u32, value: u16) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u16_at(offset),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value as u32,
    )))
}

/// true iff the u16 at offset `offset + shift` equals `value`
pub fn shift_offset_equals_u16(offset: u32, value: u16, shift: u32) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u16_at(offset + shift),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value as u32,
    )))
}

/// true iff the u32 at offset `offset` equals `value`
pub fn offset_equals_u32(offset: u32, value: u32) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u32_at(offset),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value,
    )))
}

/// true iff the u32 at offset `offset + shift` equals `value`
pub fn shift_offset_equals_u32(offset: u32, value: u32, shift: u32) -> Predicate {
    Predicate::from_inner(Terminal(Condition::new(
        cbpf::load_u32_at(offset + shift),
        cbpf::Comparison::from(BPF_JEQ as u8),
        value,
    )))
}

/// Ethernet layer filtering idioms
pub mod ethernet;

/// IP layer filtering idioms
pub mod ip;
