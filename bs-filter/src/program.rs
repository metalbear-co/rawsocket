use crate::{cbpf, instructions_to_program, Result};
use std::iter::FromIterator;

/// BPF Program for filtering packets on a socket
#[repr(C)]
#[derive(Debug)]
pub struct Program {
    filter: Vec<cbpf::Instruction>,
}

impl Program {
    /// Creates a new `Program` from the given instructions
    pub fn new(instructions: Vec<cbpf::Instruction>) -> Self {
        Self {
            filter: instructions,
        }
    }

    /// Creates a `SocketOption` referring to this `Program`
    pub fn build(self) -> Result<cbpf::SocketFilterProgram> {
        instructions_to_program(self.filter)
    }
}

impl FromIterator<cbpf::Instruction> for Program {
    fn from_iter<I: IntoIterator<Item = cbpf::Instruction>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
