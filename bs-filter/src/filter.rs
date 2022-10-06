use crate::{cbpf, program::Program, Result};
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
