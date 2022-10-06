//! Packet filtering for `bs`
pub(crate) mod cbpf;
pub(crate) mod consts;
pub(crate) mod filter;
pub(crate) mod predicate;
pub(crate) mod program;

pub use cbpf::SocketFilterProgram;
use thiserror::Error;

pub use filter::Filter;
pub use predicate::Predicate;

/// Ready-made filtering packet idioms, ranging from low level (e.g. `offset_equals_*` idioms) to
/// higher level carefully implemented widely used filters (e.g.
/// [`ip_host`](idiom/ip/fn.ip_host.html))
///
/// idioms are implemented as `Predicate`s so they can be freely combined into more sophisticated
/// and/or specific filters
pub mod idiom;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub(crate) struct Computation {
    instructions: Vec<cbpf::Instruction>,
}

impl Computation {
    pub fn new(instructions: Vec<cbpf::Instruction>) -> Self {
        Self { instructions }
    }

    pub fn build(self) -> Vec<cbpf::Instruction> {
        self.instructions
    }
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub(crate) struct Condition {
    computation: Computation,
    comparison: cbpf::Comparison,
    operand: cbpf::Value,
}

impl Condition {
    pub(crate) fn new(
        computation: Vec<cbpf::Instruction>,
        comparison: cbpf::Comparison,
        operand: cbpf::Value,
    ) -> Self {
        Self {
            computation: Computation::new(computation),
            comparison,
            operand,
        }
    }

    pub(crate) fn build(self, jt: usize, jf: usize) -> Vec<cbpf::Instruction> {
        let mut res = cbpf::jump(self.comparison, self.operand, jt, jf);
        res.extend(self.computation.build());
        res
    }
}

#[derive(Error, Debug)]
pub enum BsError {
    #[error("Filter program size exceeded max u16")]
    FilterProgramOverflow,
}

pub type Result<T> = std::result::Result<T, BsError>;

pub fn instructions_to_program(
    instructions: Vec<cbpf::Instruction>,
) -> Result<SocketFilterProgram> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(BsError::FilterProgramOverflow);
    }
    Ok(SocketFilterProgram::from_vector(instructions))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
