//! Packet filtering for `bs`
pub(crate) mod cbpf;
pub(crate) mod consts;
pub(crate) mod filter;

pub use cbpf::SocketFilterProgram;
use thiserror::Error;

pub use filter::{build_drop_always, build_tcp_port_filter};

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
