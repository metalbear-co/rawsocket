#[allow(dead_code)]
mod inner {
    pub const BPF_LD: i32 = 0x00;
    pub const BPF_LDX: i32 = 0x01;
    pub const BPF_ST: i32 = 0x02;
    pub const BPF_STX: i32 = 0x03;
    pub const BPF_ALU: i32 = 0x04;
    pub const BPF_JMP: i32 = 0x05;
    pub const BPF_RET: i32 = 0x06;
    pub const BPF_MISC: i32 = 0x07;
    pub const BPF_W: i32 = 0x00;
    pub const BPF_H: i32 = 0x08;
    pub const BPF_B: i32 = 0x10;
    pub const BPF_IMM: i32 = 0x00;
    pub const BPF_ABS: i32 = 0x20;
    pub const BPF_IND: i32 = 0x40;
    pub const BPF_MEM: i32 = 0x60;
    pub const BPF_LEN: i32 = 0x80;
    pub const BPF_MSH: i32 = 0xa0;
    pub const BPF_ADD: i32 = 0x00;
    pub const BPF_SUB: i32 = 0x10;
    pub const BPF_MUL: i32 = 0x20;
    pub const BPF_DIV: i32 = 0x30;
    pub const BPF_OR: i32 = 0x40;
    pub const BPF_AND: i32 = 0x50;
    pub const BPF_LSH: i32 = 0x60;
    pub const BPF_RSH: i32 = 0x70;
    pub const BPF_NEG: i32 = 0x80;
    pub const BPF_MOD: i32 = 0x90;
    pub const BPF_XOR: i32 = 0xa0;
    pub const BPF_JA: i32 = 0x00;
    pub const BPF_JEQ: i32 = 0x10;
    pub const BPF_JGT: i32 = 0x20;
    pub const BPF_JGE: i32 = 0x30;
    pub const BPF_JSET: i32 = 0x40;
    pub const BPF_K: i32 = 0x00;
    pub const BPF_X: i32 = 0x08;
    pub const BPF_A: i32 = 0x10;

    pub const OFFSET_ETHER_DST: u32 = 0;
    pub const OFFSET_ETHER_SRC: u32 = 6;
    pub const OFFSET_ETHER_TYPE: u32 = 12;
    pub const SIZE_ETHER_HEADER: u32 = 14;
    pub const SIZE_IPV4_HEADER: u32 = 20;
    pub const SIZE_IPV6_HEADER: u32 = 40;

    pub const OFFSET_IP4_FRAGMENT: u32 = 6;
    pub const OFFSET_IP4_TTL: u32 = 8;
    pub const OFFSET_IP4_PROTO: u32 = 9;
    pub const OFFSET_IP4_SRC: u32 = 12;
    pub const OFFSET_IP4_DST: u32 = 16;

    pub const OFFSET_IP6_NEXT_HEADER: u32 = 6;
    pub const OFFSET_IP6_HOP_LIMIT: u32 = 7;
    pub const OFFSET_IP6_SRC: u32 = 8;
    pub const OFFSET_IP6_DST: u32 = 24;

    pub const OFFSET_TCP_SRC_PORT: u32 = 0;
    pub const OFFSET_TCP_DST_PORT: u32 = 2;

    pub const ETH_P_IP: u32 = 0x0800;
    pub const ETH_P_ARP: u32 = 0x0806;
    pub const ETH_P_IPV6: u32 = 0x86DD;
    pub const ETH_P_LLDP: u32 = 0x88CC;
    pub const ETH_P_8021Q: u32 = 0x8100;

    /* Extended instruction set based on top of classic BPF */
    pub const BPF_JMP32: i32 = 0x06;
    pub const BPF_ALU64: i32 = 0x07;
    pub const BPF_DW: i32 = 0x18;
    pub const BPF_XADD: i32 = 0xc0;
    pub const BPF_MOV: i32 = 0xb0;
    pub const BPF_ARSH: i32 = 0xc0;
    pub const BPF_END: i32 = 0xd0;
    pub const BPF_TO_LE: i32 = 0x00;
    pub const BPF_TO_BE: i32 = 0x08;
    pub const BPF_FROM_LE: i32 = BPF_TO_LE;
    pub const BPF_FROM_BE: i32 = BPF_TO_BE;
    pub const BPF_JNE: i32 = 0x50;
    pub const BPF_JLT: i32 = 0xa0;
    pub const BPF_JLE: i32 = 0xb0;
    pub const BPF_JSGT: i32 = 0x60;
    pub const BPF_JSGE: i32 = 0x70;
    pub const BPF_JSLT: i32 = 0xc0;
    pub const BPF_JSLE: i32 = 0xd0;
    pub const BPF_CALL: i32 = 0x80;
    pub const BPF_EXIT: i32 = 0x90;
}
pub use inner::*;
