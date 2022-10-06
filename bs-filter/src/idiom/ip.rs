use crate::consts::{
    OFFSET_IP4_DST, OFFSET_IP4_PROTO, OFFSET_IP4_SRC, OFFSET_IP4_TTL, OFFSET_IP6_DST,
    OFFSET_IP6_HOP_LIMIT, OFFSET_IP6_NEXT_HEADER, OFFSET_IP6_SRC, SIZE_ETHER_HEADER,
};
use crate::idiom::ethernet::{ether_type_ip4, ether_type_ip6};
use crate::idiom::shift_offset_equals_u32;
use crate::idiom::shift_offset_equals_u8;
use crate::predicate::Predicate;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// true iff packet's IP TTL field is `ttl`, assuming IP layer starts at offset `shift`
pub fn shift_ip4_ttl(ttl: u8, shift: u32) -> Predicate {
    shift_offset_equals_u8(OFFSET_IP4_TTL, ttl, shift)
}

/// true iff packet's IP TTL field is `ttl`
pub fn ip4_ttl(ttl: u8) -> Predicate {
    shift_ip4_ttl(ttl, SIZE_ETHER_HEADER)
}

/// true iff packet's IP protocol field is `proto`, assuming IP layer starts at offset `shift`
pub fn shift_ip4_proto(proto: u8, shift: u32) -> Predicate {
    shift_offset_equals_u8(OFFSET_IP4_PROTO, proto, shift)
}

/// true iff packet's IP protocol field is `proto`
pub fn ip4_proto(proto: u8) -> Predicate {
    shift_ip4_proto(proto, SIZE_ETHER_HEADER)
}

/// true iff IP source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip4_src(ip: Ipv4Addr, shift: u32) -> Predicate {
    shift_offset_equals_u32(OFFSET_IP4_SRC, ip.into(), shift)
}

/// true iff IP source is `ip`
pub fn ip4_src(ip: Ipv4Addr) -> Predicate {
    ether_type_ip4() & shift_ip4_src(ip, SIZE_ETHER_HEADER)
}

/// true iff IP destination is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip4_dst(ip: Ipv4Addr, shift: u32) -> Predicate {
    shift_offset_equals_u32(OFFSET_IP4_DST, ip.into(), shift)
}

/// true iff IP destination is `ip`
pub fn ip4_dst(ip: Ipv4Addr) -> Predicate {
    ether_type_ip4() & shift_ip4_dst(ip, SIZE_ETHER_HEADER)
}

/// true iff either IP destination or source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip4_host(ip: Ipv4Addr, shift: u32) -> Predicate {
    shift_ip4_src(ip, shift) | shift_ip4_dst(ip, shift)
}

/// true iff `ip` is either IP source or destination
pub fn ip4_host(ip: Ipv4Addr) -> Predicate {
    shift_ip4_host(ip, SIZE_ETHER_HEADER)
}

/// true iff packet's IPv6 Hop Limit field is `ttl`, assuming IPv6 layer starts at offset `shift`
pub fn shift_ip6_hop_limit(ttl: u8, shift: u32) -> Predicate {
    shift_offset_equals_u8(OFFSET_IP6_HOP_LIMIT, ttl, shift)
}

/// true iff packet's IPv6 Hop Limit field is `ttl`
pub fn ip6_hop_limit(ttl: u8) -> Predicate {
    shift_ip6_hop_limit(ttl, SIZE_ETHER_HEADER)
}

/// true iff packet's IPv6 Next Header field is `proto`, assuming IPv6 layer starts at offset `shift`
pub fn shift_ip6_next_header(proto: u8, shift: u32) -> Predicate {
    shift_offset_equals_u8(OFFSET_IP6_NEXT_HEADER, proto, shift)
}

/// true iff packet's IPv6 protocol field is `proto`
pub fn ip6_next_header(proto: u8) -> Predicate {
    shift_ip6_next_header(proto, SIZE_ETHER_HEADER)
}

use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::mem::size_of;
fn ip6_address_to_u32_array(ip: Ipv6Addr) -> [u32; 4] {
    let buf = &mut ip.octets();
    let mut bytes = Cursor::new(buf);
    [
        bytes.read_u32::<BigEndian>().unwrap(),
        bytes.read_u32::<BigEndian>().unwrap(),
        bytes.read_u32::<BigEndian>().unwrap(),
        bytes.read_u32::<BigEndian>().unwrap(),
    ]
}

/// true iff IP source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip6_src(ip: Ipv6Addr, shift: u32) -> Predicate {
    let words = ip6_address_to_u32_array(ip);

    shift_offset_equals_u32(OFFSET_IP6_SRC, words[0], shift)
        & shift_offset_equals_u32(OFFSET_IP6_SRC + size_of::<u32>() as u32, words[1], shift)
        & shift_offset_equals_u32(
            OFFSET_IP6_SRC + size_of::<u32>() as u32 * 2,
            words[2],
            shift,
        )
        & shift_offset_equals_u32(
            OFFSET_IP6_SRC + size_of::<u32>() as u32 * 3,
            words[3],
            shift,
        )
}

/// true iff IP source is `ip`
pub fn ip6_src(ip: Ipv6Addr) -> Predicate {
    ether_type_ip6() & shift_ip6_src(ip, SIZE_ETHER_HEADER)
}

/// true iff IP destination is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip6_dst(ip: Ipv6Addr, shift: u32) -> Predicate {
    let words = ip6_address_to_u32_array(ip);

    shift_offset_equals_u32(OFFSET_IP6_DST, words[0], shift)
        & shift_offset_equals_u32(OFFSET_IP6_DST + size_of::<u32>() as u32, words[1], shift)
        & shift_offset_equals_u32(
            OFFSET_IP6_DST + size_of::<u32>() as u32 * 2,
            words[2],
            shift,
        )
        & shift_offset_equals_u32(
            OFFSET_IP6_DST + size_of::<u32>() as u32 * 3,
            words[3],
            shift,
        )
}

/// true iff IP destination is `ip`
pub fn ip6_dst(ip: Ipv6Addr) -> Predicate {
    ether_type_ip6() & shift_ip6_dst(ip, SIZE_ETHER_HEADER)
}

/// true iff either IP destination or source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip6_host(ip: Ipv6Addr, shift: u32) -> Predicate {
    shift_ip6_src(ip, shift) | shift_ip6_dst(ip, shift)
}

/// true iff `ip` is either IP source or destination
pub fn ip6_host(ip: Ipv6Addr) -> Predicate {
    shift_ip6_host(ip, SIZE_ETHER_HEADER)
}

/// true iff packet's Hop Limit field (TTL for IPv4) is `ttl`, assuming IP layer starts at offset `shift`
pub fn shift_ip_hop_limit(ttl: u8, shift: u32) -> Predicate {
    shift_ip4_ttl(ttl, shift) | shift_ip6_hop_limit(ttl, shift)
}

/// true iff packet's Hop Limit is `ttl`
pub fn ip_hop_limit(ttl: u8) -> Predicate {
    shift_ip_hop_limit(ttl, SIZE_ETHER_HEADER)
}

/// true iff packet's the next layer after IP is identified by IP protocol `proto`, assuming IP
/// layer starts at offset `shift`
pub fn shift_ip_next_header(proto: u8, shift: u32) -> Predicate {
    shift_ip4_proto(proto, shift) | shift_ip6_next_header(proto, shift)
}

/// true iff packet's the next layer after IP is identified by IP protocol `proto`
pub fn ip_next_header(proto: u8) -> Predicate {
    shift_ip_next_header(proto, SIZE_ETHER_HEADER)
}

/// true iff IP source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_src(ip: IpAddr, shift: u32) -> Predicate {
    match ip {
        IpAddr::V4(ip4) => shift_ip4_src(ip4, shift),
        IpAddr::V6(ip6) => shift_ip6_src(ip6, shift),
    }
}

/// true iff IP source is `ip`
pub fn ip_src(ip: IpAddr) -> Predicate {
    shift_ip_src(ip, SIZE_ETHER_HEADER)
}

/// true iff IP destination is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_dst(ip: IpAddr, shift: u32) -> Predicate {
    match ip {
        IpAddr::V4(ip4) => shift_ip4_dst(ip4, shift),
        IpAddr::V6(ip6) => shift_ip6_dst(ip6, shift),
    }
}

/// true iff IP destination is `ip`
pub fn ip_dst(ip: IpAddr) -> Predicate {
    shift_ip_dst(ip, SIZE_ETHER_HEADER)
}

/// true iff either IP destination or source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_host(ip: IpAddr, shift: u32) -> Predicate {
    shift_ip_src(ip, shift) | shift_ip_dst(ip, shift)
}

/// true iff `ip` is either IP source or destination
pub fn ip_host(ip: IpAddr) -> Predicate {
    shift_ip_host(ip, SIZE_ETHER_HEADER)
}
