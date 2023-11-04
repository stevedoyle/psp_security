use std::fmt;

use aes::Aes256;
use bitfield::bitfield;
use clap::ValueEnum;
use derive_builder::Builder;
use pnet_packet::{
    ethernet::{EthernetPacket, MutableEthernetPacket},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    udp::MutableUdpPacket,
    MutablePacket, Packet,
};

use serde::{Deserialize, Serialize};

mod packet;
use packet::psp::MutablePspPacket;

const PSP_ICV_SIZE: usize = 16;
const PSP_MASTER_KEY_SIZE: usize = 32;
const PSP_SPI_KEY_SELECTOR_BIT: u32 = 31;
const PSP_CRYPT_OFFSET_UNITS: u8 = 4;
const PSP_UDP_PORT: u16 = 1000;

enum PspVersion {
    PspVer0, // AES-GCM-128
    PspVer1, // AES-GCM-256
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, clap::ValueEnum)]
pub enum PspEncap {
    #[default]
    Transport,
    Tunnel,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Default, Serialize, Deserialize, ValueEnum)]
pub enum CryptoAlg {
    AesGcm128,
    #[default]
    AesGcm256,
}

bitfield! {
    #[derive(Copy, Clone, Serialize, PartialEq, Eq)]
    pub struct PspHeaderFlags(u8);
    impl Debug;
    s, set_s: 0;
    d, set_d: 1;
    version, set_version: 5, 2;
    vc, set_vc: 6;
    r, set_r: 7;
}

impl Default for PspHeaderFlags {
    fn default() -> Self {
        let mut flags = Self(0);
        flags.set_s(false);
        flags.set_d(false);
        flags.set_version(PspVersion::PspVer0 as u8);
        flags.set_vc(false);
        flags.set_r(true);
        flags
    }
}

#[derive(Builder, Serialize, Debug, Default)]
#[builder(default)]
pub struct PspHeader {
    /// An IP protocol number, identifying the type of the next header.
    /// For example:
    /// - 6 for transport mode when next header is TCP
    /// - 17 for transport mode when next header is UDP
    /// - 4 for tunnel mode when next header is IPv4
    /// - 41 for tunnel mode when next header is IPv6
    next_hdr: u8,
    hdr_ext_len: u8,
    crypt_off: u8,
    flags: PspHeaderFlags,
    spi: u32,
    iv: u64,
}

type PspIcv = [u8; PSP_ICV_SIZE];

//#[derive(Debug)]
//struct PspTrailer {
//    icv: PspIcv,
//}

pub type PspMasterKey = [u8; PSP_MASTER_KEY_SIZE];

type PspDerivedKey = Vec<u8>;

#[derive(Clone, Copy, Debug, Default)]
pub struct PspEncryptConfig {
    pub master_keys: [PspMasterKey; 2],
    pub spi: u32,
    pub psp_encap: PspEncap,
    pub crypto_alg: CryptoAlg,
    pub transport_crypt_off: u8,
    //    ipv4_tunnel_crypt_off: u8,
    //    ipv6_tunnel_crypt_off: u8,
    pub include_vc: bool,
}

#[derive(Debug)]
pub struct PktContext {
    pub psp_cfg: PspEncryptConfig,
    pub key: PspDerivedKey,
    pub next_iv: u64,
}

impl PktContext {
    pub fn new() -> PktContext {
        PktContext {
            psp_cfg: PspEncryptConfig {
                master_keys: [[0; 32], [0; 32]],
                spi: 1,
                psp_encap: PspEncap::Transport,
                crypto_alg: CryptoAlg::AesGcm128,
                transport_crypt_off: 0,
                //                ipv4_tunnel_crypt_off: 0,
                //                ipv6_tunnel_crypt_off: 0,
                include_vc: false,
            },
            key: vec![0; 16],
            next_iv: 1,
        }
    }
}

impl Default for PktContext {
    fn default() -> PktContext {
        PktContext {
            psp_cfg: PspEncryptConfig {
                master_keys: [[0; 32], [0; 32]],
                spi: 1,
                psp_encap: PspEncap::Transport,
                crypto_alg: CryptoAlg::AesGcm128,
                transport_crypt_off: 0,
                //                ipv4_tunnel_crypt_off: 0,
                //                ipv6_tunnel_crypt_off: 0,
                include_vc: false,
            },
            key: vec![0; 16],
            next_iv: 1,
        }
    }
}

//#[derive(thiserror::Error, Debug)]
// enum PspError {
//     #[error("Crypto Error: {0}")]
//     Crypto(aes_gcm::Error),
//     #[error{"Serialization Error: {0}"}]
//     Serialize(#[from] bincode::ErrorKind)
// }

#[derive(Debug)]
pub enum PspError {
    Crypto(aes_gcm::Error),
    Serialize(String),
    //    BadPacket(packet::Error),
    SkippedPacket(String),
}

impl std::error::Error for PspError {}

impl From<aes_gcm::Error> for PspError {
    fn from(other: aes_gcm::Error) -> Self {
        Self::Crypto(other)
    }
}

impl From<bincode::Error> for PspError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialize(other.to_string())
    }
}

impl fmt::Display for PspError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PspError::Crypto(e) => {
                write!(f, "PSP Crypto Error {e}")
            }
            PspError::Serialize(e) => {
                write!(f, "PSP Serialize Error {e}")
            }
            PspError::SkippedPacket(e) => {
                write!(f, "PSP SkippedPacket Error {e}")
            }
        }
    }
}

//impl From<packet::Error> for PspError {
//    fn from(other: packet::Error) -> Self {
//        Self::BadPacket(other)
//    }
//}

const fn select_master_key(spi: u32, keys: &[PspMasterKey]) -> &PspMasterKey {
    if (spi >> PSP_SPI_KEY_SELECTOR_BIT) & 0x01 == 0 {
        return &keys[0];
    }
    &keys[1]
}

fn derive_psp_key_128(pkt_ctx: &PktContext, counter: u8, derived_key: &mut [u8]) {
    use cmac::{Cmac, Mac};

    let spi = pkt_ctx.psp_cfg.spi;

    let mut input_block: [u8; 16] = [0; 16];
    input_block[3] = counter;
    input_block[4] = 0x50;
    input_block[5] = 0x76;

    match pkt_ctx.psp_cfg.crypto_alg {
        CryptoAlg::AesGcm128 => {
            input_block[6] = 0x30;
            input_block[15] = 0x80;
        }
        CryptoAlg::AesGcm256 => {
            input_block[6] = 0x31;
            input_block[14] = 0x01;
            input_block[15] = 0x00;
        }
    }

    input_block[8] = ((spi >> 24) & 0xff) as u8;
    input_block[9] = ((spi >> 16) & 0xff) as u8;
    input_block[10] = ((spi >> 8) & 0xff) as u8;
    input_block[11] = (spi & 0xff) as u8;

    let key = select_master_key(spi, &pkt_ctx.psp_cfg.master_keys);

    let mut mac = Cmac::<Aes256>::new(key.into());
    mac.update(&input_block);
    let result = mac.finalize();
    derived_key.copy_from_slice(&result.into_bytes());
}

pub fn derive_psp_key(pkt_ctx: &mut PktContext) -> Result<(), PspError> {
    let mut key = [0; 16];

    derive_psp_key_128(pkt_ctx, 1, &mut key);
    pkt_ctx.key = Vec::from(key);
    if pkt_ctx.psp_cfg.crypto_alg == CryptoAlg::AesGcm256 {
        derive_psp_key_128(pkt_ctx, 2, &mut key);
        pkt_ctx.key.extend_from_slice(&key);
    }
    Ok(())
}

/// Encrypt a PSP packet given the PSP header and the payload buffer. The
/// encryption is an out-of-place operation with the ciphertext and the ICV tag
/// returned in separate buffers.
pub fn psp_encrypt(
    pkt_ctx: &PktContext,
    psp_hdr: &PspHeader,
    cleartext: &[u8],
    ciphertext: &mut [u8],
    icv: &mut [u8],
) -> Result<(), PspError> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes128Gcm,
    };

    let mut gcm_iv: [u8; 12] = [0; 12];
    gcm_iv[0..4].copy_from_slice(&psp_hdr.spi.to_ne_bytes());
    gcm_iv[4..12].copy_from_slice(&psp_hdr.iv.to_ne_bytes());

    let aad = bincode::serialize(psp_hdr)?;
    let cipher = Aes128Gcm::new(pkt_ctx.key.as_slice().into());
    let payload = Payload {
        msg: cleartext,
        aad: &aad,
    };
    let ct = cipher.encrypt(&gcm_iv.into(), payload)?;
    ciphertext.copy_from_slice(&ct[0..ct.len() - PSP_ICV_SIZE]);
    icv.copy_from_slice(&ct[(ct.len() - PSP_ICV_SIZE)..ct.len()]);

    Ok(())
}

/// Encapsulate a packet in transport mode.
/// Input packet:
///     +---------+--------+---------+
///     | Eth Hdr | IP Hdr | Payload |
///     +---------+--------+---------+
///
/// Output packet:
///     +---------+--------+---------+---------+---------+-------------+
///     | Eth Hdr | IP Hdr ] UDP Hdr | PSP Hdr | Payload | PSP Trailer |
///     +---------+--------+---------+---------+---------+-------------+
///
pub fn psp_transport_encap(
    pkt_ctx: &mut PktContext,
    in_pkt: &[u8],
    out_pkt: &mut [u8],
) -> Result<(), PspError> {
    let in_eth = EthernetPacket::new(in_pkt).unwrap();
    let in_ip = Ipv4Packet::new(in_eth.payload()).unwrap();
    let payload = in_ip.payload();

    let crypt_off = pkt_ctx.psp_cfg.transport_crypt_off * PSP_CRYPT_OFFSET_UNITS;
    if crypt_off as usize > payload.len() {
        return Err(PspError::SkippedPacket("Crypt offset too big".to_string()));
    }

    // Build the PSP encapsulated packet
    //   - copy the Ethernet and IP headers of the input packet.
    //   - insert the PSP UDP header
    //   - insert the PSP header
    //   - Copy crypt_off bytes from input packet starting at the L4 header
    //   - Compute ICV and insert encrypted data
    //   - Insert ICV as the PSP trailer

    let mut eth = MutableEthernetPacket::new(out_pkt).unwrap();
    eth.clone_from(&in_eth);

    let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
    ip.clone_from(&in_ip);
    ip.set_total_length(ip.packet().len() as u16);

    // TODO: Replace unwrap() with proper handling
    let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
    udp.set_destination(PSP_UDP_PORT);
    // TODO: Replace with a simple hash of the inner transport header numbers
    udp.set_source(PSP_UDP_PORT);
    udp.set_checksum(0);
    udp.set_length(udp.packet().len() as u16);

    let mut psp = MutablePspPacket::new(udp.payload_mut()).unwrap();
    psp.set_spi(pkt_ctx.psp_cfg.spi);
    psp.set_crypt_offset(pkt_ctx.psp_cfg.transport_crypt_off);
    psp.set_hdr_ext_len(1);
    psp.set_vc(pkt_ctx.psp_cfg.include_vc as u8);
    psp.set_iv(pkt_ctx.next_iv);
    psp.set_next_hdr(in_ip.get_next_level_protocol().0);
    pkt_ctx.next_iv += 1;
    match pkt_ctx.psp_cfg.crypto_alg {
        CryptoAlg::AesGcm128 => {
            psp.set_version(PspVersion::PspVer0 as u8);
        }
        CryptoAlg::AesGcm256 => {
            psp.set_version(PspVersion::PspVer1 as u8);
        }
    };

    let mut flags = PspHeaderFlags::default();
    flags.set_d(psp.get_d() != 0);
    flags.set_s(psp.get_s() != 0);
    flags.set_version(psp.get_version());
    flags.set_vc(psp.get_vc() != 0);

    let psp_hdr = &PspHeader {
        next_hdr: psp.get_next_hdr(),
        hdr_ext_len: psp.get_hdr_ext_len(),
        crypt_off: psp.get_crypt_offset(),
        flags: flags,
        spi: psp.get_spi(),
        iv: psp.get_iv(),
    };
    let cleartext = in_ip.payload();
    let ciphertext = psp.payload_mut();
    let mut icv: PspIcv = [0u8; PSP_ICV_SIZE];
    psp_encrypt(
        pkt_ctx,
        psp_hdr,
        cleartext,
        &mut ciphertext[..cleartext.len()],
        &mut icv,
    )?;
    ciphertext[cleartext.len()..].copy_from_slice(&icv);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ::packet::{ether, ip, Builder};
    use pnet_packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        udp::UdpPacket,
    };

    use crate::packet::psp::PspPacket;

    use super::*;

    #[test]
    fn check_psp_header_builder() {
        let hdr = PspHeaderBuilder::default()
            .next_hdr(17)
            .spi(0x12345678)
            .iv(0x12345678_9ABCDEF0)
            .build()
            .unwrap();

        assert_eq!(hdr.spi, 0x12345678);
        assert_eq!(hdr.iv, 0x12345678_9ABCDEF0);
        assert_eq!(hdr.next_hdr, 17);
        assert_eq!(hdr.flags.0, 0x80u8);
    }

    #[test]
    fn test_derive_psp_key_128() {
        let mut derived_key: [u8; 16] = [0; 16];
        let mut pkt_ctx = PktContext::new();
        pkt_ctx.psp_cfg.master_keys[0] = [
            0x34, 0x44, 0x8A, 0x06, 0x42, 0x92, 0x60, 0x1B, 0x11, 0xA0, 0x97, 0x8F, 0x56, 0xA2,
            0xd3, 0x4c, 0xf3, 0xfc, 0x35, 0xed, 0xe1, 0xa6, 0xbc, 0x04, 0xf8, 0xdb, 0x3e, 0x52,
            0x43, 0xa2, 0xb0, 0xca,
        ];
        pkt_ctx.psp_cfg.master_keys[1] = [
            0x56, 0x39, 0x52, 0x56, 0x5d, 0x3a, 0x78, 0xae, 0x77, 0x3e, 0xc1, 0xb7, 0x79, 0xf2,
            0xf2, 0xd9, 0x9f, 0x4a, 0x7f, 0x53, 0xa6, 0xfb, 0xb9, 0xb0, 0x7d, 0x5b, 0x71, 0xf3,
            0x93, 0x64, 0xd7, 0x39,
        ];

        pkt_ctx.psp_cfg.spi = 0x12345678;
        let expected: [u8; 16] = [
            0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90, 0xb7, 0x4b, 0x70, 0xae, 0x46, 0x8e,
            0x4e, 0x30,
        ];

        derive_psp_key_128(&pkt_ctx, 1, &mut derived_key);
        assert_eq!(expected, derived_key);

        pkt_ctx.psp_cfg.spi = 0x9A345678;
        let expected: [u8; 16] = [
            0x39, 0x46, 0xda, 0x25, 0x54, 0xea, 0xe4, 0x6a, 0xd1, 0xef, 0x77, 0xa6, 0x43, 0x72,
            0xed, 0xc4,
        ];

        derive_psp_key_128(&pkt_ctx, 1, &mut derived_key);
        assert_eq!(expected, derived_key);
    }

    #[test]
    fn test_derive_psp_key() {
        let mut pkt_ctx = PktContext::new();
        pkt_ctx.psp_cfg.master_keys[0] = [
            0x34, 0x44, 0x8A, 0x06, 0x42, 0x92, 0x60, 0x1B, 0x11, 0xA0, 0x97, 0x8F, 0x56, 0xA2,
            0xd3, 0x4c, 0xf3, 0xfc, 0x35, 0xed, 0xe1, 0xa6, 0xbc, 0x04, 0xf8, 0xdb, 0x3e, 0x52,
            0x43, 0xa2, 0xb0, 0xca,
        ];
        pkt_ctx.psp_cfg.spi = 0x12345678;

        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm128;
        let expected: [u8; 16] = [
            0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90, 0xb7, 0x4b, 0x70, 0xae, 0x46, 0x8e,
            0x4e, 0x30,
        ];
        assert!(derive_psp_key(&mut pkt_ctx).is_ok());
        assert_eq!(pkt_ctx.key.len(), 16);
        assert_eq!(pkt_ctx.key, expected);

        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm256;
        let expected: [u8; 32] = [
            0x2b, 0x7d, 0x72, 0x07, 0x4e, 0x42, 0xca, 0x33, 0x44, 0x87, 0xf2, 0x99, 0x0e, 0x3f,
            0x8c, 0x40, 0x37, 0xe4, 0x36, 0xf3, 0x82, 0x83, 0x44, 0x9b, 0x76, 0x46, 0x3e, 0x9b,
            0x7f, 0xb2, 0xe3, 0xde,
        ];
        assert!(derive_psp_key(&mut pkt_ctx).is_ok());
        assert_eq!(pkt_ctx.key.len(), 32);
        assert_eq!(pkt_ctx.key, expected);
    }

    #[test]
    fn test_psp_encrypt() {
        let mut pkt_ctx = PktContext::new();
        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm128;
        pkt_ctx.key = vec![
            0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90, 0xb7, 0x4b, 0x70, 0xae, 0x46, 0x8e,
            0x4e, 0x30,
        ];
        let mut psp_hdr = PspHeader::default();
        psp_hdr.next_hdr = 6;
        psp_hdr.spi = 0x12345678;
        psp_hdr.iv = 0x12345678_9ABCDEFF;

        let cleartext = vec![0u8; 256];
        let mut ciphertext = vec![0u8; 256];
        let mut icv = vec![0u8; PSP_ICV_SIZE];

        let res = psp_encrypt(&pkt_ctx, &psp_hdr, &cleartext, &mut ciphertext, &mut icv);
        assert!(res.is_ok());
        assert_ne!(ciphertext, cleartext);
    }

    #[test]
    fn check_transport_encap() -> Result<(), Box<dyn std::error::Error>> {
        let in_pkt = ether::Builder::default()
            .protocol(::packet::ether::Protocol::Ipv4)?
            .ip()?
            .v4()?
            .source(Ipv4Addr::new(192, 168, 0, 1))?
            .destination(Ipv4Addr::new(192, 168, 1, 1))?
            .protocol(ip::Protocol::Udp)?
            .udp()?
            .destination(0x1234)?
            .payload(b"testing")?
            .build()?;

        // TODO: Replace magic numbers.
        let out_pkt_len = in_pkt.len()
            + UdpPacket::minimum_packet_size()
            + PspPacket::minimum_packet_size()
            + PSP_ICV_SIZE;
        let mut out_pkt = vec![0u8; out_pkt_len];
        let mut pkt_ctx = PktContext::default();
        pkt_ctx.psp_cfg.spi = 1;

        assert!(psp_transport_encap(&mut pkt_ctx, &in_pkt, &mut out_pkt).is_ok());

        let eth = EthernetPacket::new(&out_pkt).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Udp);
        let udp = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp.get_destination(), PSP_UDP_PORT);
        let psp = PspPacket::new(udp.payload()).unwrap();
        assert_eq!(psp.get_spi(), pkt_ctx.psp_cfg.spi);
        assert_eq!(psp.get_version(), PspVersion::PspVer0 as u8);

        Ok(())
    }
}
