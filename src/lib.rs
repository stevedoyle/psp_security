use std::{fmt, io, str::FromStr};

use aes::Aes256;
use aes_gcm::Aes256Gcm;
use bincode::Options;
use bitfield::bitfield;
use clap::ValueEnum;
use derive_builder::Builder;
use etherparse::{
    ether_type, ip_number, Ethernet2Header, IpHeader, Ipv4Header, Ipv6Header, PacketHeaders,
    SerializedSize, TransportHeader, UdpHeader,
};
use log::debug;
use pnet_packet::Packet;

use serde::{Deserialize, Serialize};

mod packet;
use packet::psp::PspPacket;

pub const PSP_ICV_SIZE: usize = 16;
const PSP_VC_SIZE: usize = 8;
const PSP_MASTER_KEY_SIZE: usize = 32;
const PSP_SPI_KEY_SELECTOR_BIT: u32 = 31;
const PSP_CRYPT_OFFSET_UNITS: usize = 4;
const PSP_UDP_PORT: u16 = 1000;
const PSP_HDR_FIXED_LEN: u8 = 16;

#[repr(u8)]
#[derive(Debug, PartialEq)]
enum PspVersion {
    PspVer0 = 0, // AES-GCM-128
    PspVer1 = 1, // AES-GCM-256
}

impl TryFrom<u8> for PspVersion {
    type Error = PspError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PspVersion::PspVer0),
            1 => Ok(PspVersion::PspVer1),
            _ => Err(PspError::InvalidPspVersion(value)),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, clap::ValueEnum)]
pub enum PspEncap {
    #[default]
    Transport,
    Tunnel,
}

impl fmt::Display for PspEncap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Transport => write!(f, "transport"),
            Self::Tunnel => write!(f, "tunnel"),
        }
    }
}

impl FromStr for PspEncap {
    type Err = String;

    fn from_str(s: &str) -> Result<PspEncap, Self::Err> {
        match s {
            "transport" => Ok(PspEncap::Transport),
            "tunnel" => Ok(PspEncap::Tunnel),
            _ => Err("Invalid PspEncap string".to_string()),
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Default, Serialize, Deserialize, ValueEnum)]
pub enum CryptoAlg {
    AesGcm128,
    #[default]
    AesGcm256,
}

impl fmt::Display for CryptoAlg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AesGcm128 => write!(f, "aes-gcm-128"),
            Self::AesGcm256 => write!(f, "aes-gcm-256"),
        }
    }
}

impl FromStr for CryptoAlg {
    type Err = String;

    fn from_str(s: &str) -> Result<CryptoAlg, Self::Err> {
        match s {
            "aes-gcm-128" => Ok(CryptoAlg::AesGcm128),
            "aes-gcm-256" => Ok(CryptoAlg::AesGcm256),
            _ => Err("Invalid crypto algorithm string".to_string()),
        }
    }
}

bitfield! {
    #[derive(Copy, Clone, Serialize, PartialEq, Eq)]
    pub struct PspHeaderFlags(u8);
    impl Debug;
    r, set_r: 0;
    v, set_v: 1;
    version, set_version: 5, 2;
    d, set_d: 6;
    s, set_s: 7;
}

impl Default for PspHeaderFlags {
    fn default() -> Self {
        let mut flags = Self(0);
        flags.set_r(true);
        flags.set_v(false);
        flags.set_version(PspVersion::PspVer0 as u8);
        flags.set_d(false);
        flags.set_s(false);
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

pub type PspMasterKey = [u8; PSP_MASTER_KEY_SIZE];

type PspDerivedKey = Vec<u8>;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PspConfig {
    pub master_keys: [PspMasterKey; 2],
    pub spi: u32,
    pub psp_encap: PspEncap,
    pub crypto_alg: CryptoAlg,
    pub transport_crypt_off: u8,
    pub ipv4_tunnel_crypt_off: u8,
    pub ipv6_tunnel_crypt_off: u8,
    pub include_vc: bool,
}

#[derive(Debug, Clone)]
pub struct PktContext {
    pub psp_cfg: PspConfig,
    pub key: PspDerivedKey,
    pub iv: u64,
    pub vc: u64,
}

impl PktContext {
    pub fn new() -> PktContext {
        PktContext {
            psp_cfg: PspConfig {
                master_keys: [[0; 32], [0; 32]],
                spi: 1,
                psp_encap: PspEncap::Transport,
                crypto_alg: CryptoAlg::AesGcm128,
                transport_crypt_off: 0,
                ipv4_tunnel_crypt_off: 0,
                ipv6_tunnel_crypt_off: 0,
                include_vc: false,
            },
            key: vec![0; 16],
            iv: 1,
            vc: 0,
        }
    }
}

impl Default for PktContext {
    fn default() -> PktContext {
        PktContext::new()
    }
}

/// PspError enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum PspError {
    /// Represents a crypto error. Crypto errors can occur during PSP packet
    /// encryption or decryption.
    #[error("PSP Crypto Error: {}", .0)]
    CryptoError(aes_gcm::Error),

    /// Serialization errors occur when converting PSP headers into a byte
    /// stream.
    #[error("PSP Serialization Error")]
    SerializeError(#[from] bincode::Error),

    /// The PSP packet didn't contain any ciphertext payload.
    #[error("PSP No Ciphertext In PSP Packet")]
    NoCiphertext,

    /// An error occurred when parsing a packet.
    #[error("Packet Parse Error")]
    PacketParseError(#[from] etherparse::ReadError),

    /// An error occurred when writing a packet.
    #[error("Packet Write Error")]
    PacketWriteError(#[from] etherparse::WriteError),

    /// An error was encountered building the packet.
    #[error("PSP Packet Build Error")]
    PacketBuildError(#[from] io::Error),

    /// The packet could not be encapsulated in PSP.
    #[error("Packet Could not be encapsulated in PSP: {}", .0)]
    PacketEncapError(String),

    /// Packet could not be decapsulated. This could be caused by a number of reasons including the
    /// packet not being a valid PSP packet or a combination of outer packet headers which are
    /// unsupported by the library.
    #[error("PSP Packet Decap Error: {}", .0)]
    PacketDecapError(String),

    /// Invalid PSP Version
    #[error("Invalid PSP Version: {}", .0)]
    InvalidPspVersion(u8),

    /// Invalid PSP packet size. This can occur when parsing the packet if the length after the PSP
    /// header is too short to hold the PSP ICV value.
    #[error("Invalid PSP Packet Size")]
    InvalidPspPacketSize,

    // The implementation does not support a feature. The string describes what is not supported.
    #[error("Unsupported Feature: {}", .0)]
    Unsupported(String),
}

// This is required as aes_gcm::Error doesn't implement the necessary traits for
// it to be used with thiserror #[from]
impl From<aes_gcm::Error> for PspError {
    fn from(other: aes_gcm::Error) -> Self {
        Self::CryptoError(other)
    }
}

const fn get_psp_version(alg: CryptoAlg) -> PspVersion {
    match alg {
        CryptoAlg::AesGcm128 => PspVersion::PspVer0,
        CryptoAlg::AesGcm256 => PspVersion::PspVer1,
    }
}

const fn get_psp_crypto_alg(ver: PspVersion) -> CryptoAlg {
    match ver {
        PspVersion::PspVer0 => CryptoAlg::AesGcm128,
        PspVersion::PspVer1 => CryptoAlg::AesGcm256,
    }
}

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

/// Derive a PSP key using the `pkt_ctx.psp_cfg.spi` and `pkt_ctx.master_keys` and store the derived
/// key in `pkt_ctx.key`.
pub fn derive_psp_key(pkt_ctx: &mut PktContext) {
    let mut key = [0; 16];

    derive_psp_key_128(pkt_ctx, 1, &mut key);
    pkt_ctx.key = Vec::from(key);
    if pkt_ctx.psp_cfg.crypto_alg == CryptoAlg::AesGcm256 {
        derive_psp_key_128(pkt_ctx, 2, &mut key);
        pkt_ctx.key.extend_from_slice(&key);
    }
}

/// Use the PSP packet SPI and IV fields, build an IV for use with AES-GCM.
fn get_aesgcm_iv(spi: u32, iv: u64) -> [u8; 12] {
    let mut gcm_iv: [u8; 12] = [0; 12];
    gcm_iv[0..4].copy_from_slice(&spi.to_be_bytes());
    gcm_iv[4..12].copy_from_slice(&iv.to_be_bytes());
    gcm_iv
}

/// Encrypt a PSP packet given the PSP header and the payload buffer. The
/// encryption is an out-of-place operation with the ciphertext and the ICV tag
/// returned in the same buffer.
///
/// ```rust
/// # use psp_security::*;
/// # fn main() -> Result<(), PspError> {
/// let algo = CryptoAlg::AesGcm128;
/// let key: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00];
/// let iv: [u8; 12] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
/// let aad = [0xCA, 0xFE, 0xFA, 0xCE];
/// let cleartext = vec![0u8; 64];
/// let mut ciphertext = vec![0u8; cleartext.len() + PSP_ICV_SIZE];
/// psp_encrypt(algo, &key, &iv, &aad, &cleartext, &mut ciphertext)?;
/// #
/// #   Ok(())
/// # }
/// ```
///
/// # Errors
///
/// If this function encounters any errors, a PspError::CryptoError will be returned. The contents
/// of the ciphertext slice are only valid if no errors occur.
pub fn psp_encrypt(
    algo: CryptoAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    cleartext: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), PspError> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes128Gcm,
    };

    debug!("psp_encrypt(): Key: {:02X?}", key);
    debug!("psp_encrypt(): IV:  {:02X?}", iv);
    debug!("psp_encrypt(): AAD: {:02X?}", aad);
    debug!("psp_encrypt(): Cleartext len:  {}", cleartext.len());
    debug!("psp_encrypt(): Ciphertext len: {}", ciphertext.len());

    let payload = Payload {
        msg: cleartext,
        aad,
    };

    let ct = match algo {
        CryptoAlg::AesGcm128 => Aes128Gcm::new(key.into())
            .encrypt(iv.into(), payload)
            .map_err(PspError::CryptoError)?,
        CryptoAlg::AesGcm256 => Aes256Gcm::new(key.into())
            .encrypt(iv.into(), payload)
            .map_err(PspError::CryptoError)?,
    };

    ciphertext.copy_from_slice(&ct);

    Ok(())
}

/// Decrypt a PSP packet. The decryption is an out-of-place operation returned
/// in separate buffers. On input, the ciphertext buffer must also contain the icv.
///
/// ```rust
/// # use psp_security::*;
/// # fn main() -> Result<(), psp_security::PspError> {
/// let algo = CryptoAlg::AesGcm128;
/// let key: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00];
/// let iv: [u8; 12] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
/// let aad = [0xCA, 0xFE, 0xFA, 0xCE];
/// let cleartext = vec![0u8; 64];
/// let mut ciphertext = vec![0u8; cleartext.len() + PSP_ICV_SIZE];
/// psp_encrypt(algo, &key, &iv, &aad, &cleartext, &mut ciphertext)?;
/// let mut decrypted = vec![0u8; cleartext.len()];
/// psp_decrypt(algo, &key, &iv, &aad, &ciphertext, &mut decrypted)?;
/// #
/// #   Ok(())
/// # }
/// ```
///
/// # Errors
///
/// If this function encounters any errors, a PspError::CryptoError will be returned. The contents
/// of the ciphertext slice are only valid if no errors occur.
pub fn psp_decrypt(
    algo: CryptoAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    cleartext: &mut [u8],
) -> Result<(), PspError> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes128Gcm,
    };

    if ciphertext.is_empty() {
        return Err(PspError::NoCiphertext);
    }

    debug!("psp_decrypt(): Key: {:02X?}", key);
    debug!("psp_decrypt(): IV:  {:02X?}", iv);
    debug!("psp_decrypt(): AAD: {:02X?}", aad);
    debug!("psp_encrypt(): Ciphertext len: {}", ciphertext.len());
    debug!("psp_encrypt(): Cleartext len:  {}", cleartext.len());

    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let pt = match algo {
        CryptoAlg::AesGcm128 => Aes128Gcm::new(key.into())
            .decrypt(iv.into(), payload)
            .map_err(PspError::CryptoError)?,
        CryptoAlg::AesGcm256 => Aes256Gcm::new(key.into())
            .decrypt(iv.into(), payload)
            .map_err(PspError::CryptoError)?,
    };
    // Not all of the decrypted content needs to be copied. e.g. when an encrypted vc is present.
    let drop_offset = pt.len() - cleartext.len();
    cleartext.copy_from_slice(&pt[drop_offset..]);

    Ok(())
}

/// Encapsulate a packet in transport mode.
///
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
/// ```rust
/// # use psp_security::*;
/// # use etherparse::PacketBuilder;
/// # fn main() -> Result<(), PspError> {
/// let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
///     .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
///     .udp(21, 1234);
/// let payload = [1, 2, 3, 4, 5, 6, 7, 8];
/// let mut pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
/// builder.write(&mut pkt, &payload).unwrap();
///
/// let mut pkt_ctx = PktContext::default();
/// pkt_ctx.psp_cfg.psp_encap = PspEncap::Transport;
/// derive_psp_key(&mut pkt_ctx);
/// let encap_pkt = psp_transport_encap(&mut pkt_ctx, &pkt)?;
/// #
/// #   Ok(())
/// # }
/// ```
/// # Errors
///
/// This function may encounter several types of errors.
/// Errors when trying to encapsulate the packet are returned as a `PspError::PacketEncapError`.
/// Errors when encrypting the packet are reurned as a `PspError::CryptoError`.
pub fn psp_transport_encap(pkt_ctx: &mut PktContext, in_pkt: &[u8]) -> Result<Vec<u8>, PspError> {
    let (in_eth, in_eth_payload) = Ethernet2Header::from_slice(in_pkt)?;
    match in_eth.ether_type {
        ether_type::IPV4 => (),
        ether_type::IPV6 => (),
        _ => {
            return Err(PspError::PacketEncapError(
                "Unsupported input packet type".to_string(),
            ))
        }
    }

    let (in_ip, next_protocol, in_ip_payload) = IpHeader::from_slice(in_eth_payload)?;

    let crypt_off = usize::from(pkt_ctx.psp_cfg.transport_crypt_off) * PSP_CRYPT_OFFSET_UNITS;
    let mut payload_crypt_off = crypt_off;
    let mut encrypted_vc = false;

    if pkt_ctx.psp_cfg.include_vc {
        if crypt_off >= PSP_VC_SIZE {
            payload_crypt_off -= PSP_VC_SIZE;
        } else {
            encrypted_vc = true;
            payload_crypt_off = 0;
        }
    }
    if crypt_off > in_ip_payload.len() {
        return Err(PspError::PacketEncapError(
            "Crypt offset too big".to_string(),
        ));
    }
    debug!("transport_encap: crypt_off: {crypt_off}");
    debug!("transport_encap: payload_crypt_off: {payload_crypt_off}");

    // Build the PSP encapsulated packet
    //   - copy the Ethernet and IP headers of the input packet.
    //   - insert the PSP UDP header
    //   - insert the PSP header
    //   - Copy crypt_off bytes from input packet starting at the L4 header
    //   - Compute ICV and insert encrypted data
    //   - Insert ICV as the PSP trailer

    let mut psp_encap_len = PspPacket::minimum_packet_size() + PSP_ICV_SIZE;
    if pkt_ctx.psp_cfg.include_vc {
        psp_encap_len += PSP_VC_SIZE;
    }
    let psp_udp_encap_len = psp_encap_len + UdpHeader::SERIALIZED_SIZE;
    let out_pkt_len = in_pkt.len() + psp_udp_encap_len;
    let mut out_pkt = Vec::<u8>::with_capacity(out_pkt_len);

    in_eth.write(&mut out_pkt)?;

    let mut out_ip = in_ip;
    out_ip.set_next_headers(ip_number::UDP);
    out_ip
        .set_payload_len(in_ip_payload.len() + psp_udp_encap_len)
        .map_err(|err| PspError::PacketEncapError(format!("{err}")))?;
    out_ip.write(&mut out_pkt)?;

    let out_udp = UdpHeader::without_ipv4_checksum(
        PSP_UDP_PORT,
        PSP_UDP_PORT,
        in_ip_payload.len() + psp_encap_len,
    )
    .map_err(|err| PspError::PacketEncapError(format!("{err}")))?;

    out_udp.write(&mut out_pkt)?;

    let mut flags = PspHeaderFlags::default();
    flags.set_version(get_psp_version(pkt_ctx.psp_cfg.crypto_alg) as u8);
    flags.set_v(pkt_ctx.psp_cfg.include_vc);

    let psp_hdr = &PspHeader {
        next_hdr: next_protocol,
        hdr_ext_len: match pkt_ctx.psp_cfg.include_vc {
            true => 2,
            false => 1,
        },
        crypt_off: pkt_ctx.psp_cfg.transport_crypt_off,
        flags,
        spi: pkt_ctx.psp_cfg.spi,
        iv: pkt_ctx.iv,
    };

    let start_of_psp_hdr = out_pkt.len();
    let encoder = bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding();
    let psp_buf = encoder.serialize(psp_hdr)?;
    out_pkt.extend_from_slice(&psp_buf);

    let end_of_iv = out_pkt.len();
    let start_of_crypto_region = end_of_iv + crypt_off;

    if flags.v() {
        out_pkt.extend_from_slice(&encoder.serialize(&pkt_ctx.vc)?);
    }
    let start_of_payload_region = out_pkt.len();

    let gcm_iv = get_aesgcm_iv(pkt_ctx.psp_cfg.spi, pkt_ctx.iv);
    pkt_ctx.iv += 1;

    out_pkt.extend_from_slice(&in_ip_payload[..payload_crypt_off]);
    out_pkt.resize(out_pkt_len, 0);
    let aad = out_pkt[start_of_psp_hdr..start_of_crypto_region].to_vec();

    if encrypted_vc {
        let mut cleartext: Vec<u8> = Vec::with_capacity(in_ip_payload.len() + PSP_VC_SIZE);
        cleartext.extend_from_slice(&out_pkt[start_of_crypto_region..start_of_payload_region]);
        cleartext.extend_from_slice(in_ip_payload);

        let ciphertext = &mut out_pkt[start_of_crypto_region..];

        psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &cleartext,
            ciphertext,
        )?;
    } else {
        // Simpler case, no need to copy
        let cleartext = &in_ip_payload[payload_crypt_off..];

        let ciphertext = &mut out_pkt[start_of_crypto_region..];

        psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            cleartext,
            ciphertext,
        )?;
    }

    Ok(out_pkt)
}

/// Encapsulate a packet in tunnel mode.
///
/// Input packet:
///     +---------+--------+---------+
///     | Eth Hdr | IP Hdr | Payload |
///     +---------+--------+---------+
///
/// Output packet:
///     +---------+--------+---------+---------+--------+---------+-------------+
///     | Eth Hdr | IP Hdr ] UDP Hdr | PSP Hdr | IP Hdr | Payload | PSP Trailer |
///     +---------+--------+---------+---------+--------+---------+-------------+
///
/// ```rust
/// # use psp_security::*;
/// # use etherparse::PacketBuilder;
/// # fn main() -> Result<(), PspError> {
/// let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
///     .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
///     .udp(21, 1234);
/// let payload = [1, 2, 3, 4, 5, 6, 7, 8];
/// let mut pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
/// builder.write(&mut pkt, &payload).unwrap();
///
/// let mut pkt_ctx = PktContext::default();
/// pkt_ctx.psp_cfg.psp_encap = PspEncap::Tunnel;
/// derive_psp_key(&mut pkt_ctx);
/// let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &pkt)?;
/// #
/// #   Ok(())
/// # }
/// ```
/// # Errors
///
/// This function may encounter several types of errors.
/// Errors when trying to encapsulate the packet are returned as a `PspError::PacketEncapError`.
/// Errors when encrypting the packet are reurned as a `PspError::CryptoError`.
pub fn psp_tunnel_encap(pkt_ctx: &mut PktContext, in_pkt: &[u8]) -> Result<Vec<u8>, PspError> {
    let (in_eth, in_eth_payload) = Ethernet2Header::from_slice(in_pkt)?;
    let (psp_next_protocol, tun_hdr_size) = match in_eth.ether_type {
        ether_type::IPV4 => (ip_number::IPV4, Ipv4Header::SERIALIZED_SIZE),
        ether_type::IPV6 => (ip_number::IPV6, Ipv6Header::SERIALIZED_SIZE),
        _ => {
            return Err(PspError::PacketEncapError(
                "Unsupported input packet type".to_string(),
            ))
        }
    };

    let psp_payload = in_eth_payload;
    let psp_payload_len = psp_payload.len();

    let (in_ip, _, _) = IpHeader::from_slice(in_eth_payload)?;

    let crypt_off_cfg_val = match psp_next_protocol {
        ip_number::IPV4 => usize::from(pkt_ctx.psp_cfg.ipv4_tunnel_crypt_off),
        ip_number::IPV6 => usize::from(pkt_ctx.psp_cfg.ipv6_tunnel_crypt_off),
        _ => 0,
    };
    let crypt_off = crypt_off_cfg_val * PSP_CRYPT_OFFSET_UNITS;
    let mut payload_crypt_off = crypt_off;
    let mut encrypted_vc = false;
    if pkt_ctx.psp_cfg.include_vc {
        if crypt_off >= PSP_VC_SIZE {
            payload_crypt_off -= PSP_VC_SIZE;
        } else {
            encrypted_vc = true;
        }
    }
    if payload_crypt_off > in_eth_payload.len() {
        return Err(PspError::PacketEncapError(
            "Crypto offset too big".to_string(),
        ));
    }

    // Build the PSP encapsulated packet
    //   - copy the Ethernet and IP headers of the input packet.
    //   - insert the outer ip header based on ip header of input packet.
    //   - insert the PSP UDP header
    //   - insert the PSP header
    //   - Copy crypt_off bytes from input packet starting at the IP header
    //   - Compute ICV and insert encrypted data
    //   - Insert ICV as the PSP trailer

    let mut psp_encap_len = PspPacket::minimum_packet_size() + PSP_ICV_SIZE;
    if pkt_ctx.psp_cfg.include_vc {
        psp_encap_len += PSP_VC_SIZE;
    }
    let psp_udp_encap_len = psp_encap_len + UdpHeader::SERIALIZED_SIZE;
    let psp_udp_ip_encap_len = psp_udp_encap_len + tun_hdr_size;
    let out_pkt_len = in_pkt.len() + psp_udp_ip_encap_len;
    let mut out_pkt = Vec::<u8>::with_capacity(out_pkt_len);

    in_eth.write(&mut out_pkt)?;

    let mut out_ip = in_ip;
    out_ip.set_next_headers(ip_number::UDP);
    out_ip
        .set_payload_len(psp_payload_len + psp_udp_encap_len)
        .map_err(|err| PspError::PacketEncapError(format!("{err}")))?;
    out_ip.write(&mut out_pkt)?;

    let out_udp = UdpHeader::without_ipv4_checksum(
        PSP_UDP_PORT,
        PSP_UDP_PORT,
        psp_payload_len + psp_encap_len,
    )
    .map_err(|err| PspError::PacketEncapError(format!("{err}")))?;

    out_udp.write(&mut out_pkt)?;

    let mut flags = PspHeaderFlags::default();
    flags.set_version(get_psp_version(pkt_ctx.psp_cfg.crypto_alg) as u8);
    flags.set_v(pkt_ctx.psp_cfg.include_vc);

    let psp_hdr = &PspHeader {
        next_hdr: psp_next_protocol,
        hdr_ext_len: match pkt_ctx.psp_cfg.include_vc {
            true => 2,
            false => 1,
        },
        crypt_off: crypt_off_cfg_val as u8,
        flags,
        spi: pkt_ctx.psp_cfg.spi,
        iv: pkt_ctx.iv,
    };

    let start_of_psp_hdr = out_pkt.len();

    let encoder = bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding();
    let psp_buf = encoder.serialize(psp_hdr)?;
    out_pkt.extend_from_slice(&psp_buf);

    let end_of_iv = out_pkt.len();
    let start_of_crypto_region = end_of_iv + crypt_off;

    if flags.v() {
        out_pkt.extend_from_slice(&encoder.serialize(&pkt_ctx.vc)?);
    }

    let start_of_payload_region = out_pkt.len();

    let gcm_iv = get_aesgcm_iv(pkt_ctx.psp_cfg.spi, pkt_ctx.iv);
    pkt_ctx.iv += 1;

    out_pkt.extend_from_slice(&psp_payload[..payload_crypt_off]);
    out_pkt.resize(out_pkt_len, 0);
    let aad = out_pkt[start_of_psp_hdr..start_of_crypto_region].to_vec();

    if encrypted_vc {
        let mut cleartext: Vec<u8> = Vec::with_capacity(psp_payload.len() + PSP_VC_SIZE);
        cleartext.extend_from_slice(&out_pkt[start_of_crypto_region..start_of_payload_region]);
        cleartext.extend_from_slice(psp_payload);

        let ciphertext = &mut out_pkt[start_of_crypto_region..];

        psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &cleartext,
            ciphertext,
        )?;
    } else {
        // Simpler case, no need to copy
        let cleartext = &psp_payload[payload_crypt_off..];

        let ciphertext = &mut out_pkt[start_of_crypto_region..];

        psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            cleartext,
            ciphertext,
        )?;
    }

    Ok(out_pkt)
}

/// Decapsulate a PSP packet.
/// If the PSP header Next Header field indicates an IPv4 or IPv6 header, tunnel mode decapsulation
/// will be used, otherwise, transport mode decapsulation will be used.
pub fn psp_decap(pkt_ctx: &mut PktContext, in_pkt: &[u8]) -> Result<Vec<u8>, PspError> {
    let parsed_pkt = PacketHeaders::from_ethernet_slice(in_pkt)?;
    match parsed_pkt.transport {
        None => Err(PspError::PacketDecapError("No UDP header".to_string())),
        _ => Ok(()),
    }?;

    let psp_buf = parsed_pkt.payload;

    let in_psp = PspPacket::new(psp_buf).ok_or(PspError::PacketDecapError(
        "Error parsing PSP header".to_string(),
    ))?;

    match in_psp.get_next_hdr() {
        ip_number::IPV4 | ip_number::IPV6 => psp_tunnel_decap(pkt_ctx, in_pkt),
        _ => psp_transport_decap(pkt_ctx, in_pkt),
    }
}

/// Decapsulate a PSP transport mode packet.
///
/// Input packet:
///     +---------+--------+---------+---------+---------+-------------+
///     | Eth Hdr | IP Hdr ] UDP Hdr | PSP Hdr | Payload | PSP Trailer |
///     +---------+--------+---------+---------+---------+-------------+
///
/// Output packet:
///     +---------+--------+---------+
///     | Eth Hdr | IP Hdr | Payload |
///     +---------+--------+---------+
///
/// ```rust
/// # use psp_security::*;
/// # use etherparse::PacketBuilder;
/// # fn main() -> Result<(), PspError> {
/// let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
///     .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
///     .udp(21, 1234);
/// let payload = [1, 2, 3, 4, 5, 6, 7, 8];
/// let mut pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
/// builder.write(&mut pkt, &payload).unwrap();
///
/// let mut pkt_ctx = PktContext::default();
/// pkt_ctx.psp_cfg.psp_encap = PspEncap::Transport;
/// let mut decrypt_pkt_ctx = pkt_ctx.clone();
///
/// derive_psp_key(&mut pkt_ctx);
/// let encap_pkt = psp_transport_encap(&mut pkt_ctx, &pkt)?;
/// let decap_pkt = psp_transport_decap(&mut decrypt_pkt_ctx, &encap_pkt)?;
/// #
/// #   Ok(())
/// # }
/// ```
/// # Errors
///
/// This function may encounter several types of errors.
/// Errors when trying to encapsulate the packet are returned as a `PspError::PacketDecapError`.
/// Errors when encrypting the packet are reurned as a `PspError::CryptoError`.
pub fn psp_transport_decap(pkt_ctx: &mut PktContext, in_pkt: &[u8]) -> Result<Vec<u8>, PspError> {
    let parsed_pkt = PacketHeaders::from_ethernet_slice(in_pkt)?;
    match parsed_pkt.transport {
        None => Err(PspError::PacketDecapError("No UDP header".to_string())),
        _ => Ok(()),
    }?;

    let psp_buf = parsed_pkt.payload;

    let in_psp = PspPacket::new(psp_buf).ok_or(PspError::PacketDecapError(
        "Error parsing PSP header".to_string(),
    ))?;

    let payload = in_psp.payload();
    if payload.len() < PSP_ICV_SIZE {
        return Err(PspError::InvalidPspPacketSize);
    }

    let crypt_off = usize::from(in_psp.get_crypt_offset()) * PSP_CRYPT_OFFSET_UNITS;
    debug!("transport_decap: crypt_off: {crypt_off}");
    let mut payload_crypt_off = crypt_off;
    if in_psp.get_v() == 1 {
        if crypt_off >= PSP_VC_SIZE {
            payload_crypt_off -= PSP_VC_SIZE;
        } else {
            payload_crypt_off = 0;
        }
    }
    if payload_crypt_off > payload.len() {
        return Err(PspError::PacketDecapError(
            "Invalid crypto offset".to_string(),
        ));
    }

    // Build the PSP deencapsulated packet
    //   - copy the Ethernet and IP headers of the input packet.
    //   - Skip the PSP UDP header
    //   - Skip the PSP header
    //   - Copy crypt_off bytes from input packet starting at the L4 header

    let vc_len = match in_psp.get_v() {
        0 => 0,
        _ => PSP_VC_SIZE,
    };
    let psp_encap_len = PspPacket::minimum_packet_size() + vc_len + PSP_ICV_SIZE;
    let psp_and_udp_encap_len = UdpHeader::SERIALIZED_SIZE + psp_encap_len;
    let out_pkt_len = in_pkt.len() - psp_and_udp_encap_len;
    let mut out_pkt = Vec::<u8>::with_capacity(out_pkt_len);

    if let Some(eth) = parsed_pkt.link {
        eth.write(&mut out_pkt)?;
    }
    if let Some(ip) = parsed_pkt.ip {
        let mut out_ip = ip;
        let out_ip_len = parsed_pkt.payload.len() - psp_encap_len;
        out_ip
            .set_payload_len(out_ip_len)
            .map_err(|err| PspError::PacketDecapError(format!("{err}")))?;
        out_ip.set_next_headers(in_psp.get_next_hdr());
        out_ip.write(&mut out_pkt)?;
    }

    pkt_ctx.psp_cfg.crypto_alg = get_psp_crypto_alg(in_psp.get_version().try_into()?);

    let aad_len: usize = usize::from(PSP_HDR_FIXED_LEN) + crypt_off;
    let aad = parsed_pkt.payload[..aad_len].to_vec();

    let spi = in_psp.get_spi();
    pkt_ctx.psp_cfg.spi = spi;
    let gcm_iv = get_aesgcm_iv(spi, in_psp.get_iv());

    derive_psp_key(pkt_ctx);

    let ciphertext = &parsed_pkt.payload[aad_len..];
    out_pkt.extend_from_slice(&in_psp.payload()[..payload_crypt_off]);

    let start_of_decrypt_region = out_pkt.len();
    out_pkt.resize(out_pkt_len, 0);
    let cleartext = &mut out_pkt[start_of_decrypt_region..];

    psp_decrypt(
        pkt_ctx.psp_cfg.crypto_alg,
        &pkt_ctx.key,
        &gcm_iv,
        &aad,
        ciphertext,
        cleartext,
    )?;

    Ok(out_pkt)
}

/// Decapsulate a PSP tunnel mode packet.
///
/// Input packet:
///     +---------+--------+---------+---------+--------+---------+-------------+
///     | Eth Hdr | IP Hdr ] UDP Hdr | PSP Hdr | IP Hdr | Payload | PSP Trailer |
///     +---------+--------+---------+---------+--------+---------+-------------+
///
/// Output packet:
///     +---------+--------+---------+
///     | Eth Hdr | IP Hdr | Payload |
///     +---------+--------+---------+
///
/// ```rust
/// # use psp_security::*;
/// # use etherparse::PacketBuilder;
/// # fn main() -> Result<(), PspError> {
/// let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
///     .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
///     .udp(21, 1234);
/// let payload = [1, 2, 3, 4, 5, 6, 7, 8];
/// let mut pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
/// builder.write(&mut pkt, &payload).unwrap();
///
/// let mut pkt_ctx = PktContext::default();
/// pkt_ctx.psp_cfg.psp_encap = PspEncap::Tunnel;
/// let mut decrypt_pkt_ctx = pkt_ctx.clone();
///
/// derive_psp_key(&mut pkt_ctx);
/// let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &pkt)?;
/// let decap_pkt = psp_tunnel_decap(&mut decrypt_pkt_ctx, &encap_pkt)?;
/// #
/// #   Ok(())
/// # }
/// ```
/// # Errors
///
/// This function may encounter several types of errors.
/// Errors when trying to encapsulate the packet are returned as a `PspError::PacketDecapError`.
/// Errors when encrypting the packet are reurned as a `PspError::CryptoError`.
pub fn psp_tunnel_decap(pkt_ctx: &mut PktContext, in_pkt: &[u8]) -> Result<Vec<u8>, PspError> {
    let parsed_pkt = PacketHeaders::from_ethernet_slice(in_pkt)?;

    let eth = parsed_pkt.link.ok_or(PspError::PacketDecapError(
        "Unsupported packet type".to_string(),
    ))?;

    let ip_hdr = parsed_pkt.ip.ok_or(PspError::PacketDecapError(
        "Unsupported packet type".to_string(),
    ))?;
    let ip_hdr_size = ip_hdr.header_len();

    match parsed_pkt.transport {
        Some(TransportHeader::Udp(_)) => Ok(()),
        _ => Err(PspError::PacketDecapError("No UDP header".to_string())),
    }?;

    let psp_buf = parsed_pkt.payload;
    let in_psp = PspPacket::new(psp_buf).ok_or(PspError::PacketDecapError(
        "Error parsing PSP header".to_string(),
    ))?;

    let payload = in_psp.payload();
    if payload.len() < PSP_ICV_SIZE {
        return Err(PspError::InvalidPspPacketSize);
    }

    let crypt_off = usize::from(in_psp.get_crypt_offset()) * PSP_CRYPT_OFFSET_UNITS;
    let mut payload_crypt_off = crypt_off;
    if in_psp.get_v() == 1 {
        if crypt_off >= PSP_VC_SIZE {
            payload_crypt_off -= PSP_VC_SIZE;
        } else {
            payload_crypt_off = 0;
        }
    }
    if payload_crypt_off > payload.len() {
        return Err(PspError::PacketDecapError(
            "Invalid crypto offset".to_string(),
        ));
    }

    // Build the PSP deencapsulated packet
    //   - copy the Ethernet header of the input packet.
    //   - Skip the outer IP header
    //   - Skip the PSP UDP header
    //   - Skip the PSP header
    //   - Copy crypt_off bytes from input packet starting at the L4 header
    //   - Decrypt the remainder of the input packet and write the decrypted content to the output
    //     packet.

    let vc_len = match in_psp.get_v() {
        0 => 0,
        _ => PSP_VC_SIZE,
    };
    let psp_encap_len = PspPacket::minimum_packet_size() + vc_len + PSP_ICV_SIZE;
    let psp_udp_encap_len = UdpHeader::SERIALIZED_SIZE + psp_encap_len;
    let psp_udp_ip_encap_len = ip_hdr_size + psp_udp_encap_len;
    let out_pkt_len = in_pkt.len() - psp_udp_ip_encap_len;
    let mut out_pkt = Vec::<u8>::with_capacity(out_pkt_len);

    eth.write(&mut out_pkt)?;

    pkt_ctx.psp_cfg.crypto_alg = get_psp_crypto_alg(in_psp.get_version().try_into()?);

    // crypt_off already incorporates vc len
    let aad_len: usize = usize::from(PSP_HDR_FIXED_LEN) + crypt_off;
    let aad = parsed_pkt.payload[..aad_len].to_vec();

    let spi = in_psp.get_spi();
    pkt_ctx.psp_cfg.spi = spi;
    let gcm_iv = get_aesgcm_iv(spi, in_psp.get_iv());

    derive_psp_key(pkt_ctx);

    let ciphertext = &parsed_pkt.payload[aad_len..];
    out_pkt.extend_from_slice(&in_psp.payload()[..payload_crypt_off]);

    let start_of_decrypt_region = out_pkt.len();
    out_pkt.resize(out_pkt_len, 0);
    let cleartext = &mut out_pkt[start_of_decrypt_region..];

    psp_decrypt(
        pkt_ctx.psp_cfg.crypto_alg,
        &pkt_ctx.key,
        &gcm_iv,
        &aad,
        ciphertext,
        cleartext,
    )?;

    Ok(out_pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::psp::PspPacket;
    use etherparse::{EtherType, IpNumber, PacketBuilder, TransportHeader};

    #[test]
    fn test_psp_version_try_from() {
        assert!(PspVersion::try_from(0).is_ok());
        assert!(PspVersion::try_from(1).is_ok());
        assert!(PspVersion::try_from(2).is_err());
    }

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
        assert_eq!(hdr.flags.0, 0x01u8);
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
        derive_psp_key(&mut pkt_ctx);
        assert_eq!(pkt_ctx.key.len(), 16);
        assert_eq!(pkt_ctx.key, expected);

        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm256;
        let expected: [u8; 32] = [
            0x2b, 0x7d, 0x72, 0x07, 0x4e, 0x42, 0xca, 0x33, 0x44, 0x87, 0xf2, 0x99, 0x0e, 0x3f,
            0x8c, 0x40, 0x37, 0xe4, 0x36, 0xf3, 0x82, 0x83, 0x44, 0x9b, 0x76, 0x46, 0x3e, 0x9b,
            0x7f, 0xb2, 0xe3, 0xde,
        ];
        derive_psp_key(&mut pkt_ctx);
        assert_eq!(pkt_ctx.key.len(), 32);
        assert_eq!(pkt_ctx.key, expected);
    }

    #[test]
    fn test_psp_encrypt() -> Result<(), Box<dyn std::error::Error>> {
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
        let aad = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(&psp_hdr)?;

        let gcm_iv = get_aesgcm_iv(psp_hdr.spi, psp_hdr.iv);

        let cleartext = vec![0u8; 256];
        let mut ciphertext = vec![0u8; 256 + PSP_ICV_SIZE];

        let res = psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &cleartext,
            &mut ciphertext,
        );
        assert!(res.is_ok());
        assert_ne!(ciphertext, cleartext);

        Ok(())
    }

    #[test]
    fn check_transport_encap() -> Result<(), Box<dyn std::error::Error>> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut in_pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut in_pkt, &payload)?;

        let out_pkt_len = in_pkt.len()
            + UdpHeader::SERIALIZED_SIZE
            + PspPacket::minimum_packet_size()
            + PSP_ICV_SIZE;
        let mut pkt_ctx = PktContext::default();
        pkt_ctx.psp_cfg.spi = 1;
        pkt_ctx.psp_cfg.transport_crypt_off = 1;

        let out_pkt = psp_transport_encap(&mut pkt_ctx, &in_pkt)?;
        assert_eq!(out_pkt_len, out_pkt.len());

        let pkt = PacketHeaders::from_ethernet_slice(&out_pkt)?;
        assert!(pkt.link.is_some());
        assert_eq!(pkt.link.unwrap().ether_type, EtherType::Ipv4 as u16);
        assert!(pkt.ip.is_some());
        match pkt.ip.unwrap() {
            IpHeader::Version4(ip, _) => {
                assert_eq!(ip.source, [192, 168, 1, 1]);
                assert_eq!(ip.destination, [192, 168, 1, 2]);
                assert_eq!(ip.protocol, IpNumber::Udp as u8);
            }
            _ => assert!(false),
        };
        assert!(pkt.transport.is_some());
        match pkt.transport.unwrap() {
            TransportHeader::Udp(udp) => {
                assert_eq!(udp.destination_port, PSP_UDP_PORT);
            }
            _ => assert!(false),
        }
        let psp = PspPacket::new(pkt.payload).unwrap();
        assert_eq!(psp.get_spi(), pkt_ctx.psp_cfg.spi);
        assert_eq!(psp.get_version(), PspVersion::PspVer0 as u8);

        Ok(())
    }

    #[test]
    fn check_transport_vc_encap() -> Result<(), Box<dyn std::error::Error>> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut in_pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut in_pkt, &payload)?;

        let out_pkt_len = in_pkt.len()
            + UdpHeader::SERIALIZED_SIZE
            + PspPacket::minimum_packet_size()
            + PSP_VC_SIZE
            + PSP_ICV_SIZE;
        let mut pkt_ctx = PktContext::default();
        pkt_ctx.psp_cfg.spi = 1;
        pkt_ctx.psp_cfg.include_vc = true;
        pkt_ctx.vc = 0xCAFE;
        pkt_ctx.psp_cfg.transport_crypt_off = 4;

        let out_pkt = psp_transport_encap(&mut pkt_ctx, &in_pkt)?;
        assert_eq!(out_pkt_len, out_pkt.len());

        let pkt = PacketHeaders::from_ethernet_slice(&out_pkt)?;
        assert!(pkt.link.is_some());
        assert_eq!(pkt.link.unwrap().ether_type, EtherType::Ipv4 as u16);
        assert!(pkt.ip.is_some());
        match pkt.ip.unwrap() {
            IpHeader::Version4(ip, _) => {
                assert_eq!(ip.source, [192, 168, 1, 1]);
                assert_eq!(ip.destination, [192, 168, 1, 2]);
                assert_eq!(ip.protocol, IpNumber::Udp as u8);
            }
            _ => assert!(false),
        };
        assert!(pkt.transport.is_some());
        match pkt.transport.unwrap() {
            TransportHeader::Udp(udp) => {
                assert_eq!(udp.destination_port, PSP_UDP_PORT);
            }
            _ => assert!(false),
        }
        let psp = PspPacket::new(pkt.payload).unwrap();
        assert_eq!(psp.get_spi(), pkt_ctx.psp_cfg.spi);
        assert_eq!(psp.get_version(), PspVersion::PspVer0 as u8);
        assert_eq!(psp.get_v(), 1);
        assert_eq!(psp.get_vc(), vec![0xCAFE]);

        Ok(())
    }

    fn get_pkt_ctx(ver: PspVersion) -> PktContext {
        let mut pkt_ctx = PktContext::new();
        match ver {
            PspVersion::PspVer0 => {
                pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm128;
                pkt_ctx.key = vec![
                    0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90, 0xb7, 0x4b, 0x70, 0xae, 0x46,
                    0x8e, 0x4e, 0x30,
                ];
                pkt_ctx.iv = 0x12345678_9ABCDEFF;
                pkt_ctx.psp_cfg.spi = 0x12345678;
                pkt_ctx.psp_cfg.transport_crypt_off = 1;
                pkt_ctx.psp_cfg.ipv4_tunnel_crypt_off = 6;
                pkt_ctx.psp_cfg.ipv6_tunnel_crypt_off = 11;
            }
            PspVersion::PspVer1 => {
                pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm256;
                pkt_ctx.key = vec![
                    0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90, 0xb7, 0x4b, 0x70, 0xae, 0x46,
                    0x8e, 0x4e, 0x30, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                ];
                pkt_ctx.iv = 0x12345678_9ABCDEFF;
                pkt_ctx.psp_cfg.spi = 0x82345678;
            }
        }
        pkt_ctx
    }

    fn get_ipv4_test_pkt() -> Vec<u8> {
        // Build a cleartext packet
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut orig_pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut orig_pkt, &payload).unwrap();
        orig_pkt
    }

    fn get_ipv4_empty_test_pkt() -> Vec<u8> {
        // Build a cleartext packet
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 32)
            .udp(21, 1234);
        let payload = [0u8; 0];
        let mut orig_pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut orig_pkt, &payload).unwrap();
        orig_pkt
    }

    fn get_ipv6_test_pkt() -> Vec<u8> {
        // Build a cleartext packet
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6(
                [
                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                ],
                [
                    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
                ],
                32,
            )
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut orig_pkt = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut orig_pkt, &payload).unwrap();
        orig_pkt
    }

    #[test]
    fn test_pspv0_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);

        let mut psp_hdr = PspHeader::default();
        psp_hdr.next_hdr = 6;
        psp_hdr.spi = pkt_ctx.psp_cfg.spi;
        psp_hdr.iv = pkt_ctx.iv;
        let aad = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(&psp_hdr)?;

        derive_psp_key(&mut pkt_ctx);
        let gcm_iv = get_aesgcm_iv(pkt_ctx.psp_cfg.spi, pkt_ctx.iv);

        let cleartext = vec![0u8; 256];
        let mut ciphertext = vec![0u8; cleartext.len() + PSP_ICV_SIZE];

        let rc = psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &cleartext,
            &mut ciphertext,
        );
        assert!(rc.is_ok());
        let mut decrypted = vec![1u8; cleartext.len()];
        let rc = psp_decrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &ciphertext,
            &mut decrypted,
        );
        assert!(rc.is_ok());
        assert_eq!(cleartext.len(), decrypted.len());
        assert_eq!(cleartext, decrypted);

        Ok(())
    }

    #[test]
    fn test_pspv1_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);

        let mut psp_hdr = PspHeader::default();
        psp_hdr.next_hdr = 6;
        psp_hdr.spi = pkt_ctx.psp_cfg.spi;
        psp_hdr.iv = pkt_ctx.iv;
        let aad = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(&psp_hdr)?;

        derive_psp_key(&mut pkt_ctx);
        let gcm_iv = get_aesgcm_iv(pkt_ctx.psp_cfg.spi, pkt_ctx.iv);

        let cleartext = vec![0u8; 256];
        let mut ciphertext = vec![0u8; cleartext.len() + PSP_ICV_SIZE];

        let rc = psp_encrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &cleartext,
            &mut ciphertext,
        );
        assert!(rc.is_ok());
        let mut decrypted = vec![1u8; cleartext.len()];
        let rc = psp_decrypt(
            pkt_ctx.psp_cfg.crypto_alg,
            &pkt_ctx.key,
            &gcm_iv,
            &aad,
            &ciphertext,
            &mut decrypted,
        );
        assert!(rc.is_ok());
        assert_eq!(cleartext.len(), decrypted.len());
        assert_eq!(cleartext, decrypted);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_transport_encap_decap_ipv4() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_transport_encap_decap_crypt_off() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        pkt_ctx.psp_cfg.transport_crypt_off = 1;
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_transport_encap_decap_ipv4() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_transport_encap_decap_ipv6() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_transport_encap_decap_ipv6() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_tunnel_encap_decap_ipv4() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_tunnel_encap_decap_crypt_off() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        pkt_ctx.psp_cfg.ipv4_tunnel_crypt_off = 2;
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_tunnel_encap_decap_ipv4() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv0_tunnel_encap_decap_ipv6() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_tunnel_encap_decap_ipv6() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_tunnel_encap_decap_ipv6_vc() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        pkt_ctx.psp_cfg.include_vc = true;
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_tunnel_encap_decap_ipv6_vc_no_co() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        pkt_ctx.psp_cfg.include_vc = true;
        pkt_ctx.psp_cfg.ipv6_tunnel_crypt_off = 0;
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_tunnel_encap_decap_ipv6_vc_partial_enc() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer0);
        pkt_ctx.psp_cfg.include_vc = true;
        pkt_ctx.psp_cfg.ipv6_tunnel_crypt_off = 1;
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv6_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_transport_ipv4_empty() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_empty_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_transport_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_transport_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }

    #[test_log::test]
    fn test_pspv1_tunnel_ipv4_empty() -> Result<(), PspError> {
        let mut pkt_ctx = get_pkt_ctx(PspVersion::PspVer1);
        let mut decap_pkt_ctx = pkt_ctx.clone();
        let orig_pkt = get_ipv4_empty_test_pkt();

        derive_psp_key(&mut pkt_ctx);

        let encap_pkt = psp_tunnel_encap(&mut pkt_ctx, &orig_pkt)?;
        let decap_pkt = psp_tunnel_decap(&mut decap_pkt_ctx, &encap_pkt)?;
        assert_eq!(orig_pkt, decap_pkt);

        Ok(())
    }
}
