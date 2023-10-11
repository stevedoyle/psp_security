use aes::Aes256;
use crypto_common::InvalidLength;
use cmac::{Cmac, Mac};
use std::error::Error;

const PSP_ICV_SIZE: usize = 16;
const PSP_MASTER_KEY_SIZE: usize = 32;
const PSP_DERIVED_KEY_SIZE: usize = 32;
const PSP_SPI_KEY_SELECTOR_BIT: u32 = 1 << 31;

enum PspVersion {
    PspVer0, // AES-GCM-128
    PspVer1, // AES-GCM-256
    PspVer2, // AES-GMAC-128
    PspVer3, // AES-GMAC-256
}

enum PspEncap {
    TRANSPORT,
    TUNNEL,
}

#[derive(PartialEq)]
enum CryptoAlg {
    AesGcm128,
    AesGcm256,
}

struct PspHeader {
    next_hdr: u8,
    hdr_ext_len: u8,
    crypt_off: u8,
    s_d_ver_v_1: u8,
    spi: u32,
    iv: u64,
}

struct PspTrailer {
    icv: [u8; PSP_ICV_SIZE],
}

type PspMasterKey = [u8; PSP_MASTER_KEY_SIZE];

struct PspDerivedKey {
    size: usize,
    value: [u8; PSP_DERIVED_KEY_SIZE],
}

struct PspEncryptConfig {
    master_key0: PspMasterKey,
    master_key1: PspMasterKey,
    spi: u32,
    psp_encap: PspEncap,
    crypto_alg: CryptoAlg,
    transport_crypt_off: u8,
    ipv4_tunnel_crypt_off: u8,
    ipv6_tunnel_crypt_off: u8,
    include_vc: bool,
}

struct PktContext {
    max_pkt_octets: u32,
    psp_cfg: PspEncryptConfig,
    key: PspDerivedKey,
    next_iv: u64,
    //TODO: in_pcap_pkt_hdr
//    in_pkt: &'a[u8],
    eth_hdr_len: u32,
    //TODO: out_pcap_pkt_hdr
//    out_pkt: &'a[u8],
//    scratch_buf: &'a[u8],
}

impl PktContext {
    fn new() -> PktContext {
        PktContext {
            max_pkt_octets: 1024,
            psp_cfg: PspEncryptConfig {
                master_key0: [0; 32],
                master_key1: [0; 32],
                spi: 1,
                psp_encap: PspEncap::TRANSPORT,
                crypto_alg: CryptoAlg::AesGcm128,
                transport_crypt_off: 0,
                ipv4_tunnel_crypt_off: 0,
                ipv6_tunnel_crypt_off: 0,
                include_vc: false },
            key: PspDerivedKey { size: 16, value: [0; 32] },
            next_iv: 1,
            eth_hdr_len: 18
        }
    }
}

fn select_master_key<'a>(spi: u32, key0: &'a PspMasterKey, key1: &'a PspMasterKey) -> &'a PspMasterKey {
    if (spi >> 31) & 0x01 == 0 {
        return key0;
    }
    key1
}

fn derive_psp_key_128(pkt_ctx: &PktContext, counter: u8, derived_key: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let spi = pkt_ctx.psp_cfg.spi;

    let mut input_block: [u8; 16] = [0; 16];
    input_block[3] = counter;
    input_block[4] = 0x50;
    input_block[5] = 0x76;

    match pkt_ctx.psp_cfg.crypto_alg {
        CryptoAlg::AesGcm128 => {
            input_block[6] = 0x30;
            input_block[15] = 0x80;
        },
        CryptoAlg::AesGcm256 => {
            input_block[6] = 0x31;
            input_block[14] = 0x01;
            input_block[15] = 0x00;
        },
    }

    input_block[8] = ((spi >> 24) & 0xff) as u8;
    input_block[9] = ((spi >> 16) & 0xff) as u8;
    input_block[10] = ((spi >> 8) & 0xff) as u8;
    input_block[11] = (spi & 0xff) as u8;

    let key = select_master_key(
        spi,
        &pkt_ctx.psp_cfg.master_key0,
        &pkt_ctx.psp_cfg.master_key1);

    let mut mac = Cmac::<Aes256>::new(key.into());
    mac.update(&input_block);
    let result = mac.finalize();
    derived_key.copy_from_slice(&result.into_bytes());

    Ok(())
}

fn derive_psp_key(pkt_ctx: &mut PktContext) -> Result<(), Box<dyn Error>> {
    let mut key = [0; 32];

    derive_psp_key_128(pkt_ctx, 1, &mut key[0..16])?;
    if pkt_ctx.psp_cfg.crypto_alg == CryptoAlg::AesGcm128 {
        pkt_ctx.key.size = 16;
        pkt_ctx.key.value = key;
        return Ok(());
    }
    derive_psp_key_128(pkt_ctx, 2, &mut key[16..])?;
    pkt_ctx.key.size = 32;
    pkt_ctx.key.value = key;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_psp_key_128() {
        let mut derived_key: [u8; 16] = [0; 16];
        let mut pkt_ctx = PktContext::new();
        pkt_ctx.psp_cfg.master_key0 = [
            0x34, 0x44, 0x8A, 0x06, 0x42, 0x92, 0x60, 0x1B,
            0x11, 0xA0, 0x97, 0x8F, 0x56, 0xA2, 0xd3, 0x4c,
            0xf3, 0xfc, 0x35, 0xed, 0xe1, 0xa6, 0xbc, 0x04,
            0xf8, 0xdb, 0x3e, 0x52, 0x43, 0xa2, 0xb0, 0xca,
        ];
        pkt_ctx.psp_cfg.master_key1 = [
            0x56, 0x39, 0x52, 0x56, 0x5d, 0x3a, 0x78, 0xae,
            0x77, 0x3e, 0xc1, 0xb7, 0x79, 0xf2, 0xf2, 0xd9,
            0x9f, 0x4a, 0x7f, 0x53, 0xa6, 0xfb, 0xb9, 0xb0,
            0x7d, 0x5b, 0x71, 0xf3, 0x93, 0x64, 0xd7, 0x39,
        ];

        pkt_ctx.psp_cfg.spi = 0x12345678;
        let expected: [u8; 16] = [
            0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90,
            0xb7, 0x4b, 0x70, 0xae, 0x46, 0x8e, 0x4e, 0x30];

        assert!(derive_psp_key_128(&pkt_ctx, 1, &mut derived_key).is_ok());
        assert_eq!(expected, derived_key);

        pkt_ctx.psp_cfg.spi = 0x9A345678;
        let expected: [u8; 16] = [
            0x39, 0x46, 0xda, 0x25, 0x54, 0xea, 0xe4, 0x6a,
            0xd1, 0xef, 0x77, 0xa6, 0x43, 0x72, 0xed, 0xc4];

        assert!(derive_psp_key_128(&pkt_ctx, 1, &mut derived_key).is_ok());
        assert_eq!(expected, derived_key);
    }

    #[test]
    fn test_derive_psp_key() {
        let mut pkt_ctx = PktContext::new();
        pkt_ctx.psp_cfg.master_key0 = [
            0x34, 0x44, 0x8A, 0x06, 0x42, 0x92, 0x60, 0x1B,
            0x11, 0xA0, 0x97, 0x8F, 0x56, 0xA2, 0xd3, 0x4c,
            0xf3, 0xfc, 0x35, 0xed, 0xe1, 0xa6, 0xbc, 0x04,
            0xf8, 0xdb, 0x3e, 0x52, 0x43, 0xa2, 0xb0, 0xca,
        ];
        pkt_ctx.psp_cfg.spi = 0x12345678;

        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm128;
        let expected: [u8; 16] = [
            0x96, 0xc2, 0x2d, 0xc7, 0x99, 0x19, 0x80, 0x90,
            0xb7, 0x4b, 0x70, 0xae, 0x46, 0x8e, 0x4e, 0x30];
        assert!(derive_psp_key(&mut pkt_ctx).is_ok());
        assert_eq!(pkt_ctx.key.size, 16);
        assert_eq!(pkt_ctx.key.value[0..16], expected);

        pkt_ctx.psp_cfg.crypto_alg = CryptoAlg::AesGcm256;
        let expected: [u8; 32] = [
            0x2b, 0x7d, 0x72, 0x07, 0x4e, 0x42, 0xca, 0x33,
            0x44, 0x87, 0xf2, 0x99, 0x0e, 0x3f, 0x8c, 0x40,
            0x37, 0xe4, 0x36, 0xf3, 0x82, 0x83, 0x44, 0x9b,
            0x76, 0x46, 0x3e, 0x9b, 0x7f, 0xb2, 0xe3, 0xde];
        assert!(derive_psp_key(&mut pkt_ctx).is_ok());
        assert_eq!(pkt_ctx.key.size, 32);
        assert_eq!(pkt_ctx.key.value, expected);
    }
}
