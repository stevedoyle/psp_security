use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Represents a PSP Packet.
#[packet]
pub struct Psp {
    pub next_hdr: u8,
    pub hdr_ext_len: u8,
    _r: u2,
    pub crypt_offset: u6,
    pub s: u1,
    pub d: u1,
    pub version: u4,
    pub vc: u1,
    pub always1: u1,
    pub spi: u32be,
    pub iv: u64be,
    #[payload]
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_macros_support::packet::Packet;

    #[test]
    fn psp_header_test() {
        let buf = vec![
            0x11, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let psp = PspPacket::new(&buf).unwrap();
        assert_eq!(psp.get_next_hdr(), 0x11);
        assert_eq!(psp.get_hdr_ext_len(), 1);
        assert_eq!(psp.get_crypt_offset(), 1);
        assert_eq!(psp.get_version(), 0);
        assert_eq!(psp.get_s(), 0);
        assert_eq!(psp.get_d(), 0);
        assert_eq!(psp.get_vc(), 0);
        assert_eq!(psp.get_spi(), 3);
        assert_eq!(psp.get_iv(), 0x0102030405060708);
        assert_eq!(psp.payload().len(), 24);
        assert_eq!(psp.packet().len(), 40);
    }
}
