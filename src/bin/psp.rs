use std::{
    cmp::min,
    error::Error,
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr},
    num::Wrapping,
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;

use clap::{Args, Parser, Subcommand, ValueEnum};
use log::{debug, info};
use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};
use pnet::{packet::ethernet::EtherTypes, util::MacAddr};
use pnet_packet::{
    ethernet::MutableEthernetPacket,
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, MutableIpv4Packet},
    ipv6::MutableIpv6Packet,
    udp::MutableUdpPacket,
    MutablePacket,
};
use psp_security::{
    derive_psp_key, psp_transport_decap, psp_transport_encap, psp_tunnel_decap, psp_tunnel_encap,
    CryptoAlg, PktContext, PspConfig, PspEncap, PspError, PspMasterKey,
};
use rand::{thread_rng, RngCore};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IPVersion {
    Ipv4,
    Ipv6,
}

// #[derive(Debug, Default, Serialize, Deserialize)]
// struct PspConfig {
//     master_keys: [PspMasterKey; 2],
//     spi: u32,
//     mode: PspEncap,
//     algo: CryptoAlg,
//     crypto_offset: u32,
//     include_vc: bool,
// }

#[derive(Parser)]
#[command(name = "psp")]
#[command(bin_name = "psp")]
#[command(version)]
enum PspCliCommands {
    /// Create files that are useful for testing PSP encryption and decryption.
    Create(CreateArgs),
    /// Perform PSP encryption on plaintext packets read from a pcap file.
    ///
    /// Reads plaintext packets from a pcap input file.
    ///
    /// Performs the following for each packet:
    /// - Adds appropriate PSP encapsulation
    /// - Computes ICV
    /// - Encryptes data
    ///
    /// Then writes each PSP encrypted packet to a pcap output.
    ///
    Encrypt(EncryptArgs),
    /// Performs PSP decryption on PSP-encrypted packets read from a pcap file.
    ///
    /// Reads PSP-encrypted packets from a pcap input file.
    ///
    /// Performs the following for each packet:
    /// - Removes the PSP encapsulation (supports transport and tunnel encaps)
    /// - Checks that ICV is correct
    /// - Decrypts data
    ///
    /// Then writes each cleartext packet to a pcap output file.
    ///
    Decrypt(DecryptArgs),
}

#[derive(Args, Clone, Debug)]
//#[command(about, long_about)]
struct CreateArgs {
    /// Create a cleartext pcap file that can be used for testing.
    #[command(subcommand)]
    command: CreateCommands,
}

#[derive(Debug, Clone, Subcommand)]
enum CreateCommands {
    /// Create a cleartext pcap file that can be used for testing.
    ///
    /// The created packets are of the form Eth-IP-UDP-Payload with
    /// a fixed size of 1434 octents (unless the 0e option is specified).
    ///
    /// All of the created packets are for the same flow (i.e. they all
    /// have the same MAC addresses, IP addresses and UDP port numbers).
    ///
    Pcap(CreatePcapArgs),
    /// Create a configuration file that can be used with the encrypt and decrypt
    /// commands.
    Config(CreateConfigArgs),
}

#[derive(Args, Clone, Debug)]
#[command(about, long_about)]
struct CreatePcapArgs {
    /// Number of packets to create
    #[arg(short, long, default_value_t = 1)]
    num: u16,

    /// IPv4 or IPv6 packets
    #[arg(short, long, value_enum, default_value_t = IPVersion::Ipv4)]
    ver: IPVersion,

    /// Create empty packets where empty means the size of the L4 payload is 0
    #[arg(short, long, default_value_t = false)]
    empty: bool,

    /// Name of the pcap output file
    #[arg(short, default_value_t = String::from("cleartext.pcap"))]
    output: String,
}

#[derive(Args, Clone, Debug)]
#[command(about, long_about)]
struct CreateConfigArgs {
    /// SPI. 32b hex value. Upper bit selects the master key
    #[arg(short, long, default_value_t = 0x9A345678)]
    spi: u32,

    /// Encap mode: Tunnel or Transport
    #[arg(short, long, value_enum, default_value_t = PspEncap::Transport)]
    mode: PspEncap,

    /// Crypto Algorithm
    #[arg(short, long, value_enum, default_value_t = CryptoAlg::AesGcm256)]
    alg: CryptoAlg,

    /// Crypto Offset
    ///
    /// Non-negative integer with units of 4 bytes (e.g. 1)
    #[arg(long, default_value_t = 0)]
    crypto_offset: u8,

    /// Include virtual cookie
    #[arg(short, long, default_value_t = false)]
    vc: bool,

    /// Name of the output configuration file
    #[arg(short, long, default_value_t = String::from("psp_encrypt.cfg"))]
    cfg_file: String,

    /// json file format
    #[arg(short, long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
#[command(about, long_about)]
struct EncryptArgs {
    /// Enable verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Forces a single bit error in each output packet which will cause
    /// authentication to fail.
    #[arg(short, long, default_value_t = false)]
    error: bool,

    /// PSP encryption configuration file.
    #[arg(short, default_value_t = String::from("psp_encrypt.cfg"))]
    cfg_file: String,

    /// Input pcap file containing plaintext packet(s) to encrypt
    #[arg(short, long, default_value_t = String::from("cleartext.pcap"))]
    input: String,

    /// Output pcap file where the encrypted packet(s) will be written
    #[arg(short, long, default_value_t = String::from("psp_encrypt.pcap"))]
    output: String,
}

#[derive(clap::Args, Debug)]
#[command(about, long_about, verbatim_doc_comment)]
struct DecryptArgs {
    /// Enable verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// PSP encryption configuration file.
    #[arg(short, default_value_t = String::from("psp_encrypt.cfg"))]
    cfg_file: String,

    /// Input pcap file containing encrypted packet(s) to decrypt
    #[arg(short, long, default_value_t = String::from("psp_encrypt.pcap"))]
    input: String,

    /// Output pcap file where the decrypted packet(s) will be written
    #[arg(short, long, default_value_t = String::from("psp_decrypt.pcap"))]
    output: String,
}

fn create_ipv4_packet(
    pkt_buf: &mut [u8],
    packet_id: u16,
    empty: bool,
) -> Result<u16, Box<dyn Error>> {
    let eth_hdr_len = 14;
    let ip_hdr_len = 20;
    let udp_hdr_len = 8;
    let pkt_hdrs_len = eth_hdr_len + ip_hdr_len + udp_hdr_len;

    let mut pkt_len: u16 = pkt_buf.len().try_into()?;
    if empty {
        pkt_len = min(pkt_len, pkt_hdrs_len);
    }
    let payload_len: u16 = pkt_len - pkt_hdrs_len;
    let mut eth = MutableEthernetPacket::new(pkt_buf).ok_or("Error creating packet")?;
    eth.set_source(MacAddr::new(0x00, 0x22, 0x33, 0x44, 0x55, 0x00));
    eth.set_destination(MacAddr::new(0x00, 0x88, 0x99, 0xAA, 0xBB, 0x00));
    eth.set_ethertype(EtherTypes::Ipv4);

    let eth_payload = eth.payload_mut();
    let mut ip = MutableIpv4Packet::new(eth_payload).ok_or("Error creating packet")?;
    ip.set_source(Ipv4Addr::new(10, 0, 0, 1));
    ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(pkt_len - eth_hdr_len);
    ip.set_ttl(64);
    ip.set_flags(Ipv4Flags::DontFragment);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let csum = pnet::packet::ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(csum);

    let ip_payload = ip.payload_mut();
    let mut udp = MutableUdpPacket::new(ip_payload).ok_or("Error creating packet")?;
    udp.set_source(11111);
    udp.set_destination(22222);
    udp.set_length(payload_len + udp_hdr_len);

    let payload = udp.payload_mut();
    let mut id = Wrapping(u8::try_from(packet_id % 256)?);
    for offset in 0..payload_len {
        payload[offset as usize] = id.0;
        id += 1;
    }
    Ok(pkt_len)
}

fn create_ipv6_packet(
    pkt_buf: &mut [u8],
    packet_id: u16,
    empty: bool,
) -> Result<u16, Box<dyn Error>> {
    let eth_hdr_len = 14;
    let ip_hdr_len = 40;
    let udp_hdr_len = 8;
    let pkt_hdrs_len = eth_hdr_len + ip_hdr_len + udp_hdr_len;

    let mut pkt_len: u16 = pkt_buf.len().try_into()?;
    if empty {
        pkt_len = min(pkt_len, pkt_hdrs_len);
    }
    let payload_len: u16 = pkt_len - pkt_hdrs_len;
    let mut eth = MutableEthernetPacket::new(pkt_buf).ok_or("Error creating packet")?;
    eth.set_source(MacAddr::new(0x00, 0x22, 0x33, 0x44, 0x55, 0x00));
    eth.set_destination(MacAddr::new(0x00, 0x88, 0x99, 0xAA, 0xBB, 0x00));
    eth.set_ethertype(EtherTypes::Ipv6);

    let eth_payload = eth.payload_mut();
    let mut ip = MutableIpv6Packet::new(eth_payload).ok_or("Error creating packet")?;
    ip.set_source(Ipv6Addr::new(10, 0, 0, 1, 10, 0, 0, 1));
    ip.set_destination(Ipv6Addr::new(10, 0, 0, 2, 10, 0, 0, 2));
    ip.set_version(6);
    ip.set_payload_length(pkt_len - eth_hdr_len - ip_hdr_len);
    ip.set_hop_limit(64);
    ip.set_next_header(IpNextHeaderProtocols::Udp);

    let ip_payload = ip.payload_mut();
    let mut udp = MutableUdpPacket::new(ip_payload).ok_or("Error creating packet")?;
    udp.set_source(11111);
    udp.set_destination(22222);
    udp.set_length(payload_len + udp_hdr_len);

    let payload = udp.payload_mut();
    let mut id = Wrapping(u8::try_from(packet_id % 256)?);
    for offset in 0..payload_len {
        payload[offset as usize] = id.0;
        id += 1;
    }
    Ok(pkt_len)
}

fn create_packet(
    pkt_buf: &mut [u8],
    packet_id: u16,
    ver: IPVersion,
    empty: bool,
) -> Result<u16, Box<dyn Error>> {
    match ver {
        IPVersion::Ipv4 => Ok(create_ipv4_packet(pkt_buf, packet_id, empty)?),
        IPVersion::Ipv6 => Ok(create_ipv6_packet(pkt_buf, packet_id, empty)?),
    }
}

fn create_pcap_file(args: &CreatePcapArgs) -> Result<(), Box<dyn Error>> {
    let file_out = File::create(&args.output)?;
    let mut pcap_writer = PcapWriter::new(file_out)?;

    let mut pkt_buf = [0u8; 1434];
    for packet_id in 0..args.num {
        let pkt_len = create_packet(&mut pkt_buf, packet_id, args.ver, args.empty)?;
        let pcap_pkt = PcapPacket::new(
            Duration::new(0, 0),
            u32::from(pkt_len),
            &pkt_buf[..pkt_len as usize],
        );
        pcap_writer.write_packet(&pcap_pkt).unwrap();
    }
    Ok(())
}

fn key_to_string(key: &[u8]) -> String {
    key.into_iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn vc_to_string(vc: bool) -> String {
    match vc {
        true => "vc",
        false => "no-vc",
    }
    .to_string()
}

fn create_config_file(args: &CreateConfigArgs) -> Result<(), Box<dyn Error>> {
    let mut cfg = PspConfig::default();
    thread_rng().fill_bytes(&mut cfg.master_keys[0]);
    thread_rng().fill_bytes(&mut cfg.master_keys[1]);
    cfg.spi = args.spi;
    cfg.transport_crypt_off = args.crypto_offset;
    cfg.ipv4_tunnel_crypt_off = args.crypto_offset;
    cfg.ipv6_tunnel_crypt_off = args.crypto_offset;
    cfg.psp_encap = args.mode;
    cfg.include_vc = args.vc;
    cfg.crypto_alg = args.alg;

    if args.json {
        let mut path = PathBuf::from(&args.cfg_file);
        path.set_extension("json");
        std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
        println!("Created file: {}", path.display());
    } else {
        let mut cfg_parts: Vec<String> = Vec::with_capacity(10);
        cfg_parts.push(key_to_string(&cfg.master_keys[0]));
        cfg_parts.push(key_to_string(&cfg.master_keys[1]));
        cfg_parts.push(format!("{:08X}", cfg.spi));
        cfg_parts.push(format!("{}", cfg.psp_encap));
        cfg_parts.push(format!("{}", cfg.crypto_alg));
        cfg_parts.push(format!("{}", cfg.transport_crypt_off));
        cfg_parts.push(format!("{}", cfg.ipv4_tunnel_crypt_off));
        cfg_parts.push(format!("{}", cfg.ipv6_tunnel_crypt_off));
        cfg_parts.push(format!("{}", vc_to_string(cfg.include_vc)));

        let cfg_string: String = cfg_parts.join("\n");
        info!("{cfg_string}");

        std::fs::write(&args.cfg_file, cfg_string)?;
        println!("Created file: {}", args.cfg_file);
    }
    Ok(())
}

fn read_cfg_file(cfg_file: &str) -> Result<PspConfig, Box<dyn Error>> {
    let path = PathBuf::from(cfg_file);
    let jsonfile: bool = match path.extension().unwrap_or(OsStr::new("cfg")).to_str() {
        Some("json") => true,
        _ => false,
    };

    let file_in = File::open(cfg_file)?;
    let mut reader = BufReader::new(file_in);
    let cfg = match jsonfile {
        true => serde_json::from_reader(reader)?,
        false => parse_cfg_file(&mut reader)?,
    };
    Ok(cfg)
}

fn parse_cfg_file(reader: &mut BufReader<File>) -> Result<PspConfig, Box<dyn Error>> {
    let mut cfg = PspConfig::default();
    let mut line = String::new();

    reader.read_line(&mut line)?;
    cfg.master_keys[0] = parse_key(line.trim())?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.master_keys[1] = parse_key(line.trim())?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.spi = parse_spi(&line.trim())?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.psp_encap = line.trim().parse()?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.crypto_alg = line.trim().parse()?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.transport_crypt_off = line.trim().parse()?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.ipv4_tunnel_crypt_off = line.trim().parse()?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.ipv6_tunnel_crypt_off = line.trim().parse()?;

    line.clear();
    reader.read_line(&mut line)?;
    cfg.include_vc = parse_vc(&line.trim());

    debug!("Parsed cfg: {:?}", cfg);

    Ok(cfg)
}

fn parse_key(line: &str) -> Result<PspMasterKey, Box<dyn Error>> {
    let keystr: String = line.split(' ').collect();
    let keyv = hex::decode(keystr)?;
    let key: PspMasterKey = keyv
        .try_into()
        .map_err(|_| "Invalid Master Key Length".to_string())?;
    Ok(key)
}

fn parse_spi(spi_str: &str) -> Result<u32, Box<dyn Error>> {
    let spi = u32::from_str_radix(spi_str, 16)?;

    Ok(spi)
}

fn parse_vc(vc_str: &str) -> bool {
    match vc_str {
        "vc" => true,
        _ => false,
    }
}

fn create_command(args: &CreateArgs) -> Result<(), Box<dyn Error>> {
    match &args.command {
        CreateCommands::Pcap(pcap_args) => create_pcap_file(pcap_args)?,
        CreateCommands::Config(cfg_args) => create_config_file(cfg_args)?,
    };
    Ok(())
}

fn read_pkts_from_pcap(pcap_file: &str) -> Result<Vec<PcapPacket<'_>>, Box<dyn Error>> {
    let file_in = File::open(pcap_file)?;
    let mut pcap_reader = PcapReader::new(file_in)?;

    let mut pkts = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.unwrap();
        pkts.push(pkt.into_owned());
    }
    Ok(pkts)
}

fn encrypt_pkt(pkt_ctx: &mut PktContext, pkt_in: &PcapPacket) -> Result<Vec<u8>, PspError> {
    match pkt_ctx.psp_cfg.psp_encap {
        PspEncap::Transport => psp_transport_encap(pkt_ctx, &pkt_in.data),
        PspEncap::Tunnel => psp_tunnel_encap(pkt_ctx, &pkt_in.data),
    }
}

fn encrypt_pcap_file(args: &EncryptArgs) -> Result<(), Box<dyn Error>> {
    let cfg = read_cfg_file(&args.cfg_file)?;
    let pkts = read_pkts_from_pcap(&args.input)?;

    let file_out = File::create(&args.output)?;
    let mut pcap_writer = PcapWriter::new(file_out)?;

    let mut pkt_ctx = PktContext::new();
    pkt_ctx.psp_cfg = cfg;
    pkt_ctx.iv = 1;
    derive_psp_key(&mut pkt_ctx).unwrap();

    for in_pkt in pkts {
        let out_pkt = encrypt_pkt(&mut pkt_ctx, &in_pkt)?;
        let out_pcap_pkt = PcapPacket::new(in_pkt.timestamp, out_pkt.len() as u32, &out_pkt);
        pcap_writer.write_packet(&out_pcap_pkt)?;
    }
    Ok(())
}

fn decrypt_pkt(pkt_ctx: &mut PktContext, pkt_in: &PcapPacket) -> Result<Vec<u8>, PspError> {
    match pkt_ctx.psp_cfg.psp_encap {
        PspEncap::Transport => psp_transport_decap(pkt_ctx, &pkt_in.data),
        PspEncap::Tunnel => psp_tunnel_decap(pkt_ctx, &pkt_in.data),
    }
}

fn decrypt_pcap_file(args: &DecryptArgs) -> Result<(), Box<dyn Error>> {
    let cfg = read_cfg_file(&args.cfg_file)?;
    let pkts = read_pkts_from_pcap(&args.input)?;

    let file_out = File::create(&args.output)?;
    let mut pcap_writer = PcapWriter::new(file_out)?;

    let mut pkt_ctx = PktContext::new();
    pkt_ctx.psp_cfg = cfg;
    pkt_ctx.iv = 1;
    derive_psp_key(&mut pkt_ctx).unwrap();

    for in_pkt in pkts {
        let out_pkt = decrypt_pkt(&mut pkt_ctx, &in_pkt)?;
        let out_pcap_pkt = PcapPacket::new(in_pkt.timestamp, out_pkt.len() as u32, &out_pkt);
        pcap_writer.write_packet(&out_pcap_pkt)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    let err = match PspCliCommands::parse() {
        PspCliCommands::Create(args) => create_command(&args),
        PspCliCommands::Encrypt(args) => encrypt_pcap_file(&args),
        PspCliCommands::Decrypt(args) => decrypt_pcap_file(&args),
    };
    if let Err(err) = err {
        eprintln!("Error: {err}")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key() {
        let key = "32 F0 81 74 E5 3E 7B 7F 64 43 AE 79 66 11 D6 F4 88 16 C8 E0 12 91 26 6B 5C 7B F3 92 CA A6 F8 80";
        let rc = parse_key(&key);
        assert!(rc.is_ok());
        let key = rc.unwrap();
        assert_eq!(32, key.len());
        assert_eq!(0x32, key[0]);
        assert_eq!(0x80, key[31]);
    }

    #[test]
    fn test_parse_spi() {
        let spistr = "9A345678";
        let rc = parse_spi(&spistr);
        assert!(rc.is_ok());
        assert_eq!(0x9A345678, rc.unwrap());
    }
}
