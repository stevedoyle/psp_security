// SPDX-FileCopyrightText: © 2023 Stephen Doyle
// SPDX-License-Identifier: Apache 2.0

use std::{
    cmp::min,
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::Wrapping,
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
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
use pretty_hex::PrettyHex;
use psp_security::{
    derive_psp_key, psp_decap_eth, psp_transport_encap, psp_tunnel_encap, CryptoAlg, PktContext,
    PspConfig, PspEncap, PspError, PspMasterKey, PspSocket, PspSocketOptions,
};
use rand::{thread_rng, RngCore};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IPVersion {
    Ipv4,
    Ipv6,
}

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
    /// - Encrypts data
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

    /// A client application that sends data over a PSP connection to a server.
    Client(ClientArgs),

    /// A server application that receives data over a PSP connection.
    Server(ServerArgs),
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
    #[arg(short, long, value_parser=maybe_hex::<u32>, default_value_t = 0x9A345678)]
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

#[derive(clap::Args, Debug)]
#[command(about, long_about, verbatim_doc_comment)]
struct ClientArgs {
    /// Enable verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// PSP encryption configuration file.
    #[arg(short, default_value_t = String::from("psp_encrypt.cfg"))]
    cfg_file: String,

    /// Server address
    #[arg(short, long, default_value_t = Ipv4Addr::new(127, 0, 0, 1))]
    addr: Ipv4Addr,

    /// Server port
    #[arg(short, long, default_value_t = 1000)]
    port: u16,
}

#[derive(clap::Args, Debug)]
#[command(about, long_about, verbatim_doc_comment)]
struct ServerArgs {
    /// Enable verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// PSP encryption configuration file.
    #[arg(short, default_value_t = String::from("psp_encrypt.cfg"))]
    cfg_file: String,

    /// Server port
    #[arg(short, long, default_value_t = 1000)]
    port: u16,
}

// Common packet constants for IPv4
const ETH_HDR_LEN_V4: u16 = 14;
const IP_HDR_LEN_V4: u16 = 20;
const UDP_HDR_LEN: u16 = 8;
const PKT_HDRS_LEN_V4: u16 = ETH_HDR_LEN_V4 + IP_HDR_LEN_V4 + UDP_HDR_LEN;

// Common packet constants for IPv6  
const ETH_HDR_LEN_V6: u16 = 14;
const IP_HDR_LEN_V6: u16 = 40;
const PKT_HDRS_LEN_V6: u16 = ETH_HDR_LEN_V6 + IP_HDR_LEN_V6 + UDP_HDR_LEN;

const MIN_PACKET_SIZE_V4: u16 = PKT_HDRS_LEN_V4;
const MIN_PACKET_SIZE_V6: u16 = PKT_HDRS_LEN_V6;
const MAX_PACKET_SIZE: u16 = 9000; // Jumbo frame limit

/// Common packet validation logic
fn validate_packet_buffer(pkt_buf: &[u8], min_size: u16) -> Result<u16, Box<dyn Error>> {
    // Validate buffer size
    if pkt_buf.len() < min_size as usize {
        return Err(format!("Buffer too small: {} bytes, minimum {}", pkt_buf.len(), min_size).into());
    }

    let pkt_len: u16 = pkt_buf.len().try_into().map_err(|_| "Packet buffer too large")?;
    
    // Validate packet size
    if pkt_len > MAX_PACKET_SIZE {
        return Err(format!("Packet too large: {} bytes, maximum {}", pkt_len, MAX_PACKET_SIZE).into());
    }
    
    Ok(pkt_len)
}

/// Common UDP setup and payload generation
fn setup_udp_payload(udp: &mut MutableUdpPacket, payload_len: u16, packet_id: u16) -> Result<(), Box<dyn Error>> {
    // Test UDP port numbers - not for production use
    udp.set_source(11111);
    udp.set_destination(22222);
    udp.set_length(payload_len + UDP_HDR_LEN);

    let payload = udp.payload_mut();
    let mut id = Wrapping(u8::try_from(packet_id % 256)?);
    for offset in 0..payload_len {
        payload[offset as usize] = id.0;
        id += 1;
    }
    Ok(())
}

fn create_ipv4_packet(
    pkt_buf: &mut [u8],
    packet_id: u16,
    empty: bool,
) -> Result<u16, Box<dyn Error>> {
    let mut pkt_len = validate_packet_buffer(pkt_buf, MIN_PACKET_SIZE_V4)?;

    if empty {
        pkt_len = min(pkt_len, PKT_HDRS_LEN_V4);
    }
    let payload_len: u16 = pkt_len - PKT_HDRS_LEN_V4;
    let mut eth = MutableEthernetPacket::new(pkt_buf).ok_or("Failed to create Ethernet packet - buffer too small")?;
    // Test MAC addresses - not for production use
    eth.set_source(MacAddr::new(0x00, 0x22, 0x33, 0x44, 0x55, 0x00));
    eth.set_destination(MacAddr::new(0x00, 0x88, 0x99, 0xAA, 0xBB, 0x00));
    eth.set_ethertype(EtherTypes::Ipv4);

    let eth_payload = eth.payload_mut();
    let mut ip = MutableIpv4Packet::new(eth_payload).ok_or("Failed to create IPv4 packet - buffer too small")?;
    // Test IP addresses (private network range 10.0.0.x) - not for production use  
    ip.set_source(Ipv4Addr::new(10, 0, 0, 1));
    ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(pkt_len - ETH_HDR_LEN_V4);
    ip.set_ttl(64);
    ip.set_flags(Ipv4Flags::DontFragment);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let csum = pnet::packet::ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(csum);

    let ip_payload = ip.payload_mut();
    let mut udp = MutableUdpPacket::new(ip_payload).ok_or("Failed to create UDP packet - buffer too small")?;
    setup_udp_payload(&mut udp, payload_len, packet_id)?;
    Ok(pkt_len)
}

fn create_ipv6_packet(
    pkt_buf: &mut [u8],
    packet_id: u16,
    empty: bool,
) -> Result<u16, Box<dyn Error>> {
    let mut pkt_len = validate_packet_buffer(pkt_buf, MIN_PACKET_SIZE_V6)?;

    if empty {
        pkt_len = min(pkt_len, PKT_HDRS_LEN_V6);
    }
    let payload_len: u16 = pkt_len - PKT_HDRS_LEN_V6;
    let mut eth = MutableEthernetPacket::new(pkt_buf).ok_or("Failed to create Ethernet packet - buffer too small")?;
    // Test MAC addresses - not for production use
    eth.set_source(MacAddr::new(0x00, 0x22, 0x33, 0x44, 0x55, 0x00));
    eth.set_destination(MacAddr::new(0x00, 0x88, 0x99, 0xAA, 0xBB, 0x00));
    eth.set_ethertype(EtherTypes::Ipv6);

    let eth_payload = eth.payload_mut();
    let mut ip = MutableIpv6Packet::new(eth_payload).ok_or("Failed to create IPv6 packet - buffer too small")?;
    // IPv4-mapped IPv6 addresses for test data (::ffff:10.0.0.1 and ::ffff:10.0.0.2)
    ip.set_source("::ffff:10.0.0.1".parse().unwrap());
    ip.set_destination("::ffff:10.0.0.2".parse().unwrap());
    ip.set_version(6);
    ip.set_payload_length(pkt_len - ETH_HDR_LEN_V6 - IP_HDR_LEN_V6);
    ip.set_hop_limit(64);
    ip.set_next_header(IpNextHeaderProtocols::Udp);

    let ip_payload = ip.payload_mut();
    let mut udp = MutableUdpPacket::new(ip_payload).ok_or("Failed to create UDP packet - buffer too small")?;
    setup_udp_payload(&mut udp, payload_len, packet_id)?;
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
        pcap_writer.write_packet(&pcap_pkt)
            .map_err(|e| format!("Failed to write packet {}: {}", packet_id, e))?;
    }
    Ok(())
}

fn key_to_string(key: &[u8]) -> String {
    key.iter()
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
        cfg_parts.push(vc_to_string(cfg.include_vc));

        let cfg_string: String = cfg_parts.join("\n");
        info!("{cfg_string}");

        std::fs::write(&args.cfg_file, cfg_string)?;
        println!("Created file: {}", args.cfg_file);
    }
    Ok(())
}

fn read_cfg_file(cfg_file: &str) -> Result<PspConfig, Box<dyn Error>> {
    let path = PathBuf::from(cfg_file);
    match path.extension().unwrap_or(OsStr::new("cfg")).to_str() {
        Some("json") => parse_json_cfg_file(cfg_file),
        _ => parse_cfg_file(cfg_file),
    }
}

fn parse_json_cfg_file(cfg_file: &str) -> Result<PspConfig, Box<dyn Error>> {
    let file_in = File::open(cfg_file)?;
    let reader = BufReader::new(file_in);
    let cfg: PspConfig = serde_json::from_reader(reader)?;
    
    // Validate configuration for security issues
    cfg.validate()
        .map_err(|e| format!("JSON configuration validation failed: {}", e))?;
    
    Ok(cfg)
}

fn parse_cfg_file(cfg_file: &str) -> Result<PspConfig, Box<dyn Error>> {
    let mut cfg = PspConfig::default();

    let cfg_data = fs::read_to_string(cfg_file)?;
    let mut lines = cfg_data
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty());

    let line = lines.next().unwrap_or("");
    cfg.master_keys[0] = parse_key(line)?;

    let line = lines.next().unwrap_or("");
    cfg.master_keys[1] = parse_key(line)?;

    if let Some(line) = lines.next() {
        cfg.spi = parse_spi(line)?;
    }

    if let Some(line) = lines.next() {
        cfg.psp_encap = line.parse()?;
    }

    if let Some(line) = lines.next() {
        cfg.crypto_alg = line.parse()?;
    }

    if let Some(line) = lines.next() {
        cfg.transport_crypt_off = line.parse()?;
    }

    if let Some(line) = lines.next() {
        cfg.ipv4_tunnel_crypt_off = line.parse()?;
    }

    if let Some(line) = lines.next() {
        cfg.ipv6_tunnel_crypt_off = line.parse()?;
    }

    if let Some(line) = lines.next() {
        cfg.include_vc = parse_vc(line);
    }

    debug!("Parsed cfg: {:?}", cfg);
    
    // Validate configuration for security issues
    cfg.validate()
        .map_err(|e| format!("Configuration validation failed: {}", e))?;

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
    matches!(vc_str, "vc")
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
    pkt_ctx.key = derive_psp_key(
        pkt_ctx.psp_cfg.spi,
        pkt_ctx.psp_cfg.crypto_alg,
        &pkt_ctx.psp_cfg.master_keys,
    );

    for in_pkt in pkts {
        let mut out_pkt = encrypt_pkt(&mut pkt_ctx, &in_pkt)?;
        if args.error && !out_pkt.is_empty() {
            let last = out_pkt.last_mut().unwrap();
            *last ^= 0b0000_1000;
        }
        let out_pcap_pkt = PcapPacket::new(in_pkt.timestamp, out_pkt.len() as u32, &out_pkt);
        pcap_writer.write_packet(&out_pcap_pkt)?;
    }
    Ok(())
}

fn decrypt_pkt(pkt_ctx: &mut PktContext, pkt_in: &PcapPacket) -> Result<Vec<u8>, PspError> {
    psp_decap_eth(pkt_ctx, &pkt_in.data)
}

fn decrypt_pcap_file(args: &DecryptArgs) -> Result<(), Box<dyn Error>> {
    let cfg = read_cfg_file(&args.cfg_file)?;
    let pkts = read_pkts_from_pcap(&args.input)?;

    let file_out = File::create(&args.output)?;
    let mut pcap_writer = PcapWriter::new(file_out)?;

    let mut pkt_ctx = PktContext::new();
    pkt_ctx.psp_cfg = cfg;
    pkt_ctx.iv = 1;
    pkt_ctx.key = derive_psp_key(
        pkt_ctx.psp_cfg.spi,
        pkt_ctx.psp_cfg.crypto_alg,
        &pkt_ctx.psp_cfg.master_keys,
    );

    for in_pkt in pkts {
        let out_pkt = decrypt_pkt(&mut pkt_ctx, &in_pkt)?;
        let out_pcap_pkt = PcapPacket::new(in_pkt.timestamp, out_pkt.len() as u32, &out_pkt);
        pcap_writer.write_packet(&out_pcap_pkt)?;
    }
    Ok(())
}

/// Echo Client
fn client(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    println!("{args:?}");

    let cfg = read_cfg_file(&args.cfg_file)?;
    let key = derive_psp_key(cfg.spi, cfg.crypto_alg, &cfg.master_keys);

    debug!("SPI: {:08X}", cfg.spi);
    debug!("Derived Key: {}", key.hex_dump());

    let msg = "Hello, world!";

    let socket_opts = PspSocketOptions::new(cfg.spi, &key);
    let socket = PspSocket::bind("0.0.0.0:0", socket_opts).expect("Couldn't bind to address");

    // Send the PSP packet to the server
    let server = SocketAddr::new(IpAddr::V4(args.addr), args.port);
    println!("Sending to: {}", server);
    socket
        .send_to(msg.as_bytes(), server)
        .expect("Error on send");

    let mut buf = [0; 2048];
    let (amt, _src) = socket.recv_from(&mut buf)?;

    let resp = &buf[..amt];
    println!("Payload: {:?}", resp.hex_dump());

    Ok(())
}

/// Echo server
fn server(args: &ServerArgs) -> Result<(), Box<dyn Error>> {
    println!("{args:?}");

    let cfg = read_cfg_file(&args.cfg_file)?;
    let key = derive_psp_key(cfg.spi, cfg.crypto_alg, &cfg.master_keys);

    debug!("SPI: {:08X}", cfg.spi);
    debug!("Derived Key: {}", key.hex_dump());

    let socket_opts = PspSocketOptions::new(cfg.spi, &key);

    // Listen on the selected PSP port
    // For each packet received, decrypt the packet and print the payload

    let sock_addr = format!("[::]:{}", args.port);
    let socket = PspSocket::bind(&sock_addr, socket_opts).expect("Couldn't bind to address");
    let mut buf = [0u8; 1500];
    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        let pkt = PcapPacket::new(Duration::new(0, 0), amt as u32, &buf[..amt]);
        info!("Received packet from: {:?}", src);
        info!("Packet: {:?}", pkt);
        info!("Payload: {:?}", pkt.data.hex_dump());

        // Redeclare `buf` as slice of the received data and send data back to origin.
        let buf = &mut buf[..amt];
        socket.send_to(buf, &src)?;
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let err = match PspCliCommands::parse() {
        PspCliCommands::Create(args) => create_command(&args),
        PspCliCommands::Encrypt(args) => encrypt_pcap_file(&args),
        PspCliCommands::Decrypt(args) => decrypt_pcap_file(&args),
        PspCliCommands::Client(args) => client(&args),
        PspCliCommands::Server(args) => server(&args),
    };
    if let Err(err) = err {
        eprintln!("Error: {err}");
        std::process::exit(exitcode::DATAERR);
    }
    std::process::exit(exitcode::OK);
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
