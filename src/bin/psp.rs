use clap::{Parser};

#[derive(Parser)]
#[command(name = "psp")]
#[command(bin_name = "psp")]
#[command(version)]
enum PspCliCommands {

    /// Create a cleartext pcap file that can be used for testing.
    ///
    /// The created packets are of the form Eth-IP-UDP-Payload with
    /// a fixed size of 1434 octents (unless the 0e option is specified).
    ///
    /// All of the created packets are for the same flow (i.e. they all
    /// have the same MAC addresses, IP addresses and UDP port numbers).
    ///
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

#[derive(clap::Args, Debug)]
#[command(about, long_about=None)]
struct CreateArgs {
    /// Number of packets to create
    #[arg(short, long, default_value_t = 1)]
    num: u16,

    /// 4 for IPv4 packets and 6 for IPv6 packets
    #[arg(short, default_value_t = 4)]
    ver: u8,

    /// Create empty packets where empty means the size of the L4 payload is 0
    #[arg(short, default_value_t = false)]
    empty: bool,

    /// Name of the pcap output file
    #[arg(short, default_value_t = String::from("cleartext.pcap"))]
    output: String,
}

#[derive(clap::Args, Debug)]
#[command(about, long_about=None)]
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
#[command(about, long_about=None)]
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

fn create_pcap_file(args: CreateArgs) {
    println!("{:?}", args)
}

fn encrypt_pcap_file(args: EncryptArgs) {
    println!("{:?}", args)
}

fn decrypt_pcap_file(args: DecryptArgs) {
    println!("{:?}", args)
}

fn main() {
    match PspCliCommands::parse() {
        PspCliCommands::Create(args) => {
            println!("create!");
            create_pcap_file(args);
        },
        PspCliCommands::Encrypt(args) => {
            encrypt_pcap_file(args);
        },
        PspCliCommands::Decrypt(args) => {
            decrypt_pcap_file(args);
        },
    }
}