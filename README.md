# Rust Implementation of the PSP Security Protocol

Google have released the PSP (PSP Security Protocol)
[specification and a reference implementation](https://github.com/google/psp).
That implementation is in C.

The psp_security crate is a Rust port of the reference implementation. It
implements PSP encrypt/decrypt functionality using Rust for memory safety.

The implementation consists of a core `psp_security` library which implements
the PSP packet encapsulation, decapsulation, encryption and decryption and also
a command line utility that uses this library. This utility is useful for
generating test vectors, and encrypting / decrypting content from the command
line.

## Building

```bash
cargo build
```

Run the crates unit tests.

```bash
cargo test
```

Install the command line utility. The example below installs it into the current
directory.

```bash
cargo install --path .
```

## Command Line Utility

A command line utility called `psp` is provided to illustrate how to use the
psp_security library and to provide some simple utilities for encrypting and
decrypting packets from a pcap file using PSP.

```text
Usage: psp <COMMAND>

Commands:
  create   Create files that are useful for testing PSP encryption and decryption
  encrypt  Perform PSP encryption on plaintext packets read from a pcap file
  decrypt  Performs PSP decryption on PSP-encrypted packets read from a pcap file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Example Usage

```bash
# Create a sample input pcap file
psp create pcap -n 10 -v ipv4 -o cleartext.pcap
# Create a sample configuration file
psp create config --spi 98234567 --mode transport --alg aes-gcm128 -c example.cfg
# Encrypt the pcap file using the configuration
psp encrypt -c example.cfg -i cleartext.pcap -o encrypted.pcap
# Decrypt the encrypted packets using the configuration
psp decrypt -c example.cfg -i encrypted.pcap -o decrypted.pcap
# Compare the decrypted packets against the origin sample packets
tcpdump -X -r cleartext.pcap > cleartext.txt
tcpdump -X -r decrypted.pcap > decrypted.txt
diff cleartext.txt decrypted.txt
```

### Command Details

#### psp encrypt

Encrypting packets in a pcap file using `psp encrypt` requires not only a pcap
file containing the packets but also a configuration file that specifies the PSP
configuration.

```text
$ psp encrypt -h
Perform PSP encryption on plaintext packets read from a pcap file

Usage: psp encrypt [OPTIONS]

Options:
  -v, --verbose          Enable verbose mode
  -e, --error            Forces a single bit error in each output packet which will cause authentication to fail
  -c <CFG_FILE>          PSP encryption configuration file [default: psp_encrypt.cfg]
  -i, --input <INPUT>    Input pcap file containing plaintext packet(s) to encrypt [default: cleartext.pcap]
  -o, --output <OUTPUT>  Output pcap file where the encrypted packet(s) will be written [default: psp_encrypt.pcap]
  -h, --help             Print help (see more with '--help')
```

#### psp decrypt

Encrypting packets in a pcap file using `psp encrypt` requires not only a pcap
file containing the packets but also a configuration file that specifies the PSP
configuration.

```text
$ psp decrypt -h
Performs PSP decryption on PSP-encrypted packets read from a pcap file

Usage: psp decrypt [OPTIONS]

Options:
  -v, --verbose          Enable verbose mode
  -c <CFG_FILE>          PSP encryption configuration file [default: psp_encrypt.cfg]
  -i, --input <INPUT>    Input pcap file containing encrypted packet(s) to decrypt [default: psp_encrypt.pcap]
  -o, --output <OUTPUT>  Output pcap file where the decrypted packet(s) will be written [default: psp_decrypt.pcap]
  -h, --help             Print help (see more with '--help')
```

#### psp create config

The `psp create config` command can be used to create a sample configuration
file in either json or a raw text format. The raw text format is based on the
configuration file format that the google PSP C language implementation uses. It
is supported here to allow compatibility testing with the C language
implementation.

```text
$ psp create config -h
Create a configuration file that can be used with the encrypt and decrypt commands

Usage: psp create config [OPTIONS]

Options:
  -s, --spi <SPI>                      SPI. 32b hex value. Upper bit selects the master key [default: 2587121272]
  -m, --mode <MODE>                    Encap mode: Tunnel or Transport [default: transport] [possible values: transport, tunnel]
  -a, --alg <ALG>                      Crypto Algorithm [default: aes-gcm256] [possible values: aes-gcm128, aes-gcm256]
      --crypto-offset <CRYPTO_OFFSET>  Crypto Offset [default: 0]
  -v, --vc                             Include virtual cookie
  -c, --cfg-file <CFG_FILE>            Name of the output configuration file [default: psp_encrypt.cfg]
  -j, --json                           json file format
  -h, --help                           Print help (see more with '--help')
```

#### psp create pcap

The `psp create pcap` utility can be used to create a sample pcap file which can
be used for testing purposes.

```text
$ psp create pcap -h
Create a cleartext pcap file that can be used for testing

Usage: psp create pcap [OPTIONS]

Options:
  -n, --num <NUM>  Number of packets to create [default: 1]
  -v, --ver <VER>  IPv4 or IPv6 packets [default: ipv4] [possible values: ipv4, ipv6]
  -e, --empty      Create empty packets where empty means the size of the L4 payload is 0
  -o <OUTPUT>      Name of the pcap output file [default: cleartext.pcap]
  -h, --help       Print help (see more with '--help')
  ```
