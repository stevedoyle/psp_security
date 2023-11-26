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
