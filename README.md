# Rust Implementation of the PSP Security Protocol

Google have released the PSP (PSP Security Protocol)
[specification and a reference implementation](https://github.com/google/psp).
That implementation isin C.

The psp_security crate implements the PSP encrypt/decrypt functionality using
Rust for memory safety.

The implementation consists of a core `psp_security` library which implements
the PSP packet encapsulation, decapsulation, encryption and decryption and also
a set of utilities that use this library. These utilites are useful for
generating test vectors, and encrypting / decrypting content from the command
line.
