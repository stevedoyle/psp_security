# PSP Socket Implementation Notes

`PspSocket` is designed as a wrapper around a UDP socket.

A simple client and echo server example will be used to illustrate the usage of
`PspSocket`.

One challenge is the management of keys and the co-ordination of the derived
keys for the connection between the client and the server. Since a PSP SA is
uni-directional, a pair of SAs is required to implement the bi-directional
communications. In PSP, the receiver derives the key for the SA and the SA key
is then passed out-of-band through some unspecified mechanism to the
transmitter. In the client-server case, both the client and the server must
derive a key for the SA for which they are the receiver and these keys must be
somehow sent to the peer.

Some options:

1. Use the same master keys (from a shared config file) for both the client and
   the server. This should allow the same key to be derived in both the client
   and the server. This is not ideal or secure but it may do for a first
   iteration of the implementation.
2. Establish a TLS connection between the client and the server and use it to
   exchange the derived key + spi for the SA.
3. Same as #2 but use a gRPC link between the client and server for
   communicating the (spi, tx_key) pair.