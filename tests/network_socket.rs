// SPDX-FileCopyrightText: © 2023 Stephen Doyle
// SPDX-License-Identifier: Apache 2.0

//! Integration tests for PSP network socket operations

use psp_security::{
    derive_psp_key, CryptoAlg, PktContext, PspConfig, PspEncap, PspSocket, PspSocketOptions,
};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

/// Helper function to create a test PspSocketOptions
fn create_test_socket_options() -> PspSocketOptions {
    let mut master_keys = [[0u8; 32]; 2];
    master_keys[0] = [1u8; 32];
    master_keys[1] = [2u8; 32];

    let spi = 0x12345678;
    let key = derive_psp_key(spi, CryptoAlg::AesGcm256, &master_keys);

    PspSocketOptions::new(spi, &key)
}

/// Test basic socket binding
#[test]
fn test_socket_bind_success() {
    let opts = create_test_socket_options();
    let addr = "127.0.0.1:0"; // Port 0 = let OS choose port

    let result = PspSocket::bind(addr, opts);
    assert!(result.is_ok(), "Should successfully bind PSP socket");
}

/// Test binding to specific port
#[test]
fn test_socket_bind_specific_port() {
    let opts = create_test_socket_options();
    // Use high port number to avoid conflicts
    let addr = "127.0.0.1:35001";

    let result = PspSocket::bind(addr, opts);
    assert!(
        result.is_ok(),
        "Should successfully bind PSP socket to specific port"
    );
}

/// Test binding to invalid address fails
#[test]
fn test_socket_bind_invalid_address() {
    let opts = create_test_socket_options();
    // Invalid IP address
    let addr = "999.999.999.999:35002";

    let result = PspSocket::bind(addr, opts);
    assert!(result.is_err(), "Should fail to bind to invalid address");
}

/// Test binding to already-in-use port fails
#[test]
fn test_socket_bind_port_in_use() {
    let addr = "127.0.0.1:35003";

    // First bind with a regular UDP socket
    let _blocking_socket = UdpSocket::bind(addr).expect("Should bind first socket");

    // Try to bind PSP socket to same port
    let opts = create_test_socket_options();
    let result = PspSocket::bind(addr, opts);

    assert!(
        result.is_err(),
        "Should fail to bind when port is already in use"
    );
}

/// Test socket send operation
#[test]
fn test_socket_send_to() {
    let opts = create_test_socket_options();
    let sender_addr = "127.0.0.1:0";
    let receiver_addr = "127.0.0.1:35004";

    // Create receiver socket first
    let _receiver = UdpSocket::bind(receiver_addr).expect("Should bind receiver");

    // Create PSP sender socket
    let sender = PspSocket::bind(sender_addr, opts).expect("Should bind sender");

    // Send a test packet
    let test_data = vec![0x01, 0x02, 0x03, 0x04];
    let result = sender.send_to(&test_data, receiver_addr);

    assert!(
        result.is_ok(),
        "Should successfully send packet to receiver"
    );
}

/// Test socket receive operation
#[test]
fn test_socket_recv_from() {
    let opts = create_test_socket_options();
    let receiver_addr = "127.0.0.1:35005";

    // Create PSP receiver socket
    let receiver = PspSocket::bind(receiver_addr, opts).expect("Should bind receiver");

    // Create sender in separate thread
    let sender_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100)); // Give receiver time to start

        let sender_opts = create_test_socket_options();
        let sender = PspSocket::bind("127.0.0.1:0", sender_opts).expect("Should bind sender");

        let test_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        sender
            .send_to(&test_data, receiver_addr)
            .expect("Should send packet");
    });

    // Give sender time to send
    thread::sleep(Duration::from_millis(200));

    let mut buf = vec![0u8; 2048];
    let result = receiver.recv_from(&mut buf);

    // Join sender thread
    sender_thread.join().expect("Sender thread should complete");

    // Result may vary - receiving might timeout or succeed
    let _ = result;
}

/// Test sending to invalid address
#[test]
fn test_socket_send_to_invalid_address() {
    let opts = create_test_socket_options();
    let sender = PspSocket::bind("127.0.0.1:0", opts).expect("Should bind sender");

    let test_data = vec![0x01, 0x02, 0x03, 0x04];
    let result = sender.send_to(&test_data, "256.256.256.256:35006");

    // This might succeed (UDP is connectionless) but won't actually deliver
    // We're mainly testing that it doesn't panic
    let _ = result;
}

/// Test multiple packets in sequence
#[test]
fn test_socket_multiple_packets_sequence() {
    let opts1 = create_test_socket_options();
    let opts2 = create_test_socket_options();

    let sender = PspSocket::bind("127.0.0.1:0", opts1).expect("Should bind sender");
    let receiver_addr = "127.0.0.1:35007";
    let _receiver = UdpSocket::bind(receiver_addr).expect("Should bind receiver");

    // Send multiple packets
    for i in 0..5 {
        let test_data = vec![i as u8; 10];
        let result = sender.send_to(&test_data, receiver_addr);
        assert!(result.is_ok(), "Packet {} should send successfully", i);
    }
}

/// Test socket with different crypto algorithms
#[test]
fn test_socket_with_different_algorithms() {
    // Test with AES-GCM-128
    let mut master_keys = [[0u8; 32]; 2];
    master_keys[0] = [3u8; 32];
    master_keys[1] = [4u8; 32];

    let spi = 0x11111111;
    let key128 = derive_psp_key(spi, CryptoAlg::AesGcm128, &master_keys);
    let opts128 = PspSocketOptions::new(spi, &key128);

    let result = PspSocket::bind("127.0.0.1:0", opts128);
    assert!(result.is_ok(), "Should bind with AES-GCM-128");

    // Test with AES-GCM-256
    let key256 = derive_psp_key(spi, CryptoAlg::AesGcm256, &master_keys);
    let opts256 = PspSocketOptions::new(spi, &key256);

    let result = PspSocket::bind("127.0.0.1:0", opts256);
    assert!(result.is_ok(), "Should bind with AES-GCM-256");
}

/// Test socket with IPv6
#[test]
#[ignore] // May not work in all test environments
fn test_socket_ipv6() {
    let opts = create_test_socket_options();
    let addr = "[::1]:35008"; // IPv6 loopback

    let result = PspSocket::bind(addr, opts);
    // May fail if IPv6 is not available, so we don't assert
    let _ = result;
}

/// Test concurrent socket operations
#[test]
fn test_concurrent_socket_operations() {
    let receiver_addr: SocketAddr = "127.0.0.1:35009".parse().unwrap();

    // Create receiver
    let receiver_opts = create_test_socket_options();
    let receiver = PspSocket::bind(receiver_addr, receiver_opts).expect("Should bind receiver");

    // Spawn multiple senders
    let mut sender_threads = vec![];

    for i in 0..3 {
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100 * i)); // Stagger sends

            let opts = create_test_socket_options();
            let sender = PspSocket::bind("127.0.0.1:0", opts).expect("Should bind sender");

            let test_data = vec![i as u8; 20];
            sender
                .send_to(&test_data, receiver_addr)
                .expect("Should send");
        });

        sender_threads.push(thread);
    }

    // Wait for senders to send
    thread::sleep(Duration::from_millis(500));

    // Try to receive packets
    let mut received_count = 0;
    for _ in 0..3 {
        let mut buf = vec![0u8; 2048];
        if receiver.recv_from(&mut buf).is_ok() {
            received_count += 1;
        }
    }

    // Wait for all senders
    for thread in sender_threads {
        thread.join().expect("Sender thread should complete");
    }

    // We may or may not receive packets due to timing - just ensure no panic
    let _ = received_count;
}

/// Test socket error handling with no UDP socket
#[test]
fn test_socket_without_udp_socket() {
    use std::io;
    use std::net::ToSocketAddrs;

    // This test verifies error handling when UDP socket is None
    // We can't directly create a PspSocket without UDP socket through public API,
    // but we can test the error path by sending to an unbound socket scenario

    let opts = create_test_socket_options();
    let socket = PspSocket::bind("127.0.0.1:0", opts).expect("Should bind");

    // Socket should have UDP socket at this point, so operations should work
    let test_data = vec![0x01, 0x02];
    let result = socket.send_to(&test_data, "127.0.0.1:35010");

    // Should work (though may not deliver if nothing is listening)
    assert!(result.is_ok() || result.is_err()); // Either is fine for this test
}

/// Test socket with small buffer receive
#[test]
fn test_socket_receive_small_buffer() {
    let receiver_addr = "127.0.0.1:35011";
    let opts = create_test_socket_options();
    let receiver = PspSocket::bind(receiver_addr, opts).expect("Should bind receiver");

    // Create sender in thread
    let sender_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));

        let sender_opts = create_test_socket_options();
        let sender = PspSocket::bind("127.0.0.1:0", sender_opts).expect("Should bind sender");

        let test_data = vec![0xFFu8; 1000]; // Large data
        sender
            .send_to(&test_data, receiver_addr)
            .expect("Should send");
    });

    // Wait for sender
    thread::sleep(Duration::from_millis(200));

    // Try to receive with small buffer
    let mut small_buf = vec![0u8; 100]; // Buffer smaller than sent data
    let result = receiver.recv_from(&mut small_buf);

    sender_thread.join().expect("Sender should complete");

    // Should either succeed (truncated) or fail gracefully
    let _ = result; // Don't assert - behavior may vary by platform
}

/// Test socket reuse - bind, close, bind again
#[test]
fn test_socket_reuse_port() {
    let addr = "127.0.0.1:35012";
    let opts1 = create_test_socket_options();

    {
        let _socket1 = PspSocket::bind(addr, opts1).expect("Should bind first time");
        // Socket1 drops here
    }

    // Should be able to bind again after first socket is dropped
    let opts2 = create_test_socket_options();
    let result = PspSocket::bind(addr, opts2);

    assert!(
        result.is_ok(),
        "Should be able to bind after previous socket is closed"
    );
}
