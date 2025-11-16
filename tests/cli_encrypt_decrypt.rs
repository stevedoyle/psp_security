// SPDX-FileCopyrightText: © 2023 Stephen Doyle
// SPDX-License-Identifier: Apache 2.0

//! Integration tests for PSP CLI encrypt/decrypt workflow

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Test the complete encrypt/decrypt workflow with PSPv0 (AES-GCM-128)
#[test]
fn test_encrypt_decrypt_workflow_pspv0() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Step 1: Create config file (PSPv0 = AES-GCM-128)
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x12345678")
        .arg("--mode")
        .arg("transport")
        .arg("--alg")
        .arg("aes-gcm128")
        .arg("-c")
        .arg(&config_path);

    cmd.assert().success();
    assert!(config_path.exists(), "Config file should be created");

    // Step 2: Create cleartext PCAP file
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("5")
        .arg("-v")
        .arg("ipv4")
        .arg("-o")
        .arg(&cleartext_path);

    cmd.assert().success();
    assert!(cleartext_path.exists(), "Cleartext PCAP should be created");

    // Step 3: Encrypt the PCAP file
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path);

    cmd.assert().success();
    assert!(encrypted_path.exists(), "Encrypted PCAP should be created");

    // Verify encrypted file is larger than cleartext (due to PSP header + ICV)
    let cleartext_size = fs::metadata(&cleartext_path).unwrap().len();
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    assert!(
        encrypted_size > cleartext_size,
        "Encrypted file should be larger than cleartext"
    );

    // Step 4: Decrypt the PCAP file
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("decrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path);

    cmd.assert().success();
    assert!(decrypted_path.exists(), "Decrypted PCAP should be created");

    // Verify decrypted file size matches original cleartext
    let decrypted_size = fs::metadata(&decrypted_path).unwrap().len();
    assert_eq!(
        cleartext_size, decrypted_size,
        "Decrypted file should match cleartext size"
    );
}

/// Test encrypt/decrypt workflow with PSPv1 (AES-GCM-256)
#[test]
fn test_encrypt_decrypt_workflow_pspv1() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Create config file (PSPv1 = AES-GCM-256)
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x92345678")
        .arg("--mode")
        .arg("tunnel")
        .arg("--alg")
        .arg("aes-gcm256")
        .arg("-c")
        .arg(&config_path);

    cmd.assert().success();

    // Create cleartext PCAP
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("3")
        .arg("-v")
        .arg("ipv6")
        .arg("-o")
        .arg(&cleartext_path);

    cmd.assert().success();

    // Encrypt
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path);

    cmd.assert().success();

    // Decrypt
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("decrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path);

    cmd.assert().success();
}

/// Test encrypt/decrypt with virtual cookie (VC)
#[test]
fn test_encrypt_decrypt_with_virtual_cookie() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Create config with virtual cookie enabled
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x12345678")
        .arg("--mode")
        .arg("transport")
        .arg("--alg")
        .arg("aes-gcm128")
        .arg("--vc")
        .arg("-c")
        .arg(&config_path);

    cmd.assert().success();

    // Create, encrypt, and decrypt
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("2")
        .arg("-o")
        .arg(&cleartext_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("decrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path)
        .assert()
        .success();
}

/// Test encrypt with crypto offset
#[test]
fn test_encrypt_decrypt_with_crypto_offset() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Create config with crypto offset
    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x12345678")
        .arg("--mode")
        .arg("transport")
        .arg("--alg")
        .arg("aes-gcm128")
        .arg("--crypto-offset")
        .arg("2")
        .arg("-c")
        .arg(&config_path);

    cmd.assert().success();

    // Create, encrypt, and decrypt
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("1")
        .arg("-o")
        .arg(&cleartext_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("decrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path)
        .assert()
        .success();
}

/// Test that decryption fails with wrong config (different key)
#[test]
fn test_decrypt_with_wrong_config_fails() {
    let temp_dir = TempDir::new().unwrap();
    let config1_path = temp_dir.path().join("config1.cfg");
    let config2_path = temp_dir.path().join("config2.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Create two different configs
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x12345678")
        .arg("-c")
        .arg(&config1_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x87654321")
        .arg("-c")
        .arg(&config2_path)
        .assert()
        .success();

    // Create cleartext
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("1")
        .arg("-o")
        .arg(&cleartext_path)
        .assert()
        .success();

    // Encrypt with config1
    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config1_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path)
        .assert()
        .success();

    // Try to decrypt with config2 (different SPI/keys) - should fail
    Command::cargo_bin("psp")
        .unwrap()
        .arg("decrypt")
        .arg("-c")
        .arg(&config2_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path)
        .assert()
        .failure();
}

/// Test that missing input file produces error
#[test]
fn test_encrypt_missing_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    // Create config
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Try to encrypt non-existent file
    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg("nonexistent.pcap")
        .arg("-o")
        .arg("output.pcap")
        .assert()
        .failure();
}

/// Test creating empty packets and encrypting them
#[test]
fn test_encrypt_decrypt_empty_packets() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");
    let cleartext_path = temp_dir.path().join("cleartext.pcap");
    let encrypted_path = temp_dir.path().join("encrypted.pcap");
    let decrypted_path = temp_dir.path().join("decrypted.pcap");

    // Create config
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Create empty packets
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("2")
        .arg("--empty")
        .arg("-o")
        .arg(&cleartext_path)
        .assert()
        .success();

    // Encrypt empty packets
    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&cleartext_path)
        .arg("-o")
        .arg(&encrypted_path)
        .assert()
        .success();

    // Decrypt empty packets
    Command::cargo_bin("psp")
        .unwrap()
        .arg("decrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypted_path)
        .assert()
        .success();
}
