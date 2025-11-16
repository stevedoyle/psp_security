// SPDX-FileCopyrightText: © 2023 Stephen Doyle
// SPDX-License-Identifier: Apache 2.0

//! Integration tests for PSP CLI config creation

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

/// Test creating a basic config file
#[test]
fn test_create_config_basic() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    let mut cmd = Command::cargo_bin("psp").unwrap();
    cmd.arg("create").arg("config").arg("-c").arg(&config_path);

    cmd.assert().success();
    assert!(config_path.exists(), "Config file should be created");

    // Verify file has content
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(!content.is_empty(), "Config file should not be empty");
}

/// Test creating config with custom SPI
#[test]
fn test_create_config_custom_spi() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0xABCDEF12")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("ABCDEF12") || content.contains("abcdef12"),
        "Config should contain the custom SPI"
    );
}

/// Test creating config with transport mode
#[test]
fn test_create_config_transport_mode() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--mode")
        .arg("transport")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.to_lowercase().contains("transport"),
        "Config should specify transport mode"
    );
}

/// Test creating config with tunnel mode
#[test]
fn test_create_config_tunnel_mode() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--mode")
        .arg("tunnel")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.to_lowercase().contains("tunnel"),
        "Config should specify tunnel mode"
    );
}

/// Test creating config with AES-GCM-128
#[test]
fn test_create_config_aes_gcm_128() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--alg")
        .arg("aes-gcm128")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.to_lowercase().contains("128") || content.to_lowercase().contains("aes-gcm128"),
        "Config should specify AES-GCM-128"
    );
}

/// Test creating config with AES-GCM-256
#[test]
fn test_create_config_aes_gcm_256() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--alg")
        .arg("aes-gcm256")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.to_lowercase().contains("256") || content.to_lowercase().contains("aes-gcm256"),
        "Config should specify AES-GCM-256"
    );
}

/// Test creating config with virtual cookie
#[test]
fn test_create_config_with_virtual_cookie() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--vc")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
}

/// Test creating config with crypto offset
#[test]
fn test_create_config_with_crypto_offset() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--crypto-offset")
        .arg("4")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
}

/// Test creating JSON format config
#[test]
fn test_create_config_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.json");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--json")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());

    // Verify it's valid JSON
    let content = fs::read_to_string(&config_path).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("Config file should be valid JSON");
}

/// Test creating config with all options
#[test]
fn test_create_config_all_options() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--spi")
        .arg("0x12345678")
        .arg("--mode")
        .arg("tunnel")
        .arg("--alg")
        .arg("aes-gcm256")
        .arg("--crypto-offset")
        .arg("2")
        .arg("--vc")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
}

/// Test creating PCAP file with default options
#[test]
fn test_create_pcap_basic() {
    let temp_dir = TempDir::new().unwrap();
    let pcap_path = temp_dir.path().join("test.pcap");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-o")
        .arg(&pcap_path)
        .assert()
        .success();

    assert!(pcap_path.exists(), "PCAP file should be created");

    // Verify file has content
    let metadata = fs::metadata(&pcap_path).unwrap();
    assert!(metadata.len() > 0, "PCAP file should not be empty");
}

/// Test creating PCAP with multiple packets
#[test]
fn test_create_pcap_multiple_packets() {
    let temp_dir = TempDir::new().unwrap();
    let pcap_path = temp_dir.path().join("test.pcap");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("10")
        .arg("-o")
        .arg(&pcap_path)
        .assert()
        .success();

    assert!(pcap_path.exists());
}

/// Test creating IPv4 PCAP
#[test]
fn test_create_pcap_ipv4() {
    let temp_dir = TempDir::new().unwrap();
    let pcap_path = temp_dir.path().join("test.pcap");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-v")
        .arg("ipv4")
        .arg("-o")
        .arg(&pcap_path)
        .assert()
        .success();

    assert!(pcap_path.exists());
}

/// Test creating IPv6 PCAP
#[test]
fn test_create_pcap_ipv6() {
    let temp_dir = TempDir::new().unwrap();
    let pcap_path = temp_dir.path().join("test.pcap");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-v")
        .arg("ipv6")
        .arg("-o")
        .arg(&pcap_path)
        .assert()
        .success();

    assert!(pcap_path.exists());
}

/// Test creating empty packets
#[test]
fn test_create_pcap_empty() {
    let temp_dir = TempDir::new().unwrap();
    let pcap_path = temp_dir.path().join("test.pcap");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("--empty")
        .arg("-o")
        .arg(&pcap_path)
        .assert()
        .success();

    assert!(pcap_path.exists());
}
