// SPDX-FileCopyrightText: © 2023 Stephen Doyle
// SPDX-License-Identifier: Apache 2.0

//! Integration tests for PSP configuration file I/O

use psp_security::{CryptoAlg, PspConfig, PspEncap};
use std::fs;
use tempfile::TempDir;

/// Test loading a JSON configuration file created by the CLI
#[test]
fn test_load_json_config_file() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.json");

    // Create a JSON config using CLI
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--json")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Read and parse the JSON file
    let json_str = fs::read_to_string(&config_path).expect("Should read config file");
    let config: PspConfig = serde_json::from_str(&json_str).expect("Should parse JSON config");

    // Verify basic config structure
    assert!(config.spi != 0, "SPI should be non-zero");
    assert!(
        config.master_keys[0] != [0u8; 32],
        "Master key 0 should not be all zeros"
    );
    assert!(
        config.master_keys[1] != [0u8; 32],
        "Master key 1 should not be all zeros"
    );
}

/// Test saving and loading a PspConfig as JSON
#[test]
fn test_save_load_json_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("roundtrip.json");

    // Create a config programmatically
    let original_config = PspConfig::new_secure().expect("Should create secure config");

    // Serialize to JSON and write to file
    let json_str = serde_json::to_string_pretty(&original_config).expect("Should serialize");
    fs::write(&config_path, &json_str).expect("Should write config file");

    // Read back and deserialize
    let loaded_json = fs::read_to_string(&config_path).expect("Should read config file");
    let loaded_config: PspConfig = serde_json::from_str(&loaded_json).expect("Should deserialize");

    // Verify configs match
    assert_eq!(original_config.spi, loaded_config.spi);
    assert_eq!(original_config.crypto_alg, loaded_config.crypto_alg);
    assert_eq!(original_config.master_keys, loaded_config.master_keys);
}

/// Test creating multiple config files with different parameters
#[test]
fn test_multiple_config_files() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();

    // Create transport mode config
    let transport_path = temp_dir.path().join("transport.cfg");
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--mode")
        .arg("transport")
        .arg("-c")
        .arg(&transport_path)
        .assert()
        .success();

    // Create tunnel mode config
    let tunnel_path = temp_dir.path().join("tunnel.cfg");
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--mode")
        .arg("tunnel")
        .arg("-c")
        .arg(&tunnel_path)
        .assert()
        .success();

    // Verify both files exist
    assert!(transport_path.exists());
    assert!(tunnel_path.exists());

    // Verify they have different content
    let transport_content = fs::read_to_string(&transport_path).unwrap();
    let tunnel_content = fs::read_to_string(&tunnel_path).unwrap();
    assert_ne!(transport_content, tunnel_content);
}

/// Test configuration validation after loading
#[test]
fn test_loaded_config_validation() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.json");

    // Create a config
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--json")
        .arg("--spi")
        .arg("0x12345678")
        .arg("--alg")
        .arg("aes-gcm256")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Load the config
    let json_str = fs::read_to_string(&config_path).expect("Should read config");
    let config: PspConfig = serde_json::from_str(&json_str).expect("Should parse config");

    // Validate the loaded config
    assert!(
        config.validate().is_ok(),
        "Loaded config should pass validation"
    );
    assert_eq!(config.spi, 0x12345678);
    assert_eq!(config.crypto_alg, CryptoAlg::AesGcm256);
}

/// Test that config file contains expected fields
#[test]
fn test_json_config_has_required_fields() {
    use assert_cmd::Command;

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

    let json_str = fs::read_to_string(&config_path).expect("Should read config");
    let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("Should parse JSON");

    // Verify required fields exist
    assert!(json_value.get("spi").is_some(), "Should have spi field");
    assert!(
        json_value.get("master_keys").is_some(),
        "Should have master_keys field"
    );
    assert!(
        json_value.get("crypto_alg").is_some(),
        "Should have crypto_alg field"
    );
    assert!(
        json_value.get("psp_encap").is_some(),
        "Should have psp_encap field"
    );
}

/// Test creating config with specific parameters and verifying they are saved
#[test]
fn test_config_parameters_are_saved() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.json");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("--json")
        .arg("--spi")
        .arg("0xABCDEF12")
        .arg("--mode")
        .arg("tunnel")
        .arg("--alg")
        .arg("aes-gcm128")
        .arg("--crypto-offset")
        .arg("3")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    let json_str = fs::read_to_string(&config_path).expect("Should read config");
    let config: PspConfig = serde_json::from_str(&json_str).expect("Should parse config");

    assert_eq!(config.spi, 0xABCDEF12);
    assert_eq!(config.crypto_alg, CryptoAlg::AesGcm128);
}

/// Test that text format config files can be created
#[test]
fn test_text_format_config_creation() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.cfg");

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Verify file exists and has content
    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).expect("Should read config");
    assert!(!content.is_empty(), "Config file should not be empty");

    // Verify it's not JSON (no opening brace on first line typically)
    assert!(
        !content.trim().starts_with('{'),
        "Text format should not start with JSON brace"
    );
}

/// Test config file permissions and readability
#[test]
fn test_config_file_is_readable() {
    use assert_cmd::Command;

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

    // Verify file can be read
    let metadata = fs::metadata(&config_path).expect("Should get metadata");
    assert!(metadata.is_file(), "Should be a file");
    assert!(metadata.len() > 0, "File should have content");

    // Verify file can be read as string
    let _content = fs::read_to_string(&config_path).expect("Should read as string");
}

/// Test that config files can be reused for multiple operations
#[test]
fn test_config_reuse() {
    use assert_cmd::Command;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("reusable.cfg");
    let pcap1_path = temp_dir.path().join("test1.pcap");
    let pcap2_path = temp_dir.path().join("test2.pcap");
    let enc1_path = temp_dir.path().join("enc1.pcap");
    let enc2_path = temp_dir.path().join("enc2.pcap");

    // Create one config
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("config")
        .arg("-c")
        .arg(&config_path)
        .assert()
        .success();

    // Use it for multiple operations
    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("1")
        .arg("-o")
        .arg(&pcap1_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&pcap1_path)
        .arg("-o")
        .arg(&enc1_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("create")
        .arg("pcap")
        .arg("-n")
        .arg("2")
        .arg("-o")
        .arg(&pcap2_path)
        .assert()
        .success();

    Command::cargo_bin("psp")
        .unwrap()
        .arg("encrypt")
        .arg("-c")
        .arg(&config_path)
        .arg("-i")
        .arg(&pcap2_path)
        .arg("-o")
        .arg(&enc2_path)
        .assert()
        .success();

    // Verify both operations succeeded
    assert!(enc1_path.exists());
    assert!(enc2_path.exists());
}
