//! Integration tests for d4if-sign

use std::fs;
use std::process::Command;

use tempfile::tempdir;

fn sign_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sign")
}

#[test]
fn test_keygen() {
    let dir = tempdir().expect("create tempdir");
    let secret_path = dir.path().join("test_secret.key");
    let public_path = dir.path().join("test_public.key");

    let output = Command::new(sign_bin())
        .args([
            "keygen",
            "--secret-out",
            secret_path.to_str().unwrap(),
            "--public-out",
            public_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute keygen");

    assert!(
        output.status.success(),
        "Keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(secret_path.is_file(), "Secret key file not created");
    assert!(public_path.is_file(), "Public key file not created");
}

#[test]
fn test_sign_and_verify() {
    let dir = tempdir().expect("create tempdir");
    let secret_path = dir.path().join("test_sign_secret.key");
    let public_path = dir.path().join("test_sign_public.key");
    let doc_path = dir.path().join("test_document.txt");
    let svg_path = dir.path().join("test_signature.svg");
    let token_path = dir.path().join("test_token.paseto");

    let keygen_output = Command::new(sign_bin())
        .args([
            "keygen",
            "--secret-out",
            secret_path.to_str().unwrap(),
            "--public-out",
            public_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute keygen");

    assert!(keygen_output.status.success(), "Keygen failed");

    fs::write(&doc_path, "This is a test document for signing.")
        .expect("Failed to create test document");

    let sign_output = Command::new(sign_bin())
        .args([
            "sign",
            "--key",
            secret_path.to_str().unwrap(),
            "--file",
            doc_path.to_str().unwrap(),
            "--issuer",
            "Test Issuer",
            "--signer",
            "Test Signer",
            "--doc-id",
            "TEST-001",
            "--subject",
            "Test Document",
            "--out",
            svg_path.to_str().unwrap(),
            "--token-out",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute sign");

    assert!(
        sign_output.status.success(),
        "Sign failed: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );

    assert!(svg_path.is_file(), "Signature SVG not created");
    assert!(token_path.is_file(), "Token file not created");

    let verify_output = Command::new(sign_bin())
        .args([
            "verify",
            "--public-key",
            public_path.to_str().unwrap(),
            "--token",
            token_path.to_str().unwrap(),
            "--file",
            doc_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute verify");

    assert!(
        verify_output.status.success(),
        "Verification failed: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
}

#[test]
fn test_inspect() {
    let dir = tempdir().expect("create tempdir");
    let secret_path = dir.path().join("test_inspect_secret.key");
    let public_path = dir.path().join("test_inspect_public.key");
    let doc_path = dir.path().join("test_inspect_doc.txt");
    let token_path = dir.path().join("test_inspect_token.paseto");

    let keygen_output = Command::new(sign_bin())
        .args([
            "keygen",
            "--secret-out",
            secret_path.to_str().unwrap(),
            "--public-out",
            public_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute keygen");

    assert!(keygen_output.status.success(), "Keygen failed");

    fs::write(&doc_path, "Test document for inspection.").expect("Failed to create test document");

    let sign_output = Command::new(sign_bin())
        .args([
            "sign",
            "--key",
            secret_path.to_str().unwrap(),
            "--file",
            doc_path.to_str().unwrap(),
            "--issuer",
            "Test Inspector",
            "--signer",
            "Inspector",
            "--doc-id",
            "INSPECT-001",
            "--subject",
            "Inspection Test",
            "--token-out",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute sign");

    assert!(sign_output.status.success(), "Sign failed");

    let inspect_output = Command::new(sign_bin())
        .args(["inspect", "--token", token_path.to_str().unwrap()])
        .output()
        .expect("Failed to execute inspect");

    assert!(
        inspect_output.status.success(),
        "Inspect failed: {}",
        String::from_utf8_lossy(&inspect_output.stderr)
    );

    let output_str = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(
        output_str.contains("Test Inspector"),
        "Issuer not found in inspect output"
    );
    assert!(
        output_str.contains("Inspector"),
        "Signer not found in inspect output"
    );
}
