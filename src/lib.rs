use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use image::Luma;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::footer::Footer;
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::paserk::FormatAsPaserk;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{public, Public};
use qrcode::render::{svg, unicode};
use qrcode::{EcLevel, QrCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(feature = "gui")]
pub mod gui;
pub mod pdf_stamp;

#[derive(Debug)]
pub struct AppError(String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<pasetors::errors::Error> for AppError {
    fn from(err: pasetors::errors::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedKeypair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDigest {
    pub file_name: Option<String>,
    pub size_bytes: u64,
    pub sha256_hex: String,
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub file: Option<PathBuf>,
    pub issuer: Option<String>,
    pub signer: Option<String>,
    pub doc_id: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub ttl_secs: Option<u64>,
    pub footer: Option<String>,
    pub extra_claims: Vec<(String, String)>,
    pub implicit_assert: Option<Vec<u8>>,
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignResult {
    pub token: String,
    pub qr_payload: String,
    pub public_key: String,
    pub doc_hash: Option<String>,
    pub doc_name: Option<String>,
    pub doc_size: Option<u64>,
    pub claims: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub claims: Value,
    pub footer: Option<String>,
    pub file_hash_matched: Option<bool>,
    pub actual_file_hash: Option<String>,
    pub expected_file_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub header: String,
    pub claims: Value,
    pub footer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrFormat {
    Svg,
    Png,
    Terminal,
}

impl QrFormat {
    pub fn from_path(path: &Path) -> Result<Self, AppError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        match ext.as_deref() {
            Some("svg") => Ok(Self::Svg),
            Some("png") => Ok(Self::Png),
            Some("txt") => Ok(Self::Terminal),
            _ => Err(AppError(format!(
                "Ekstensi keluaran QR tidak dikenali pada '{}'. Gunakan .svg, .png, .txt, atau tentukan --format.",
                path.display()
            ))),
        }
    }
}

pub fn generate_keypair() -> Result<GeneratedKeypair, AppError> {
    let kp = AsymmetricKeyPair::<V4>::generate()?;
    let mut public_key = String::new();
    let mut secret_key = String::new();
    FormatAsPaserk::fmt(&kp.public, &mut public_key)
        .map_err(|e| AppError(format!("Gagal memformat public key PASERK: {e}")))?;
    FormatAsPaserk::fmt(&kp.secret, &mut secret_key)
        .map_err(|e| AppError(format!("Gagal memformat secret key PASERK: {e}")))?;
    Ok(GeneratedKeypair {
        public_key,
        secret_key,
    })
}

pub fn write_key_file(
    path: &Path,
    content: &str,
    #[allow(unused_variables)] secret: bool,
) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, format!("{content}\n"))?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_secret_key(input: &str) -> Result<AsymmetricSecretKey<V4>, AppError> {
    let raw = read_inline_or_file(input)?;
    AsymmetricSecretKey::<V4>::try_from(raw.as_str())
        .map_err(|e| AppError(format!("Secret key PASERK v4 tidak valid: {e}")))
}

/// Locate a default `signing.key` across CWD, binary sibling dir, user config dir
/// (`~/.config/d4if/signing.key` / `%APPDATA%\d4if\signing.key`), or saved last key path.
pub fn find_default_signing_key() -> Option<PathBuf> {
    let cwd_key = PathBuf::from("signing.key");
    if cwd_key.is_file() {
        return Some(cwd_key);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("signing.key");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    if let Some(cfg_dir) = user_config_dir() {
        let cfg_key = cfg_dir.join("signing.key");
        if cfg_key.is_file() {
            return Some(cfg_key);
        }
        let last_path_file = cfg_dir.join("last_key_path");
        if let Ok(saved) = fs::read_to_string(&last_path_file) {
            let saved_path = PathBuf::from(saved.trim());
            if saved_path.is_file() {
                return Some(saved_path);
            }
        }
    }
    None
}

/// Persist the last chosen `signing.key` path so `sign` works from any folder.
pub fn remember_signing_key_path(path: &Path) {
    if !path.is_file() {
        return;
    }
    let Some(cfg_dir) = user_config_dir() else {
        return;
    };
    let abs = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if fs::create_dir_all(&cfg_dir).is_ok() {
        let _ = fs::write(
            cfg_dir.join("last_key_path"),
            abs.to_string_lossy().as_bytes(),
        );
    }
}

fn user_config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return Some(PathBuf::from(appdata).join("d4if"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg).join("d4if"));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("d4if"))
}

pub fn load_public_key(input: &str) -> Result<AsymmetricPublicKey<V4>, AppError> {
    let raw = read_inline_or_file(input)?;
    AsymmetricPublicKey::<V4>::try_from(raw.as_str())
        .map_err(|e| AppError(format!("Public key PASERK v4 tidak valid: {e}")))
}

pub fn derive_public_paserk(secret: &AsymmetricSecretKey<V4>) -> Result<String, AppError> {
    let pub_key = AsymmetricPublicKey::<V4>::try_from(secret)
        .map_err(|e| AppError(format!("Gagal menurunkan public key: {e}")))?;
    let mut public_paserk = String::new();
    FormatAsPaserk::fmt(&pub_key, &mut public_paserk)
        .map_err(|e| AppError(format!("Gagal memformat public key PASERK: {e}")))?;
    Ok(public_paserk)
}

fn read_inline_or_file(input: &str) -> Result<String, AppError> {
    let trimmed = input.trim();
    if trimmed.starts_with("k4.secret.")
        || trimmed.starts_with("k4.public.")
        || trimmed.starts_with("v4.public.")
    {
        return Ok(trimmed.to_string());
    }
    let path = Path::new(trimmed);
    if path.is_file() {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }
    Ok(trimmed.to_string())
}

pub fn sha256_file(path: &Path) -> Result<FileDigest, AppError> {
    let file = File::open(path)
        .map_err(|e| AppError(format!("Gagal membuka dokumen '{}': {e}", path.display())))?;
    let metadata = file.metadata()?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(ToString::to_string);

    Ok(FileDigest {
        file_name,
        size_bytes: metadata.len(),
        sha256_hex: hex::encode(digest),
    })
}

pub fn parse_duration_str(raw: &str) -> Result<u64, AppError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(AppError("Durasi TTL tidak boleh kosong.".to_string()));
    }
    let (num_part, multiplier) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400u64)
    } else {
        (s, 1u64)
    };

    let value: u64 = num_part.trim().parse().map_err(|_| {
        AppError(format!(
            "Format TTL tidak valid: '{raw}'. Contoh: 30m, 24h, 365d."
        ))
    })?;
    if value == 0 {
        return Err(AppError("Durasi TTL harus lebih besar dari 0.".to_string()));
    }
    value
        .checked_mul(multiplier)
        .ok_or_else(|| AppError(format!("Durasi TTL terlalu besar: '{raw}'.")))
}

fn build_footer(raw: Option<&str>) -> Result<Option<Footer>, AppError> {
    let Some(text) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut footer = Footer::new();
    if text.starts_with('{') {
        footer
            .parse_string(text)
            .map_err(|e| AppError(format!("Footer JSON PASETO tidak valid: {e}")))?;
    } else if text.starts_with("k4.pid.") {
        let id = pasetors::paserk::Id::try_from(text)
            .map_err(|e| AppError(format!("PASERK key ID footer tidak valid: {e}")))?;
        footer.key_id(&id);
    } else {
        let json_footer = serde_json::json!({ "kid": text }).to_string();
        footer
            .parse_string(&json_footer)
            .map_err(|e| AppError(format!("Gagal mengatur key_id footer: {e}")))?;
    }
    Ok(Some(footer))
}

pub fn sign_document(
    secret: &AsymmetricSecretKey<V4>,
    req: &SignRequest,
) -> Result<SignResult, AppError> {
    let mut claims = match req.ttl_secs {
        Some(secs) => Claims::new_expires_in(&Duration::from_secs(secs))?,
        None => {
            let mut c = Claims::new()?;
            c.non_expiring();
            c
        }
    };

    if let Some(iss) = req
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        claims.issuer(iss)?;
    }
    if let Some(sub) = req
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        claims.subject(sub)?;
    }
    if let Some(aud) = req
        .audience
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        claims.audience(aud)?;
    }
    if let Some(jti) = req
        .doc_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        claims.token_identifier(jti)?;
    }
    if let Some(signer) = req
        .signer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        claims.add_additional("signer", signer)?;
    }

    let digest = match &req.file {
        Some(path) => Some(sha256_file(path)?),
        None => None,
    };

    if let Some(ref d) = digest {
        claims.add_additional("doc_hash", d.sha256_hex.as_str())?;
        claims.add_additional("doc_alg", "sha256")?;
        claims.add_additional("doc_size", d.size_bytes)?;
        if let Some(ref name) = d.file_name {
            claims.add_additional("doc_name", name.as_str())?;
        }
    }

    for (key, value) in &req.extra_claims {
        let parsed_val: Value =
            serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.clone()));
        claims.add_additional(key, parsed_val)?;
    }

    let footer = build_footer(req.footer.as_deref())?;
    let token = public::sign(
        secret,
        &claims,
        footer.as_ref(),
        req.implicit_assert.as_deref(),
    )?;

    let qr_payload = match req
        .verify_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(base) => format_verify_url(base, &token),
        None => token.clone(),
    };

    let claims_json: Value = serde_json::from_str(&claims.to_string()?)?;
    let public_key = derive_public_paserk(secret)?;

    Ok(SignResult {
        token,
        qr_payload,
        public_key,
        doc_hash: digest.as_ref().map(|d| d.sha256_hex.clone()),
        doc_name: digest.as_ref().and_then(|d| d.file_name.clone()),
        doc_size: digest.as_ref().map(|d| d.size_bytes),
        claims: claims_json,
    })
}

fn format_verify_url(base_url: &str, token: &str) -> String {
    if base_url.contains("#token=") || base_url.contains("?token=") {
        format!("{base_url}{token}")
    } else if base_url.contains('#') {
        format!("{base_url}&token={token}")
    } else {
        format!("{base_url}#token={token}")
    }
}

pub fn extract_token_string(input: &str) -> Result<String, AppError> {
    let raw = read_inline_or_file(input)?;
    let trimmed = raw.trim();
    if trimmed.starts_with("v4.public.") {
        return Ok(trimmed.to_string());
    }
    if let Some(idx) = trimmed.find("token=") {
        let after = &trimmed[idx + "token=".len()..];
        let token_part = after.split(&['&', '#'][..]).next().unwrap_or("").trim();
        if token_part.starts_with("v4.public.") {
            return Ok(token_part.to_string());
        }
    }
    Err(AppError(
        "Input tidak mengandung token PASETO v4.public yang valid.".to_string(),
    ))
}

pub fn verify_token(
    public_key: &AsymmetricPublicKey<V4>,
    token_input: &str,
    expected_file: Option<&Path>,
    expected_footer: Option<&str>,
    implicit_assert: Option<&[u8]>,
) -> Result<VerifyResult, AppError> {
    let token_str = extract_token_string(token_input)?;
    let untrusted = UntrustedToken::<Public, V4>::try_from(token_str.as_str())
        .map_err(|e| AppError(format!("Format token PASETO v4.public tidak valid: {e}")))?;

    let mut rules = ClaimsValidationRules::new();
    rules.allow_non_expiring();

    let footer = build_footer(expected_footer)?;
    let trusted = public::verify(
        public_key,
        &untrusted,
        &rules,
        footer.as_ref(),
        implicit_assert,
    )
    .map_err(|e| AppError(format!("Verifikasi tanda tangan gagal: {e}")))?;

    let claims: Value = serde_json::from_str(trusted.payload())?;
    let footer_str = String::from_utf8_lossy(trusted.footer());
    let footer_trimmed = footer_str.trim();
    let footer_out = if footer_trimmed.is_empty() {
        None
    } else {
        Some(footer_trimmed.to_string())
    };

    let expected_file_hash = claims
        .get("doc_hash")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let doc_base_len = claims
        .get("doc_base_len")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok());

    let (file_hash_matched, actual_file_hash) = match expected_file {
        Some(path) => match expected_file_hash.as_deref() {
            Some(expected) => {
                let (matched, actual_hash) =
                    pdf_stamp::verify_file_integrity(path, expected, doc_base_len)?;
                (Some(matched), Some(actual_hash))
            }
            None => {
                let digest = sha256_file(path)?;
                (None, Some(digest.sha256_hex))
            }
        },
        None => (None, None),
    };

    Ok(VerifyResult {
        valid: file_hash_matched.unwrap_or(true),
        claims,
        footer: footer_out,
        file_hash_matched,
        actual_file_hash,
        expected_file_hash,
    })
}

pub fn inspect_token(token_input: &str) -> Result<InspectResult, AppError> {
    let token_str = extract_token_string(token_input)?;
    let untrusted = UntrustedToken::<Public, V4>::try_from(token_str.as_str())
        .map_err(|e| AppError(format!("Format token PASETO v4.public tidak valid: {e}")))?;

    let payload_str = String::from_utf8_lossy(untrusted.untrusted_payload());
    let claims: Value = serde_json::from_str(&payload_str)
        .unwrap_or_else(|_| Value::String(payload_str.into_owned()));
    let footer_str = String::from_utf8_lossy(untrusted.untrusted_footer());
    let footer_raw = footer_str.trim();
    let footer = if footer_raw.is_empty() {
        None
    } else {
        Some(footer_raw.to_string())
    };

    Ok(InspectResult {
        header: "v4.public.".to_string(),
        claims,
        footer,
    })
}

pub fn render_svg(payload: &str, min_size: u32) -> Result<String, AppError> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| AppError(format!("Payload terlalu panjang untuk QR Code: {e}")))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(min_size, min_size)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

pub fn render_png(payload: &str, path: &Path, min_size: u32) -> Result<(), AppError> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| AppError(format!("Payload terlalu panjang untuk QR Code: {e}")))?;
    let image = code
        .render::<Luma<u8>>()
        .min_dimensions(min_size, min_size)
        .dark_color(Luma([0u8]))
        .light_color(Luma([255u8]))
        .build();
    image
        .save(path)
        .map_err(|e| AppError(format!("Gagal menyimpan PNG '{}': {e}", path.display())))
}

pub fn render_terminal(payload: &str) -> Result<String, AppError> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| AppError(format!("Payload terlalu panjang untuk QR Code: {e}")))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build())
}

pub fn write_qr(
    payload: &str,
    out_path: &Path,
    format: Option<QrFormat>,
    min_size: u32,
) -> Result<QrFormat, AppError> {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let fmt = match format {
        Some(f) => f,
        None => QrFormat::from_path(out_path)?,
    };
    match fmt {
        QrFormat::Svg => fs::write(out_path, render_svg(payload, min_size)?)?,
        QrFormat::Png => render_png(payload, out_path, min_size)?,
        QrFormat::Terminal => fs::write(out_path, render_terminal(payload)?)?,
    }
    Ok(fmt)
}

pub fn parse_claim_kv(raw: &str) -> Result<(String, String), AppError> {
    let Some((k, v)) = raw.split_once('=') else {
        return Err(AppError(format!(
            "Format --claim harus KEY=VALUE, ditemukan '{raw}'."
        )));
    };
    let key = k.trim();
    if key.is_empty() {
        return Err(AppError(
            "Nama kunci --claim tidak boleh kosong.".to_string(),
        ));
    }
    Ok((key.to_string(), v.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("d4if_sign_test_{nanos}_{name}"))
    }

    #[test]
    fn keygen_roundtrip() {
        let kp = generate_keypair().expect("keygen");
        assert!(kp.public_key.starts_with("k4.public."));
        assert!(kp.secret_key.starts_with("k4.secret."));

        let sec = load_secret_key(&kp.secret_key).expect("parse secret");
        let pub_k = load_public_key(&kp.public_key).expect("parse public");
        let derived = derive_public_paserk(&sec).expect("derive");
        assert_eq!(derived, kp.public_key);

        let mut derived_parsed = String::new();
        FormatAsPaserk::fmt(&pub_k, &mut derived_parsed).expect("fmt");
        assert_eq!(derived_parsed, kp.public_key);
    }

    #[test]
    fn sign_and_verify_document_roundtrip() {
        let kp = generate_keypair().expect("keygen");
        let sec = load_secret_key(&kp.secret_key).expect("sec");
        let pub_k = load_public_key(&kp.public_key).expect("pub");

        let doc_path = temp_path("surat.txt");
        fs::write(&doc_path, b"Surat Resmi Prodi D4TI ULBI").expect("write doc");

        let req = SignRequest {
            file: Some(doc_path.clone()),
            issuer: Some("Prodi D4TI ULBI".to_string()),
            signer: Some("NN257L".to_string()),
            doc_id: Some("SK-001".to_string()),
            subject: Some("Surat Keterangan".to_string()),
            audience: None,
            ttl_secs: None,
            footer: Some("d4if-ulbi-2026".to_string()),
            extra_claims: vec![("prodi".to_string(), "D4TI".to_string())],
            implicit_assert: None,
            verify_url: Some("https://d4if.github.io/validate/".to_string()),
        };

        let signed = sign_document(&sec, &req).expect("sign");
        assert!(signed.token.starts_with("v4.public."));
        assert!(signed
            .qr_payload
            .starts_with("https://d4if.github.io/validate/#token=v4.public."));
        assert!(signed.doc_hash.is_some());

        let verified = verify_token(
            &pub_k,
            &signed.qr_payload,
            Some(&doc_path),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify");
        assert!(verified.valid);
        assert_eq!(verified.file_hash_matched, Some(true));
        assert_eq!(verified.claims["iss"], "Prodi D4TI ULBI");
        assert_eq!(verified.claims["signer"], "NN257L");

        // Tampered document must fail hash check
        let tampered_path = temp_path("surat_tampered.txt");
        fs::write(&tampered_path, b"Surat Palsu").expect("write tampered");
        let tampered_check = verify_token(
            &pub_k,
            &signed.token,
            Some(&tampered_path),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify tampered");
        assert!(!tampered_check.valid);
        assert_eq!(tampered_check.file_hash_matched, Some(false));

        let _ = fs::remove_file(doc_path);
        let _ = fs::remove_file(tampered_path);
    }

    #[test]
    fn qr_svg_and_png_rendering() {
        let kp = generate_keypair().expect("keygen");
        let sec = load_secret_key(&kp.secret_key).expect("sec");
        let req = SignRequest {
            file: None,
            issuer: Some("D4TI".to_string()),
            signer: None,
            doc_id: None,
            subject: Some("Test".to_string()),
            audience: None,
            ttl_secs: Some(3600),
            footer: None,
            extra_claims: vec![],
            implicit_assert: None,
            verify_url: None,
        };
        let signed = sign_document(&sec, &req).expect("sign");

        let svg = render_svg(&signed.qr_payload, 256).expect("svg");
        assert!(svg.contains("<svg"));

        let png_path = temp_path("qr.png");
        render_png(&signed.qr_payload, &png_path, 256).expect("png");
        let bytes = fs::read(&png_path).expect("read png");
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        let _ = fs::remove_file(png_path);
    }

    #[test]
    fn parse_ttl_durations() {
        assert_eq!(parse_duration_str("45").unwrap(), 45);
        assert_eq!(parse_duration_str("30s").unwrap(), 30);
        assert_eq!(parse_duration_str("10m").unwrap(), 600);
        assert_eq!(parse_duration_str("2h").unwrap(), 7200);
        assert_eq!(parse_duration_str("7d").unwrap(), 604_800);
        assert!(parse_duration_str("0d").is_err());
        assert!(parse_duration_str("abc").is_err());
    }
}
