use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "gui")]
use d4if_sign::gui::run_gui;
use d4if_sign::pdf_stamp::{sign_and_stamp_pdf, PdfStampRequest};
use d4if_sign::{
    extract_token_string, find_default_signing_key, generate_keypair, inspect_token,
    load_public_key, load_secret_key, parse_claim_kv, parse_duration_str, render_svg,
    render_terminal, sign_document, verify_token, write_key_file, write_qr, QrFormat, SignRequest,
};

#[derive(Parser)]
#[command(
    name = "sign",
    version,
    about = "Generator, editor QR PDF, & verifikator tanda tangan digital berbasis PASETO v4.public"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Membuat pasangan kunci asimetris Ed25519 PASERK v4 (k4.public & k4.secret)
    Keygen {
        /// Lokasi penyimpanan kunci privat (k4.secret)
        #[arg(long, default_value = "signing.key")]
        secret_out: PathBuf,
        /// Lokasi penyimpanan kunci publik (k4.public)
        #[arg(long, default_value = "verifying.key")]
        public_out: PathBuf,
        /// Tampilkan output sebagai JSON tanpa menulis file jika --stdout-only diaktifkan
        #[arg(long)]
        stdout_only: bool,
        /// Format output JSON
        #[arg(long)]
        json: bool,
    },
    /// Menandatangani dokumen atau metadata menjadi token PASETO v4.public dan QR Code
    Sign {
        /// Path berkas secret key atau string PASERK k4.secret.* (atau env PASETO_SECRET_KEY)
        #[arg(short, long, env = "PASETO_SECRET_KEY", default_value = "signing.key")]
        key: String,
        /// Path dokumen yang akan di-hash (SHA-256) dan ditandatangani
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Penerbit tanda tangan (claim: iss)
        #[arg(long)]
        issuer: Option<String>,
        /// Identitas penanda tangan, mis. kode dosen (claim: signer)
        #[arg(long)]
        signer: Option<String>,
        /// Nomor / ID dokumen (claim: jti)
        #[arg(long)]
        doc_id: Option<String>,
        /// Subjek / judul dokumen (claim: sub)
        #[arg(long)]
        subject: Option<String>,
        /// Penerima dokumen (claim: aud)
        #[arg(long)]
        audience: Option<String>,
        /// Masa berlaku token, mis. 30m, 24h, 365d (default: permanen / non-expiring)
        #[arg(long)]
        ttl: Option<String>,
        /// Footer PASETO (JSON object atau key ID teks)
        #[arg(long)]
        footer: Option<String>,
        /// Klaim tambahan KEY=VALUE (dapat diulang)
        #[arg(long = "claim")]
        claims: Vec<String>,
        /// Implicit assertion PASETO v4 (opsional)
        #[arg(long)]
        implicit_assert: Option<String>,
        /// URL dasar halaman validator untuk membungkus token di QR Code (isi "" untuk token mentah)
        #[arg(long, default_value = "https://repo.if.ulbi.ac.id/validate/")]
        verify_url: Option<String>,
        /// Path keluaran QR Code (.svg, .png, atau .txt)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Paksa format keluaran QR Code
        #[arg(long, value_enum)]
        format: Option<CliQrFormat>,
        /// Dimensi minimum QR Code dalam piksel (default: 320)
        #[arg(long, default_value_t = 320)]
        size: u32,
        /// Simpan token mentah v4.public ke berkas teks
        #[arg(long)]
        token_out: Option<PathBuf>,
        /// Tempelkan QR Code ke PDF secara incremental dan simpan ke berkas PDF baru
        #[arg(long)]
        pdf_out: Option<PathBuf>,
        /// Nomor halaman PDF (mulai dari 1) untuk --pdf-out
        #[arg(long, default_value_t = 1)]
        page: u32,
        /// Koordinat kiri-bawah X (dalam PDF point) untuk --pdf-out
        #[arg(long, default_value_t = 360.0)]
        x: f32,
        /// Koordinat kiri-bawah Y (dalam PDF point) untuk --pdf-out
        #[arg(long, default_value_t = 110.0)]
        y: f32,
        /// Ukuran sisi QR persegi (dalam PDF point) untuk --pdf-out
        #[arg(long, default_value_t = 88.0)]
        qr_size: f32,
        /// Format output JSON
        #[arg(long)]
        json: bool,
    },
    /// Membuka editor desktop GUI untuk menempel, menggeser, dan resize QR pada PDF
    #[cfg(feature = "gui")]
    Gui {
        /// Berkas PDF awal yang langsung dibuka di editor (opsional)
        #[arg(short, long)]
        pdf: Option<PathBuf>,
    },
    /// Memverifikasi token PASETO v4.public menggunakan public key dan mencocokkan dokumen
    Verify {
        /// Path berkas public key atau string PASERK k4.public.*
        #[arg(short = 'k', long, default_value = "verifying.key")]
        public_key: String,
        /// Token v4.public.*, URL validator, atau path berkas token
        #[arg(short, long)]
        token: String,
        /// Dokumen asli untuk verifikasi kecocokan hash SHA-256 (opsional)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Footer yang diharapkan (jika token memiliki footer)
        #[arg(long)]
        footer: Option<String>,
        /// Implicit assertion PASETO v4 (harus sama dengan saat signing)
        #[arg(long)]
        implicit_assert: Option<String>,
        /// Format output JSON
        #[arg(long)]
        json: bool,
    },
    /// Membaca isi payload dan footer token tanpa verifikasi kriptografis
    Inspect {
        /// Token v4.public.*, URL validator, atau path berkas token
        #[arg(short, long)]
        token: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliQrFormat {
    Svg,
    Png,
    Terminal,
}

impl From<CliQrFormat> for QrFormat {
    fn from(value: CliQrFormat) -> Self {
        match value {
            CliQrFormat::Svg => QrFormat::Svg,
            CliQrFormat::Png => QrFormat::Png,
            CliQrFormat::Terminal => QrFormat::Terminal,
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        #[cfg(feature = "gui")]
        {
            return run_gui(None);
        }
        #[cfg(not(feature = "gui"))]
        {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            return Ok(());
        }
    };

    match command {
        Commands::Keygen {
            secret_out,
            public_out,
            stdout_only,
            json,
        } => {
            let kp = generate_keypair()?;
            if !stdout_only {
                write_key_file(&secret_out, &kp.secret_key, true)?;
                write_key_file(&public_out, &kp.public_key, false)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&kp)?);
            } else {
                if !stdout_only {
                    println!("Secret key disimpan ke : {}", secret_out.display());
                    println!("Public key disimpan ke : {}", public_out.display());
                } else {
                    println!("Secret key : {}", kp.secret_key);
                }
                println!("Public key : {}", kp.public_key);
            }
        }
        Commands::Sign {
            key,
            file,
            issuer,
            signer,
            doc_id,
            subject,
            audience,
            ttl,
            footer,
            claims,
            implicit_assert,
            verify_url,
            out,
            format,
            size,
            token_out,
            pdf_out,
            page,
            x,
            y,
            qr_size,
            json,
        } => {
            let resolved_key = if key == "signing.key" && !std::path::Path::new(&key).is_file() {
                find_default_signing_key()
                    .map(|p| p.display().to_string())
                    .unwrap_or(key)
            } else {
                key
            };
            let secret = load_secret_key(&resolved_key)?;
            let ttl_secs = ttl.as_deref().map(parse_duration_str).transpose()?;
            let extra_claims = claims
                .iter()
                .map(|c| parse_claim_kv(c))
                .collect::<Result<Vec<_>, _>>()?;

            let result = if let Some(ref stamped_path) = pdf_out {
                let pdf_in = file
                    .clone()
                    .ok_or("Opsi --pdf-out wajib disertai --file <input.pdf>.")?;
                let stamped = sign_and_stamp_pdf(
                    &secret,
                    &PdfStampRequest {
                        pdf_in,
                        pdf_out: stamped_path.clone(),
                        page,
                        x,
                        y,
                        qr_size,
                        issuer,
                        signer,
                        doc_id,
                        subject,
                        audience,
                        ttl_secs,
                        footer,
                        extra_claims,
                        implicit_assert: implicit_assert.map(String::into_bytes),
                        verify_url,
                    },
                )?;
                stamped.sign_result
            } else {
                let req = SignRequest {
                    file,
                    issuer,
                    signer,
                    doc_id,
                    subject,
                    audience,
                    ttl_secs,
                    footer,
                    extra_claims,
                    implicit_assert: implicit_assert.map(String::into_bytes),
                    verify_url,
                };
                sign_document(&secret, &req)?
            };

            if let Some(ref t_path) = token_out {
                if let Some(parent) = t_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(t_path, format!("{}\n", result.token))?;
            }

            if let Some(ref qr_path) = out {
                write_qr(&result.qr_payload, qr_path, format.map(Into::into), size)?;
            } else if !json {
                match format {
                    Some(CliQrFormat::Svg) => {
                        println!("{}", render_svg(&result.qr_payload, size)?);
                    }
                    _ => {
                        println!("{}", render_terminal(&result.qr_payload)?);
                    }
                }
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Token      : {}", result.token);
                println!("Public key : {}", result.public_key);
                if let Some(ref hash) = result.doc_hash {
                    println!("SHA-256    : {hash}");
                }
                if let Some(ref qr_path) = out {
                    println!("QR Code    : {}", qr_path.display());
                }
            }
        }
        Commands::Verify {
            public_key,
            token,
            file,
            footer,
            implicit_assert,
            json,
        } => {
            let pub_k = load_public_key(&public_key)?;
            let result = verify_token(
                &pub_k,
                &token,
                file.as_deref(),
                footer.as_deref(),
                implicit_assert.as_deref().map(str::as_bytes),
            )?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Status tanda tangan : {}",
                    if result.valid { "VALID" } else { "TIDAK COCOK" }
                );
                if let Some(matched) = result.file_hash_matched {
                    println!(
                        "Integritas berkas   : {}",
                        if matched {
                            "COCOK (SHA-256 sesuai)"
                        } else {
                            "TIDAK COCOK (berkas berubah!)"
                        }
                    );
                }
                if let Some(ref f) = result.footer {
                    println!("Footer              : {f}");
                }
                println!(
                    "Claims              :\n{}",
                    serde_json::to_string_pretty(&result.claims)?
                );
            }

            if !result.valid {
                return Err("Hash dokumen tidak cocok dengan tanda tangan digital.".into());
            }
        }
        Commands::Inspect { token } => {
            let normalized = extract_token_string(&token)?;
            let info = inspect_token(&normalized)?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        #[cfg(feature = "gui")]
        Commands::Gui { pdf } => {
            run_gui(pdf)?;
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
