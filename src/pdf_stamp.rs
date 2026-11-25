use std::path::Path;

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, IncrementalDocument, Object, Stream};
use qrcode::{Color as QrColor, EcLevel, QrCode};
use sha2::{Digest, Sha256};

use crate::{sign_document, AppError, SignRequest, SignResult};

/// Request to sign a PDF document and stamp a QR code via PDF incremental update.
#[derive(Debug, Clone)]
pub struct PdfStampRequest {
    pub pdf_in: std::path::PathBuf,
    pub pdf_out: std::path::PathBuf,
    /// 1-based page number.
    pub page: u32,
    /// Bottom-left X coordinate in PDF points.
    pub x: f32,
    /// Bottom-left Y coordinate in PDF points.
    pub y: f32,
    /// Square QR width/height in PDF points.
    pub qr_size: f32,
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

/// Result of signing and stamping a PDF document.
#[derive(Debug, Clone)]
pub struct PdfStampResult {
    pub sign_result: SignResult,
    pub doc_base_len: usize,
    pub output_path: std::path::PathBuf,
}

/// Information about a single PDF page dimensions (in PDF points).
#[derive(Debug, Clone, Copy)]
pub struct PdfPageMetrics {
    pub width_pt: f32,
    pub height_pt: f32,
}

/// Compute SHA-256 hex digest of an in-memory byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Check that the appended incremental update contains exactly one `%%EOF` marker
/// at the end of the file, ensuring no extra revisions were appended after stamping.
pub fn has_single_incremental_eof(tail: &[u8]) -> bool {
    let eof_marker = b"%%EOF";
    let mut count = 0usize;
    let mut last_pos = None;
    for (idx, window) in tail.windows(eof_marker.len()).enumerate() {
        if window == eof_marker {
            count += 1;
            last_pos = Some(idx);
        }
    }
    if count != 1 {
        return false;
    }
    let Some(pos) = last_pos else {
        return false;
    };
    let after = &tail[pos + eof_marker.len()..];
    after.iter().all(|b| b.is_ascii_whitespace())
}

/// Read page dimensions (`MediaBox` / `CropBox`) for all pages of a PDF using `lopdf`.
pub fn inspect_pdf_pages(pdf_bytes: &[u8]) -> Result<Vec<PdfPageMetrics>, AppError> {
    let doc =
        Document::load_mem(pdf_bytes).map_err(|e| AppError(format!("Gagal membaca PDF: {e}")))?;
    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(AppError("Berkas PDF tidak memiliki halaman.".to_string()));
    }

    let mut result = Vec::with_capacity(pages.len());
    for page_id in pages.values() {
        let (w, h) = page_dimensions(&doc, *page_id)?;
        result.push(PdfPageMetrics {
            width_pt: w,
            height_pt: h,
        });
    }
    Ok(result)
}

fn page_dimensions(doc: &Document, page_id: lopdf::ObjectId) -> Result<(f32, f32), AppError> {
    let dict = doc
        .get_dictionary(page_id)
        .map_err(|e| AppError(format!("Gagal membaca dictionary halaman PDF: {e}")))?;
    let box_obj = dict
        .get(b"CropBox")
        .or_else(|_| dict.get(b"MediaBox"))
        .or_else(|_| find_inherited_box(doc, dict));

    if let Ok(obj) = box_obj {
        if let Ok(arr) = resolve_array(doc, obj) {
            if arr.len() >= 4 {
                let x0 = obj_to_f32(&arr[0]).unwrap_or(0.0);
                let y0 = obj_to_f32(&arr[1]).unwrap_or(0.0);
                let x1 = obj_to_f32(&arr[2]).unwrap_or(595.28);
                let y1 = obj_to_f32(&arr[3]).unwrap_or(841.89);
                return Ok(((x1 - x0).abs().max(1.0), (y1 - y0).abs().max(1.0)));
            }
        }
    }
    Ok((595.28, 841.89))
}

fn find_inherited_box<'a>(doc: &'a Document, dict: &'a Dictionary) -> lopdf::Result<&'a Object> {
    let mut current = dict;
    for _ in 0..16 {
        let parent_ref = current.get(b"Parent")?.as_reference()?;
        let parent = doc.get_dictionary(parent_ref)?;
        if let Ok(b) = parent.get(b"CropBox").or_else(|_| parent.get(b"MediaBox")) {
            return Ok(b);
        }
        current = parent;
    }
    Err(lopdf::Error::DictKey("MediaBox".to_string()))
}

fn resolve_array<'a>(doc: &'a Document, obj: &'a Object) -> lopdf::Result<&'a Vec<Object>> {
    match obj {
        Object::Array(arr) => Ok(arr),
        Object::Reference(id) => doc.get_object(*id)?.as_array(),
        _ => Err(lopdf::Error::ObjectType {
            expected: "Array",
            found: "Other",
        }),
    }
}

fn obj_to_f32(obj: &Object) -> Option<f32> {
    match obj {
        Object::Integer(v) => Some(*v as f32),
        Object::Real(v) => Some(*v),
        _ => None,
    }
}

/// Build a lossless compressed grayscale PDF Image XObject stream for a QR payload.
fn build_qr_image_stream(payload: &str) -> Result<Stream, AppError> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| AppError(format!("Payload terlalu panjang untuk QR Code: {e}")))?;

    let modules = code.width();
    let quiet = 2usize;
    let scale = 4usize;
    let total_modules = modules + quiet * 2;
    let img_dim = total_modules * scale;

    let mut pixels = vec![255u8; img_dim * img_dim];
    for my in 0..modules {
        for mx in 0..modules {
            if code[(mx, my)] == QrColor::Dark {
                let px_x0 = (mx + quiet) * scale;
                let px_y0 = (my + quiet) * scale;
                for dy in 0..scale {
                    let row_start = (px_y0 + dy) * img_dim + px_x0;
                    pixels[row_start..row_start + scale].fill(0u8);
                }
            }
        }
    }

    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Image".to_vec()));
    dict.set("Width", Object::Integer(img_dim as i64));
    dict.set("Height", Object::Integer(img_dim as i64));
    dict.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));
    dict.set("BitsPerComponent", Object::Integer(8));

    let mut stream = Stream::new(dict, pixels);
    let _ = stream.compress();
    Ok(stream)
}

/// Sign a PDF document and append the QR stamp as an incremental PDF revision.
///
/// The original PDF bytes `[0..doc_base_len]` remain untouched at the start of the output
/// file, and both `doc_hash` (SHA-256 of those base bytes) and `doc_base_len` are embedded
/// inside the signed PASETO claims so verifiers can authenticate the base PDF bytes directly
/// from the stamped PDF file.
pub fn sign_and_stamp_pdf(
    secret: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>,
    req: &PdfStampRequest,
) -> Result<PdfStampResult, AppError> {
    let prev_bytes = std::fs::read(&req.pdf_in)
        .map_err(|e| AppError(format!("Gagal membaca PDF '{}': {e}", req.pdf_in.display())))?;
    let doc_base_len = prev_bytes.len();
    let base_hash = sha256_bytes(&prev_bytes);
    let file_name = req
        .pdf_in
        .file_name()
        .and_then(|n| n.to_str())
        .map(ToString::to_string);

    let mut extra_claims = req.extra_claims.clone();
    extra_claims.push(("doc_hash".to_string(), base_hash));
    extra_claims.push(("doc_alg".to_string(), "sha256".to_string()));
    extra_claims.push(("doc_size".to_string(), doc_base_len.to_string()));
    extra_claims.push(("doc_base_len".to_string(), doc_base_len.to_string()));
    if let Some(ref name) = file_name {
        extra_claims.push(("doc_name".to_string(), name.clone()));
    }

    let sign_req = SignRequest {
        file: None,
        issuer: req.issuer.clone(),
        signer: req.signer.clone(),
        doc_id: req.doc_id.clone(),
        subject: req.subject.clone(),
        audience: req.audience.clone(),
        ttl_secs: req.ttl_secs,
        footer: req.footer.clone(),
        extra_claims,
        implicit_assert: req.implicit_assert.clone(),
        verify_url: req.verify_url.clone(),
    };

    let mut sign_result = sign_document(secret, &sign_req)?;
    sign_result.doc_hash = sign_result
        .claims
        .get("doc_hash")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    sign_result.doc_name = file_name;
    sign_result.doc_size = Some(doc_base_len as u64);

    let prev_doc = Document::load_mem(&prev_bytes)
        .map_err(|e| AppError(format!("Gagal mem-parsing PDF: {e}")))?;
    let pages = prev_doc.get_pages();
    let page_id = *pages.get(&req.page).ok_or_else(|| {
        AppError(format!(
            "Halaman {} tidak ditemukan (PDF memiliki {} halaman).",
            req.page,
            pages.len()
        ))
    })?;

    let mut inc = IncrementalDocument::create_from(prev_bytes, prev_doc);
    let qr_stream = build_qr_image_stream(&sign_result.qr_payload)?;
    let qr_obj_id = inc.new_document.add_object(qr_stream);
    let xobj_name = format!("D4IFQR{}", qr_obj_id.0);
    inc.add_xobject(page_id, xobj_name.as_bytes(), qr_obj_id)
        .map_err(|e| AppError(format!("Gagal menambahkan XObject QR ke halaman PDF: {e}")))?;

    // Isolate existing page content with q/Q so any non-identity CTM left by the
    // original stream cannot skew or hide our stamped QR code.
    let q_open = Content {
        operations: vec![Operation::new("q", vec![])],
    }
    .encode()
    .map_err(|e| AppError(format!("Gagal menyandikan stream q: {e}")))?;
    let q_open_id = inc
        .new_document
        .add_object(Stream::new(Default::default(), q_open));

    let qr_draw = Content {
        operations: vec![
            Operation::new("Q", vec![]),
            Operation::new("q", vec![]),
            Operation::new(
                "cm",
                vec![
                    req.qr_size.into(),
                    0.into(),
                    0.into(),
                    req.qr_size.into(),
                    req.x.into(),
                    req.y.into(),
                ],
            ),
            Operation::new("Do", vec![Object::Name(xobj_name.into_bytes())]),
            Operation::new("Q", vec![]),
        ],
    }
    .encode()
    .map_err(|e| AppError(format!("Gagal menyandikan stream QR: {e}")))?;
    let qr_draw_id = inc
        .new_document
        .add_object(Stream::new(Default::default(), qr_draw));

    inc.opt_clone_object_to_new_document(page_id).map_err(|e| {
        AppError(format!(
            "Gagal mengkloning halaman ke revisi incremental: {e}"
        ))
    })?;

    let existing_contents = {
        let page_dict = inc
            .new_document
            .get_dictionary(page_id)
            .map_err(|e| AppError(format!("Gagal membaca dictionary halaman: {e}")))?;
        page_dict.get(b"Contents").ok().cloned()
    };

    let mut new_contents = vec![Object::Reference(q_open_id)];
    match existing_contents {
        Some(Object::Reference(id)) => {
            if let Ok(Object::Array(arr)) = inc.get_prev_documents().get_object(id) {
                new_contents.extend(arr.clone());
            } else {
                new_contents.push(Object::Reference(id));
            }
        }
        Some(Object::Array(arr)) => {
            new_contents.extend(arr);
        }
        _ => {}
    }
    new_contents.push(Object::Reference(qr_draw_id));

    let page_dict_mut = inc
        .new_document
        .get_object_mut(page_id)
        .and_then(Object::as_dict_mut)
        .map_err(|e| AppError(format!("Gagal memperbarui Contents halaman: {e}")))?;
    page_dict_mut.set("Contents", Object::Array(new_contents));

    if let Some(parent) = req.pdf_out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    inc.save(&req.pdf_out).map_err(|e| {
        AppError(format!(
            "Gagal menyimpan PDF hasil '{}': {e}",
            req.pdf_out.display()
        ))
    })?;

    Ok(PdfStampResult {
        sign_result,
        doc_base_len,
        output_path: req.pdf_out.clone(),
    })
}

/// Verify an expected `doc_hash` against a file on disk, supporting both raw files
/// and incrementally stamped PDFs that carry `doc_base_len`.
pub fn verify_file_integrity(
    path: &Path,
    expected_hash: &str,
    doc_base_len: Option<usize>,
) -> Result<(bool, String), AppError> {
    let bytes = std::fs::read(path)
        .map_err(|e| AppError(format!("Gagal membuka dokumen '{}': {e}", path.display())))?;
    let full_hash = sha256_bytes(&bytes);
    if expected_hash.eq_ignore_ascii_case(&full_hash) {
        return Ok((true, full_hash));
    }

    if let Some(base_len) = doc_base_len {
        if base_len > 0 && bytes.len() > base_len && bytes.starts_with(b"%PDF-") {
            let base_hash = sha256_bytes(&bytes[..base_len]);
            let single_revision = has_single_incremental_eof(&bytes[base_len..]);
            if expected_hash.eq_ignore_ascii_case(&base_hash) && single_revision {
                return Ok((true, base_hash));
            }
            return Ok((false, base_hash));
        }
    }

    Ok((false, full_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_keypair, load_public_key, load_secret_key, verify_token};
    use lopdf::{Document, Object, Stream};
    use tempfile::tempdir;

    fn create_minimal_pdf(path: &Path) {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            b"BT /F1 12 Tf 72 720 Td (Halo D4TI ULBI) Tj ET".to_vec(),
        ));
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Parent", Object::Reference(pages_id));
        page.set(
            "MediaBox",
            Object::Array(vec![0.into(), 0.into(), 595.into(), 842.into()]),
        );
        page.set("Contents", Object::Reference(content_id));
        let page_id = doc.add_object(page);

        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Count", Object::Integer(1));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        doc.objects.insert(pages_id, Object::Dictionary(pages));

        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let catalog_id = doc.add_object(catalog);
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(path).expect("save minimal pdf");
    }

    #[test]
    fn incremental_pdf_stamp_and_verify_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let pdf_in = dir.path().join("input.pdf");
        let pdf_out = dir.path().join("stamped.pdf");
        create_minimal_pdf(&pdf_in);
        let orig_bytes = std::fs::read(&pdf_in).expect("read orig");

        let kp = generate_keypair().expect("keygen");
        let sec = load_secret_key(&kp.secret_key).expect("sec");
        let pub_k = load_public_key(&kp.public_key).expect("pub");

        let req = PdfStampRequest {
            pdf_in: pdf_in.clone(),
            pdf_out: pdf_out.clone(),
            page: 1,
            x: 360.0,
            y: 120.0,
            qr_size: 90.0,
            issuer: Some("Prodi D4TI ULBI".to_string()),
            signer: Some("RMA".to_string()),
            doc_id: Some("SK-PDF-001".to_string()),
            subject: Some("Test PDF Stamp".to_string()),
            audience: None,
            ttl_secs: None,
            footer: Some("d4if-ulbi-2026".to_string()),
            extra_claims: vec![],
            implicit_assert: None,
            verify_url: Some("https://repo.if.ulbi.ac.id/validate/".to_string()),
        };

        let stamped = sign_and_stamp_pdf(&sec, &req).expect("stamp pdf");
        let stamped_bytes = std::fs::read(&pdf_out).expect("read stamped");
        assert!(stamped_bytes.len() > stamped.doc_base_len);
        assert_eq!(
            &stamped_bytes[..stamped.doc_base_len],
            orig_bytes.as_slice()
        );

        // Verify both original PDF and stamped PDF against token
        let v_orig = verify_token(
            &pub_k,
            &stamped.sign_result.qr_payload,
            Some(&pdf_in),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify orig");
        assert!(v_orig.valid);
        assert_eq!(v_orig.file_hash_matched, Some(true));

        let v_stamped = verify_token(
            &pub_k,
            &stamped.sign_result.qr_payload,
            Some(&pdf_out),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify stamped");
        assert!(v_stamped.valid);
        assert_eq!(v_stamped.file_hash_matched, Some(true));

        // Tampering with base bytes must fail
        let tampered_base = dir.path().join("tampered_base.pdf");
        let mut bad_bytes = stamped_bytes.clone();
        bad_bytes[10] ^= 0xff;
        std::fs::write(&tampered_base, &bad_bytes).expect("write tampered base");
        let v_bad_base = verify_token(
            &pub_k,
            &stamped.sign_result.qr_payload,
            Some(&tampered_base),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify bad base");
        assert!(!v_bad_base.valid);
        assert_eq!(v_bad_base.file_hash_matched, Some(false));

        // Appending another %%EOF revision after stamping must fail
        let tampered_rev = dir.path().join("tampered_rev.pdf");
        let mut extra_rev = stamped_bytes;
        extra_rev.extend_from_slice(b"\n%%EOF\n");
        std::fs::write(&tampered_rev, &extra_rev).expect("write tampered rev");
        let v_bad_rev = verify_token(
            &pub_k,
            &stamped.sign_result.qr_payload,
            Some(&tampered_rev),
            Some("d4if-ulbi-2026"),
            None,
        )
        .expect("verify bad rev");
        assert!(!v_bad_rev.valid);
        assert_eq!(v_bad_rev.file_hash_matched, Some(false));
    }
}
