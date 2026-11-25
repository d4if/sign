use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;
use egui_file_dialog::FileDialog;
use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{render, PixmapSettings, RenderCache, RenderSettings};
use qrcode::{Color as QrColor, EcLevel, QrCode};

use crate::pdf_stamp::{inspect_pdf_pages, sign_and_stamp_pdf, PdfPageMetrics, PdfStampRequest};
use crate::{load_secret_key, parse_duration_str};

const LECTURERS: [(&str, &str); 9] = [
    ("RAN", "Roni Andarsyah, S.T., M.Kom."),
    ("MYH", "M. Yusril Helmi Setyawan, S.Kom., M.Kom."),
    ("RMA", "Rolly Maulana Awangga, S.T., M.T., CAIP."),
    ("MNF", "Dr. Mohamad Nurkamal Fauzan, S.T., M.T."),
    ("CPY", "Cahyo Prianto, S.Pd., M.T."),
    (
        "SFP",
        "Dr. Syafrial Fachri Pane, S.T., M.T.I., EBDP., CDSP.",
    ),
    ("RHA", "Roni Habibi, S.Kom., M.T."),
    ("NHH", "Nisa Hanum Harani, S.Kom., M.T., CDSP."),
    ("RNS", "Rd. Nuraini Siti Fathonah, S.S., M.Hum."),
];

enum DialogPurpose {
    PickPdf,
    PickKey,
    SavePdf,
}

struct LoadedPdf {
    path: PathBuf,
    bytes: Arc<Vec<u8>>,
    pages: Vec<PdfPageMetrics>,
}

pub fn run_gui(initial_pdf: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 820.0])
            .with_min_inner_size([860.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "D4TI Sign - Editor QR Code PDF (PASETO v4.public)",
        options,
        Box::new(move |cc| Ok(Box::new(SignEditorApp::new(cc, initial_pdf)))),
    )
    .map_err(|e| format!("Gagal menjalankan antarmuka desktop: {e}").into())
}

struct SignEditorApp {
    file_dialog: FileDialog,
    dialog_purpose: Option<DialogPurpose>,

    pdf: Option<LoadedPdf>,
    current_page: usize,
    rendered_page: Option<usize>,
    page_texture: Option<egui::TextureHandle>,
    qr_preview_texture: Option<egui::TextureHandle>,

    // QR placement in PDF points (origin at bottom-left of page).
    qr_x_pt: f32,
    qr_y_pt: f32,
    qr_size_pt: f32,

    // Signing configuration & metadata.
    key_input: String,
    issuer: String,
    signer: String,
    doc_id: String,
    subject: String,
    footer: String,
    ttl: String,
    verify_url: String,

    status_ok: Option<String>,
    status_err: Option<String>,
}

impl SignEditorApp {
    fn new(_cc: &eframe::CreationContext<'_>, initial_pdf: Option<PathBuf>) -> Self {
        let default_key = find_default_signing_key()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "signing.key".to_string());

        let mut app = Self {
            file_dialog: FileDialog::new(),
            dialog_purpose: None,
            pdf: None,
            current_page: 1,
            rendered_page: None,
            page_texture: None,
            qr_preview_texture: None,
            qr_x_pt: 360.0,
            qr_y_pt: 110.0,
            qr_size_pt: 88.0,
            key_input: default_key,
            issuer: "Prodi D4TI ULBI".to_string(),
            signer: "RMA".to_string(),
            doc_id: "SK-2026-001".to_string(),
            subject: "Dokumen Resmi Prodi D4TI ULBI".to_string(),
            footer: "d4if-ulbi-2026".to_string(),
            ttl: String::new(),
            verify_url: "https://repo.if.ulbi.ac.id/validate/".to_string(),
            status_ok: None,
            status_err: None,
        };

        if let Some(path) = initial_pdf {
            app.load_pdf_file(&path);
        }

        app
    }

    fn load_pdf_file(&mut self, path: &Path) {
        self.status_ok = None;
        self.status_err = None;
        match std::fs::read(path) {
            Ok(raw) => match inspect_pdf_pages(&raw) {
                Ok(pages) => {
                    let first = pages[0];
                    self.qr_size_pt = 88.0_f32.min(first.width_pt * 0.35);
                    self.qr_x_pt =
                        (first.width_pt * 0.63).min((first.width_pt - self.qr_size_pt).max(0.0));
                    self.qr_y_pt =
                        (first.height_pt * 0.16).min((first.height_pt - self.qr_size_pt).max(0.0));
                    self.current_page = 1;
                    self.rendered_page = None;
                    self.page_texture = None;
                    self.pdf = Some(LoadedPdf {
                        path: path.to_path_buf(),
                        bytes: Arc::new(raw),
                        pages,
                    });
                }
                Err(e) => {
                    self.status_err = Some(e.to_string());
                }
            },
            Err(e) => {
                self.status_err = Some(format!("Gagal membaca '{}': {e}", path.display()));
            }
        }
    }

    fn ensure_page_texture(&mut self, ctx: &egui::Context) {
        let Some(pdf_state) = &self.pdf else {
            return;
        };
        if self.rendered_page == Some(self.current_page) && self.page_texture.is_some() {
            return;
        }

        let pdf_data = Arc::clone(&pdf_state.bytes);
        let page_idx = self.current_page.saturating_sub(1);
        match Pdf::new(pdf_data) {
            Ok(parsed) => {
                let pages = parsed.pages();
                if let Some(page) = pages.get(page_idx) {
                    let cache = RenderCache::new();
                    let pixmap = render(
                        page,
                        &cache,
                        &InterpreterSettings::default(),
                        &RenderSettings::default(),
                        &PixmapSettings {
                            x_scale: 1.75,
                            y_scale: 1.75,
                            bg_color: WHITE,
                        },
                    );
                    let w = usize::from(pixmap.width());
                    let h = usize::from(pixmap.height());
                    let rgba = pixmap.data_as_u8_slice();
                    let image = egui::ColorImage::from_rgba_unmultiplied([w, h], rgba);
                    let tex = ctx.load_texture(
                        format!("pdf-page-{}", self.current_page),
                        image,
                        egui::TextureOptions::LINEAR,
                    );
                    self.page_texture = Some(tex);
                    self.rendered_page = Some(self.current_page);
                }
            }
            Err(e) => {
                self.status_err = Some(format!("Gagal merender pratinjau PDF: {e:?}"));
                self.rendered_page = Some(self.current_page);
            }
        }
    }

    fn ensure_qr_preview_texture(&mut self, ctx: &egui::Context) {
        if self.qr_preview_texture.is_some() {
            return;
        }
        if let Ok(code) = QrCode::with_error_correction_level(
            b"https://repo.if.ulbi.ac.id/validate/#preview-d4if-ulbi-2026",
            EcLevel::M,
        ) {
            let modules = code.width();
            let scale = 4usize;
            let quiet = 2usize;
            let dim = (modules + quiet * 2) * scale;
            let mut rgba = vec![255u8; dim * dim * 4];
            for my in 0..modules {
                for mx in 0..modules {
                    if code[(mx, my)] == QrColor::Dark {
                        let px_x0 = (mx + quiet) * scale;
                        let px_y0 = (my + quiet) * scale;
                        for dy in 0..scale {
                            for dx in 0..scale {
                                let idx = ((px_y0 + dy) * dim + (px_x0 + dx)) * 4;
                                rgba[idx] = 0;
                                rgba[idx + 1] = 0;
                                rgba[idx + 2] = 0;
                                rgba[idx + 3] = 255;
                            }
                        }
                    }
                }
            }
            let image = egui::ColorImage::from_rgba_unmultiplied([dim, dim], &rgba);
            self.qr_preview_texture =
                Some(ctx.load_texture("qr-overlay-preview", image, egui::TextureOptions::NEAREST));
        }
    }

    fn save_signed_pdf(&mut self, out_path: &Path) {
        self.status_ok = None;
        self.status_err = None;

        let Some(pdf_state) = &self.pdf else {
            self.status_err = Some("Pilih berkas PDF terlebih dahulu.".to_string());
            return;
        };

        let secret = match load_secret_key(&self.key_input) {
            Ok(s) => s,
            Err(e) => {
                self.status_err = Some(e.to_string());
                return;
            }
        };

        let ttl_secs = if self.ttl.trim().is_empty() {
            None
        } else {
            match parse_duration_str(&self.ttl) {
                Ok(secs) => Some(secs),
                Err(e) => {
                    self.status_err = Some(e.to_string());
                    return;
                }
            }
        };

        let req = PdfStampRequest {
            pdf_in: pdf_state.path.clone(),
            pdf_out: out_path.to_path_buf(),
            page: self.current_page as u32,
            x: self.qr_x_pt,
            y: self.qr_y_pt,
            qr_size: self.qr_size_pt,
            issuer: non_empty(&self.issuer),
            signer: non_empty(&self.signer),
            doc_id: non_empty(&self.doc_id),
            subject: non_empty(&self.subject),
            audience: None,
            ttl_secs,
            footer: non_empty(&self.footer),
            extra_claims: Vec::new(),
            implicit_assert: None,
            verify_url: non_empty(&self.verify_url),
        };

        match sign_and_stamp_pdf(&secret, &req) {
            Ok(res) => {
                let hash_short = res
                    .sign_result
                    .doc_hash
                    .as_deref()
                    .map(|h| &h[..16.min(h.len())])
                    .unwrap_or("-");
                self.status_ok = Some(format!(
                    "Berhasil disimpan ke:\n{}\n\nSHA-256 dasar ({} byte): {}...",
                    res.output_path.display(),
                    res.doc_base_len,
                    hash_short
                ));
            }
            Err(e) => {
                self.status_err = Some(e.to_string());
            }
        }
    }
}

impl eframe::App for SignEditorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.ensure_page_texture(&ctx);
        self.ensure_qr_preview_texture(&ctx);

        egui::Panel::left("controls-panel")
            .resizable(true)
            .default_size(350.0)
            .min_size(300.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("D4TI Sign - Editor QR PDF");
                    ui.label("Tempel, geser, dan ubah ukuran QR Code tanda tangan digital PASETO v4.public langsung pada PDF.");
                    ui.separator();

                    ui.strong("1. Berkas PDF");
                    ui.horizontal(|ui| {
                        if ui.button("Pilih PDF...").clicked() {
                            self.dialog_purpose = Some(DialogPurpose::PickPdf);
                            self.file_dialog.pick_file();
                        }
                        if let Some(pdf) = &self.pdf {
                            let name = pdf
                                .path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("PDF");
                            ui.label(name);
                        } else {
                            ui.weak("Belum ada PDF dipilih");
                        }
                    });

                    if let Some(pdf) = &self.pdf {
                        let total = pdf.pages.len();
                        ui.horizontal(|ui| {
                            if ui.add_enabled(self.current_page > 1, egui::Button::new("<")).clicked() {
                                self.current_page -= 1;
                                self.rendered_page = None;
                            }
                            ui.label(format!("Halaman {} dari {}", self.current_page, total));
                            if ui.add_enabled(self.current_page < total, egui::Button::new(">")).clicked() {
                                self.current_page += 1;
                                self.rendered_page = None;
                            }
                        });
                    }

                    ui.add_space(6.0);
                    ui.strong("2. Kunci Privat (signing.key)");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.key_input).desired_width(210.0));
                        if ui.button("Cari...").clicked() {
                            self.dialog_purpose = Some(DialogPurpose::PickKey);
                            self.file_dialog.pick_file();
                        }
                    });

                    ui.add_space(6.0);
                    ui.strong("3. Metadata Dokumen");

                    ui.label("Penerbit (iss)");
                    ui.text_edit_singleline(&mut self.issuer);

                    ui.label("Penanda Tangan (signer)");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.signer).desired_width(110.0));
                        egui::ComboBox::from_id_salt("signer-preset")
                            .selected_text("Pilih Dosen")
                            .show_ui(ui, |ui| {
                                for (code, name) in LECTURERS {
                                    if ui.selectable_label(self.signer == code, format!("{code} - {name}")).clicked() {
                                        self.signer = code.to_string();
                                    }
                                }
                            });
                    });

                    ui.label("Nomor / ID Dokumen (jti)");
                    ui.text_edit_singleline(&mut self.doc_id);

                    ui.label("Subjek / Perihal (sub)");
                    ui.text_edit_singleline(&mut self.subject);

                    ui.label("Footer / Key ID (kid)");
                    ui.text_edit_singleline(&mut self.footer);

                    ui.label("Masa Berlaku TTL (opsional, mis. 365d)");
                    ui.text_edit_singleline(&mut self.ttl);

                    ui.label("URL Validator");
                    ui.text_edit_singleline(&mut self.verify_url);

                    ui.add_space(6.0);
                    ui.strong("4. Posisi & Ukuran QR (pt)");
                    if let Some(pdf) = &self.pdf {
                        let page_m = pdf.pages[self.current_page - 1];
                        let max_qr = (page_m.width_pt.min(page_m.height_pt) * 0.6).max(40.0);
                        ui.add(egui::Slider::new(&mut self.qr_size_pt, 36.0..=max_qr).text("Ukuran"));
                        self.qr_x_pt = self.qr_x_pt.clamp(0.0, (page_m.width_pt - self.qr_size_pt).max(0.0));
                        self.qr_y_pt = self.qr_y_pt.clamp(0.0, (page_m.height_pt - self.qr_size_pt).max(0.0));
                        ui.small(format!(
                            "Koordinat PDF: x={:.1} pt, y={:.1} pt, ukuran={:.1} pt",
                            self.qr_x_pt, self.qr_y_pt, self.qr_size_pt
                        ));
                    } else {
                        ui.small("Pilih PDF untuk mengatur posisi & ukuran QR.");
                    }

                    ui.add_space(10.0);
                    let can_save = self.pdf.is_some();
                    if ui
                        .add_enabled(can_save, egui::Button::new("Tandatangani & Simpan PDF..."))
                        .clicked()
                    {
                        self.dialog_purpose = Some(DialogPurpose::SavePdf);
                        self.file_dialog.save_file();
                    }

                    if let Some(msg) = &self.status_ok {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(34, 160, 88), msg);
                    }
                    if let Some(err) = &self.status_err {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(220, 60, 60), err);
                    }
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            let Some(pdf_state) = &self.pdf else {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("Belum ada dokumen PDF");
                        ui.label("Klik 'Pilih PDF...' di panel kiri untuk memuat berkas PDF dan menempatkan QR Code.");
                    });
                });
                return;
            };

            let page_metrics = pdf_state.pages[self.current_page - 1];
            let Some(tex) = self.page_texture.clone() else {
                ui.centered_and_justified(|ui| {
                    ui.spinner();
                });
                return;
            };

            let avail = ui.available_size();
            let padding = 16.0;
            let max_w = (avail.x - padding * 2.0).max(120.0);
            let max_h = (avail.y - padding * 2.0).max(120.0);
            let aspect = page_metrics.width_pt / page_metrics.height_pt;

            let (disp_w, disp_h) = if max_w / max_h > aspect {
                (max_h * aspect, max_h)
            } else {
                (max_w, max_w / aspect)
            };

            let (outer_rect, _) = ui.allocate_exact_size(avail, egui::Sense::hover());
            let page_rect = egui::Rect::from_center_size(outer_rect.center(), egui::vec2(disp_w, disp_h));

            ui.painter().rect_filled(
                page_rect.expand(2.0),
                2.0,
                egui::Color32::from_gray(45),
            );
            ui.painter().image(
                tex.id(),
                page_rect,
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );

            let scale = page_rect.width() / page_metrics.width_pt;
            let px_size = self.qr_size_pt * scale;
            let px_left = page_rect.min.x + self.qr_x_pt * scale;
            let px_bottom = page_rect.max.y - self.qr_y_pt * scale;
            let qr_rect = egui::Rect::from_min_size(
                egui::pos2(px_left, px_bottom - px_size),
                egui::vec2(px_size, px_size),
            );

            if let Some(qr_tex) = &self.qr_preview_texture {
                ui.painter().image(
                    qr_tex.id(),
                    qr_rect,
                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                    egui::Color32::from_white_alpha(235),
                );
            } else {
                ui.painter().rect_filled(qr_rect, 2.0, egui::Color32::from_white_alpha(210));
            }

            ui.painter().rect_stroke(
                qr_rect,
                1.0,
                egui::Stroke::new(2.0, egui::Color32::from_rgb(31, 95, 190)),
                egui::StrokeKind::Outside,
            );

            // Resize handle at bottom-right corner.
            let handle_size = 14.0;
            let handle_rect = egui::Rect::from_center_size(
                qr_rect.max,
                egui::vec2(handle_size, handle_size),
            );
            let handle_resp = ui.interact(
                handle_rect,
                ui.make_persistent_id("qr-resize-handle"),
                egui::Sense::drag(),
            );
            if handle_resp.hovered() || handle_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeNwSe);
            }
            if handle_resp.dragged() {
                let delta = handle_resp.drag_delta();
                let delta_pt = (delta.x + delta.y) * 0.5 / scale;
                let max_qr = (page_metrics.width_pt.min(page_metrics.height_pt) * 0.6).max(40.0);
                let old_size = self.qr_size_pt;
                let new_size = (old_size + delta_pt).clamp(36.0, max_qr);
                // Keep top-left anchored while resizing from bottom-right.
                self.qr_y_pt -= new_size - old_size;
                self.qr_size_pt = new_size;
                self.qr_x_pt = self.qr_x_pt.clamp(0.0, (page_metrics.width_pt - new_size).max(0.0));
                self.qr_y_pt = self.qr_y_pt.clamp(0.0, (page_metrics.height_pt - new_size).max(0.0));
            }

            // Move drag across the QR body (only when not dragging resize handle).
            let move_resp = ui.interact(
                qr_rect,
                ui.make_persistent_id("qr-move-box"),
                egui::Sense::drag(),
            );
            if move_resp.hovered() || move_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Grab);
            }
            if move_resp.dragged() && !handle_resp.dragged() {
                let delta = move_resp.drag_delta();
                self.qr_x_pt = (self.qr_x_pt + delta.x / scale)
                    .clamp(0.0, (page_metrics.width_pt - self.qr_size_pt).max(0.0));
                self.qr_y_pt = (self.qr_y_pt - delta.y / scale)
                    .clamp(0.0, (page_metrics.height_pt - self.qr_size_pt).max(0.0));
            }

            ui.painter().rect_filled(
                handle_rect,
                2.0,
                egui::Color32::from_rgb(31, 95, 190),
            );
        });

        self.file_dialog.update(&ctx);
        if let Some(picked) = self.file_dialog.take_picked() {
            let path = picked.to_path_buf();
            match self.dialog_purpose.take() {
                Some(DialogPurpose::PickPdf) => self.load_pdf_file(&path),
                Some(DialogPurpose::PickKey) => self.key_input = path.display().to_string(),
                Some(DialogPurpose::SavePdf) => self.save_signed_pdf(&path),
                None => {}
            }
        }
    }
}

fn non_empty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn find_default_signing_key() -> Option<PathBuf> {
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
    None
}
