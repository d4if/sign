# sign

Generator tanda tangan digital dokumen berbasis QR Code menggunakan **PASETO `v4.public`** (Ed25519) yang ringan dan efisien dalam bahasa Rust.

## Fitur Utama

- **Pembuatan Pasangan Kunci (`keygen`)**: Menghasilkan kunci privat (`k4.secret...`) dan kunci publik (`k4.public...`) berformat PASERK v4.
- **Penandatanganan Dokumen (`sign`)**: Menghitung hash SHA-256 berkas secara streaming (hemat memori), menyematkan metadata dokumen ke dalam token PASETO `v4.public`, lalu merender QR Code dalam format **SVG**, **PNG**, atau **Terminal**.
- **Verifikasi CLI (`verify`)**: Memverifikasi tanda tangan digital menggunakan kunci publik `k4.public...` sekaligus mencocokkan integritas hash SHA-256 berkas dokumen.
- **Inspeksi Token (`inspect`)**: Membaca payload dan footer token tanpa verifikasi kriptografis untuk keperluan pemeriksaan cepat.
- **Kompatibel dengan `d4if/validate`**: Mendukung payload token mentah maupun URL validator (`--verify-url https://d4if.github.io/validate/`).

## Pemasangan

Unduh binary rilis terbaru sesuai platform (Linux x86_64/ARM64 GNU/musl, Windows x86_64/ARM64, macOS Intel/Apple Silicon) dari halaman [GitHub Releases](https://github.com/d4if/sign/releases), atau kompilasi dari source:

```sh
cargo build --release
```

## Contoh Penggunaan

### 1. Membuat Pasangan Kunci

```sh
sign keygen --secret-out signing.key --public-out verifying.key
```

### 2. Menandatangani Dokumen & Membuat QR Code

```sh
sign sign \
  --key signing.key \
  --file surat-keterangan.pdf \
  --issuer "Prodi D4TI ULBI" \
  --signer "NN257L" \
  --doc-id "SK-2026-001" \
  --subject "Surat Keterangan Aktif Kuliah" \
  --out signature-qr.svg
```

Opsi tambahan:
- `--ttl 365d` — masa berlaku token (`s`, `m`, `h`, `d`). Tanpa `--ttl`, token bersifat permanen (`non-expiring`).
- `--verify-url https://d4if.github.io/validate/` — membungkus token ke dalam URL `#token=...` agar QR langsung membuka halaman validator saat dipindai kamera ponsel.
- `--out signature-qr.png` — menyimpan QR Code dalam format raster PNG.
- `--token-out signature.paseto` — menyimpan string token mentah ke berkas teks.
- `--json` — mencetak keluaran terstruktur JSON.

### 3. Memverifikasi Token & Integritas Berkas

```sh
sign verify \
  --public-key verifying.key \
  --token signature.paseto \
  --file surat-keterangan.pdf
```

### 4. Menginspeksi Token

```sh
sign inspect --token signature.paseto
```

## Lisensi

MIT — lihat berkas [LICENSE](LICENSE).
