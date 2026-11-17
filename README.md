# dudelogs

Aplikasi desktop Rust: kelola koneksi SSH ke VM, daftarkan project (path log) di tiap VM,
sync error, lalu baca **fix plan** (penyebab dugaan + langkah + perintah verifikasi) yang
bisa ditempel ke tiket.

Bukan monitoring: tidak ada agent yang dipasang di VM, tidak ada auto-fix. Semua probe
read-only dan berjalan dari mesin ini. Koneksi & project disimpan di **SQLite lokal**.

## Alur pakai

1. Buka app → **+ VM** → isi nama, host/IP, user, port, lalu pilih auth:
   **SSH key / agent** (opsional identity file) atau **Password**.
2. Di VM itu → **+ project** → isi nama project + path log (satu per baris) dan/atau
   perintah read-only tambahan.
3. Klik **Sync all** (semua VM) atau **sync** di satu VM.
4. Pilih temuan di tabel tengah → panel kanan berisi fix plan → **Copy markdown**,
   atau **Tandai solved** setelah diperbaiki.
5. Tabel punya kolom **Tanggal** (waktu dari log; fallback waktu pertama terdeteksi),
   dropdown **project**, filter severity, dan tombol "baru saja".
6. Urutkan: klik tombol `urut: severity` → `tanggal: terbaru` → `tanggal: terlama`.
   Filter project juga bisa diklik dari panel kiri.
7. Temuan yang sudah ditandai solved tampil abu-abu dengan label **SOLVED**; centang
   "sembunyikan solved" untuk menyembunyikannya.
8. Pilih banyak baris: klik = satu baris, **cmd/ctrl/shift+klik** = tambah/kurangi pilihan,
   **pilih semua** = semua yang lolos filter. Lalu klik **Tandai solved** untuk massal.
6. Report markdown tiap run tersimpan di `~/.dudelogs/reports/`.

## Prasyarat

- Rust stable. Di mesin ini rustup baru dipasang, jadi shell baru perlu:
  ```sh
  source "$HOME/.cargo/env"
  ```
- `ssh` bisa login: pakai ssh-agent/`identity_file` (BatchMode), atau auth password yang
  dikirim lewat `SSH_ASKPASS` (`SSH_ASKPASS_REQUIRE=force`, didukung OpenSSH 8.4+).
- Probe journal/docker butuh user remote di grup `systemd-journal`/`adm` dan `docker`.
  Kalau tidak, probe dilaporkan **gagal**, bukan "tidak ada error".

Cek dulu: `ssh -o BatchMode=yes deploy@10.0.0.11 'systemctl --failed --no-legend; id'`

## Install (macOS, .dmg)

```sh
cd ~/SitesRust/dudelogs
./scripts/build-dmg.sh
# dist/dudelogs.app
# dist/dudelogs-0.1.0-arm64.dmg
```

Buka dmg → drag **dudelogs** ke **Applications**. Tidak perlu Terminal setelah itu.

- Build hanya untuk arsitektur mesin ini (`arm64` di Apple Silicon). Untuk Intel, build di
  mesin Intel atau tambahkan target `x86_64-apple-darwin`.
- Binary di-sign **ad-hoc** (gratis). Di Mac ini langsung jalan; di Mac lain Gatekeeper bisa
  menolak → klik kanan app → **Open** sekali, atau izinkan di
  System Settings → Privacy & Security.
- Ikon custom: taruh `assets/AppIcon.icns` sebelum build; script akan memasukkannya.
- Installer tidak menyentuh data: koneksi/report tetap di `~/.dudelogs`.

Kalau dibuka dari Finder, `SSH_AUTH_SOCK` diambil dari `launchctl getenv` supaya ssh-agent
tetap terpakai. Kalau key tetap tidak terbaca, isi **identity file** atau pakai auth
**password** di form VM.

## Menjalankan dari source

```sh
cd ~/SitesRust/dudelogs
cargo run                    # GUI
cargo run -- --headless      # sync semua koneksi di DB, cetak ringkasan + report
cargo run -- --config ~/.dudelogs/dudelogs.toml
```

Opsi lain: `DUDELOGS_HOME=/path` untuk memindah DB/report, `DUDELOGS_SSH_BIN` untuk
mengganti binary ssh (dipakai test).

## Data lokal

```
~/.dudelogs/
├── state.db                      # koneksi, project, runs, findings (SQLite)
├── reports/2026-11-17-12-07-12-run3.md
└── raw/3/vm-web-01/applog[shop].txt   # output probe, sudah diredaksi
```

Skema:

| Tabel | Isi |
|---|---|
| `connections` | id, name (unik), host, user, port, identity_file, auth_method (`key`/`password`), password, probes (dipilih per VM) |
| `projects` | id, connection_id (cascade), name, log_paths (newline), extra_cmd |
| `runs` | id, started_at, finished_at, status, targets_ok/fail |
| `findings` | fingerprint, target, project, source, severity, message, excerpt, unit, event_time, first_seen, last_seen, occurrences, solved, last_run_id (PK: fingerprint+target) |

`fingerprint` = hash dari `source + project + unit + message` setelah timestamp, pid, uuid,
hex, dan IP dibuang. Error yang sama di beberapa VM = satu baris dengan beberapa target;
project berbeda = baris terpisah (supaya filter project akurat). `findings` dipakai untuk
menandai **NEW** vs sudah dikenal dan menghitung `occurrences`.

### History & solved

- Saat app dibuka, tabel langsung memuat temuan dari **run terakhir** (`last_run_id`),
  jadi hasil sync tidak hilang walau app ditutup, dihapus dari Applications, atau
  di-install ulang. Sync ulang tidak wajib untuk melihat data lama.
- Temuan yang tidak muncul lagi di sync berikutnya tidak ditampilkan sebagai temuan aktif,
  tetapi barisnya tetap ada di DB (history penuh bisa dibaca dengan `sqlite3 state.db`).
- **Tandai solved** menulis `solved=1` ke DB dan **tidak dihapus oleh sync berikutnya**.
  Sync hanya meng-*append*/update: `occurrences` dan `last_seen` bertambah, status solved
  tetap seperti yang kamu set. Untuk membuka kembali, klik **Buka lagi**.
- Karena solved tidak auto-reopen, kalau error yang sudah solved muncul lagi, barisnya
  tetap abu-abu — cek kolom "terakhir" di panel detail bila ingin memastikan. (Kalau mau
  perilaku auto-reopen, bilang saja; tinggal ubah satu baris di `upsert`.)
- Hapus aplikasi (`/Applications/dudelogs.app`) hanya menghapus binary. Data tetap di
  `~/.dudelogs` (folder 0700). Backup: `cp ~/.dudelogs/state.db ~/backup-dudelogs.db`.

## Konfigurasi (opsional)

Hanya knob runtime + jalur import awal. **Kalau file tidak ada, app tetap jalan** dengan
default: `ssh`, concurrency 4, timeout 20s, probe `systemd/journal/docker/resources`.
Indikator di kanan atas akan menulis `config: default`.
Dicari di: `--config` → `./dudelogs.toml` → `~/.dudelogs/dudelogs.toml`.

```toml
ssh_bin = "ssh"
concurrency = 4          # probe paralel
probe_timeout_secs = 20

[defaults]
probes = ["systemd", "journal", "docker", "resources"]
```

Kalau `--config <path>` diberikan tapi file tidak ada, itu tetap error (supaya salah path
ketahuan). `[[target]]` masih diterima **hanya untuk import satu kali**: bila tabel `connections`
masih kosong, isinya dipindahkan ke SQLite lalu diabaikan. Setelah itu koneksi/project
dikelola lewat UI (atau SQLite langsung). Contoh lengkap ada di `dudelogs.example.toml`.

## Auth koneksi

| Pilihan | Cara kerja | Catatan |
|---|---|---|
| SSH key / agent | `ssh` biasa + `BatchMode=yes`; `identity_file` diisi → `-i` + `IdentitiesOnly=yes` | Disarankan. Ikut `~/.ssh/config` bila field kosong |
| Password | tanpa BatchMode; `NumberOfPasswordPrompts=1`, `PubkeyAuthentication=no`, `PreferredAuthentications=password,keyboard-interactive`; password dikirim ke `ssh` via env + helper `SSH_ASKPASS` | Password disimpan **plaintext** di `state.db` (file 0600, folder 0700). Pindah ke key = password lama dihapus |

Helper askpass hanya berisi `printf '%s' "$DUDELOGS_SSH_PASSWORD"`; secret tidak pernah
ditulis ke disk, hanya ada di environment proses `ssh` selama koneksi berjalan.

## Satu sesi per VM

Saat sync, app membuka **satu koneksi SSH per VM** (ControlMaster) lalu menjalankan semua
probe sebagai channel di atasnya:

- `ControlMaster=auto`, `ControlPath=/tmp/ddl-cm-<pid>-<run>/c<id>.sock`, `ControlPersist=60`
- Sebelum probe, ada satu `ssh ... true` per VM untuk membuat master. Kalau auth/transport
  gagal di langkah ini, semua probe VM itu ditandai gagal **sekali** (tidak mencoba login
  berulang per probe) — penting untuk auth password.
- Setelah run selesai, master ditutup (`ssh -O exit`) dan direktori socket dihapus.
- Kalau path socket kepanjangan (>95 byte, batas Unix socket di macOS), kontrol otomatis
  dimatikan dan probe kembali memakai koneksi masing-masing.

## Probe

| Probe | Perintah | Cakupan |
|---|---|---|
| `systemd` | `systemctl --failed --no-legend --plain` | per VM |
| `journal` | `journalctl -p 3 -o json --since '-2 hours' -n 500` | per VM |
| `docker` | `docker ps` (exited/dead/restarting) | per VM |
| `resources` | `df -P`, `/proc/meminfo`, `/proc/loadavg` | per VM |
| `applog` | `tail -n 2000 <path project>` lalu parsing record di lokal | per project |
| extra | perintah bebas dari form project | per project |

### Setup Laravel

1. **Tambah VM** (`+ VM`): host/IP, user, port, auth. Centang probe:
   - `systemd` → unit `php*-fpm`, `nginx`, worker/supervisor yang mati
   - `journal` → error priority ≤3 dari php-fpm/nginx/cron
   - `resources` → disk/memory/load
   - `docker` → **jangan dicentang** kalau VM tidak pakai Docker
2. **Tambah project** di VM itu:
   - Nama: mis. `psb-keu`
   - Path log (satu per baris):
     ```
     /var/www/psb-keu/storage/logs/laravel.log
     ```
     untuk daily log pakai glob: `/var/www/psb-keu/storage/logs/*.log`
   - Perintah tambahan (opsional, read-only):
     ```
     php /var/www/psb-keu/artisan queue:failed --no-ansi
     ```
     Hasilnya jadi temuan source `extra` (job queue yang gagal).
3. **Sync all** / `sync` di VM itu. Temuan `applog` berisi label project `psb-keu`.

Cara log dibaca (berlaku untuk Laravel maupun log lain):

- Satu **record** = satu baris ber-timestamp (`[2026-11-17 11:10:41] ...` atau
  `2026/11/17 11:10:41 ...`) **plus semua baris setelahnya** sampai timestamp berikutnya.
  Stack trace (`#0`, `#1`, `[stacktrace]`, JSON `{"exception": ...}`) ikut record itu.
- Hasilnya **satu error = satu baris tabel**. Pesan diambil dari header record tanpa
  timestamp dan tanpa konteks JSON; stack trace lengkap disimpan dan muncul di panel kanan
  (Evidence) saat baris diklik.
- Level yang dikenali: `.ERROR:`, `.CRITICAL:`, `.ALERT:`, `.EMERGENCY:`, `.WARNING:`,
  plus kata `panic`/`fatal`/`exception`/`failed` pada baris header.
- SQLSTATE dan `Allowed memory size` punya fix plan khusus.
- File tanpa timestamp (log aplikasi plain) tetap didukung: tiap baris dievaluasi sendiri.

Syarat: user SSH harus bisa membaca file log (biasanya `www-data`, grup `adm`, atau ACL).
Kalau tidak, probe `applog` gagal dengan `permission denied` — perbaiki izin, jangan
dimatikan probe-nya. Pastikan juga path mengikuti `LOG_CHANNEL`/`daily` di `.env`.

### Probe per VM

Di form koneksi ada checkbox `systemd / journal / docker / resources`. Uncheck yang tidak
relevan untuk VM itu — misalnya VM Laravel tanpa Docker: matikan `docker`, sisakan
`systemd`, `journal`, `resources`, lalu isi path log project
(`/var/www/psb-keu/storage/logs/laravel.log` atau `/var/www/psb-keu/storage/logs/*.log`).

Selain itu, kalau probe tetap aktif tetapi binary-nya tidak ada, `ssh` mengembalikan
**exit 127** dan probe **dilewati** (bukan error): target tetap `ok`, dan report memuat
bagian **Catatan probe** seperti `docker: dilewati (exit 127: docker: not found)`.

Aturan keamanan (divalidasi saat simpan, bukan saat run):

- Path log: hanya `A-Z a-z 0-9 / . _ - * ? [ ] : @ +`. Spasi/quote/`;` ditolak karena
  path masuk ke shell remote.
- Perintah tambahan: `sudo`, `rm`, `mv`, `systemctl start/stop/restart`, `docker rm`,
  `>`, `;`, `&&`, `||`, backtick, `$()` ditolak. Pipe (`|`) boleh.
- Exit code remote non-zero = probe **gagal** (kecuali `grep` tanpa match: exit 1 +
  stdout kosong dianggap "tidak ada temuan").

## Fix plan (`playbook.toml`)

Rule bawaan di-embed ke binary. Override tanpa rebuild:

```sh
cp playbook.toml ~/.dudelogs/playbook.toml
```

```toml
[[rule]]
id = "systemd.failed"
match = { source = "systemd" }
cause = "Unit gagal start. Umumnya config invalid, port terpakai, atau dependency belum siap."
steps = [
  "systemctl status {{unit}} -l --no-pager",
  "journalctl -u {{unit}} -n 200 --no-pager -p 3",
]
verify = "systemctl is-active {{unit}}"
risk = "medium"
```

Rule dicocokkan berurutan (first match menang); taruh yang paling spesifik di atas.
`severity_min` menyaring rule untuk temuan ringan. Tanpa rule, temuan tetap tampil dengan
triage generik dan `confidence: low` — bukan plan karangan.

## Batasan v1

- Read-only: tidak ada eksekusi perbaikan di remote.
- Tidak ada LLM; fix plan deterministik.
- Target Linux + systemd/journal; distro lain tetap jalan lewat `applog`/extra.
- Tidak ada alerting, chart historis, server multi-user.
- Satu sesi per VM (ControlMaster) dengan channel per probe; bukan satu channel persisten
  yang di-streaming, jadi tiap probe tetap punya timeout sendiri.
- Jendela error terbatas: journal 2 jam terakhir/500 baris, `tail` 2000 baris per path project.

## Development

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo test     # 36 unit + 3 e2e (stub ssh + fixture, tanpa VM)
cargo run -- --headless
```

E2E memakai `tests/stub-ssh` + `tests/fixtures/` dan DB sementara; `DUDELOGS_HOME`
digunakan test agar tidak mengotori `~/.dudelogs`.

## Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `ssh error (exit 255): Permission denied` | Key belum ada / butuh passphrase. Pakai ssh-agent atau isi `identity_file`. Tidak ada prompt password. |
| `journal: exit 1: ... permission denied` | User remote tidak di grup `systemd-journal`/`adm`. |
| `docker: exit 1: permission denied` | User remote tidak di grup `docker`. |
| Semua probe gagal `timeout 20s` | VM lambat/jaringan. Naikkan `probe_timeout_secs`. |
| `Host key verification failed` | `StrictHostKeyChecking=accept-new` dipakai; login manual sekali bila perlu. |
| Project tidak menghasilkan temuan | Path salah/glob tidak match, log kosong, atau user SSH tidak bisa membaca file. Cek `~/.dudelogs/raw/<run>/<vm>/applog[project].txt`; kalau `tail` gagal, probe juga melaporkan error. |
| `applog: permission denied` | User SSH tidak bisa baca `storage/logs`. Tambahkan ke grup `www-data`/`adm` atau pakai ACL. |
| Perubahan TOML tidak berefek | Setelah import pertama, koneksi dikelola di SQLite/UI. |
| Auth password ditolak (`Permission denied`) | Cek user+password; server harus mengizinkan `PasswordAuthentication yes`. Ganti ke auth key bila server hanya menerima key. |
| Semua probe satu VM gagal dengan satu pesan `koneksi: ...` | Itu kegagalan sesi (auth/transpor) saat membuat master — perbaiki koneksi, bukan masing-masing probe. |
| `docker: not found` / exit 127 | Tool tidak terpasang. Probe otomatis dilewati dan dicatat di report; matikan checkbox `docker` di form VM agar tidak dicoba sama sekali. |
| DB lama tidak punya kolom auth | Tidak perlu aksi: kolom `auth_method`/`password` ditambahkan otomatis saat app dibuka. |
