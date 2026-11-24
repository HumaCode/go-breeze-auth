# Go Breeze Auth (`go-breeze-auth`)

[![Go Reference](https://pkg.go.dev/badge/github.com/HumaCode/go-breeze-auth.svg)](https://pkg.go.dev/github.com/HumaCode/go-breeze-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Go Breeze Auth** adalah authentication toolkit untuk Golang yang terinspirasi dari kesederhanaan dan kelengkapan **Laravel Breeze**. Package ini menyediakan alur autentikasi menyeluruh (Login, Register, Forgot Password, Reset Password, Email Verification, dan Profile Management) yang siap digunakan untuk arsitektur modern (Stateless JWT) maupun form web tradisional.

Proyek ini dirancang dengan **Dual Mode**:
1. **Reusable Library (`breezeauth`):** Dapat di-import (`go get`) ke dalam proyek web Golang apa pun dengan framework apa pun (Breeze v2, Gin, Echo, Fiber, Chi, atau `net/http` standar).
2. **Standalone API Server:** Template backend siap pakai dengan framework **Breeze v2** dan **PostgreSQL + GORM**.

> 💡 **Kompatibilitas:** Struktur tabel `users` (menggunakan **ULID** 26 karakter dan `is_active`) 100% konsisten dan kompatibel dengan [`go-rbac-menu`](https://github.com/HumaCode/go-rbac-menu). Anda dapat mengombinasikan autentikasi dari `go-breeze-auth` dan otorisasi menu dinamis dari `go-rbac-menu` tanpa konflik skema.

---

## 🚀 Fitur Unggulan

- **Identitas & Kunci Primer ULID:** Identifier 26-karakter yang terurut berdasarkan waktu (*time-ordered*).
- **Fleksibilitas Login & Remember Me:** Login dapat menggunakan **Email** maupun **Username**, serta dilengkapi fitur checkbox `remember_me` untuk memperpanjang masa aktif JWT (misal 30 hari vs 24 jam).
- **Proteksi XSS & Keamanan Input:** Sanitasi otomatis semua input teks (nama, username) menggunakan escaping HTML untuk mencegah injeksi *Stored XSS*.
- **Anti-Brute Force Throttling & Suspend 10 Menit:**
  - Jika salah memasukkan kredensial sebanyak **3 kali berturut-turut**, akun otomatis ditangguhkan (*suspended*) selama **10 menit**.
  - Menyimpan **keterangan suspend tersembunyi** di database (`json:"-"`) yang aman dan tidak bocor ke publik.
  - Akun yang di-suspend dapat diaktifkan kembali secara instan oleh role **developer/admin**.
- **Stateless JWT:** Token JWT HS256 yang aman dengan data klaim user (`user_id`, `email`, `username`).
- **Alur Forgot & Reset Password:** Token acak yang aman dengan penyimpanan terenkripsi (SHA-256 hash) dan waktu kedaluwarsa otomatis.
- **Verifikasi Email:** Opsi verifikasi alamat email yang dapat diaktifkan atau dinonaktifkan (`RequireEmailVerification`).
- **Dual Mailer Driver:**
  - `LogMailer` (Default): Menampilkan simulasi email dan tautan reset password langsung di terminal/konsol agar dev lokal tidak membutuhkan akun SMTP.
  - `SMTPMailer`: Pengiriman email HTML sesungguhnya ke mail server (Mailtrap, SendGrid, Gmail, dll).
- **Multi-Framework Middleware:**
  - `breezeauth.BreezeMiddleware(jwtSecret)` untuk framework **Breeze v2**.
  - `breezeauth.AuthMiddleware(jwtSecret)` untuk standar **`net/http`** (kompatibel dengan Chi, Gin, Fiber adaptor, dll).
- **Manajemen Profil & Kata Sandi:** Endpoint get user (`/me`), update profil, dan update kata sandi dengan validasi kata sandi lama.

---

## 📦 Instalasi Reusable Library

Di dalam proyek Golang Anda, jalankan:

```bash
go get github.com/HumaCode/go-breeze-auth/breezeauth
```

---

## 🛠️ Panduan Penggunaan Library di Proyek Anda

### 1. Migrasi Database (GORM)

Panggil fungsi `AutoMigrate` menggunakan instance `*gorm.DB` yang sudah ada:

```go
package main

import (
    "github.com/HumaCode/go-breeze-auth/breezeauth"
    "gorm.io/gorm"
)

func migrate(db *gorm.DB) error {
    return breezeauth.AutoMigrate(db)
}
```

Tabel yang dibuat:
- `users` (ID ULID, name, username, email, password_hash, email_verified_at, is_active, timestamps)
- `password_reset_tokens` (email, token_hash, expires_at, created_at)
- `email_verification_tokens` (user_id, token_hash, expires_at, created_at)

---

### 2. Inisialisasi Service Autentikasi

```go
import (
    "time"
    "github.com/HumaCode/go-breeze-auth/breezeauth"
)

// Inisialisasi service dengan konfigurasi
authSvc := breezeauth.New(db, breezeauth.Config{
    JWTSecret:                "kunci-rahasia-jwt-anda",
    JWTExpiration:            24 * time.Hour,
    ResetTokenExpiration:     60 * time.Minute,
    FrontendResetPasswordURL: "http://localhost:3000/reset-password",
    FrontendVerifyEmailURL:   "http://localhost:3000/verify-email",
    Mailer:                   breezeauth.NewLogMailer(), // atau breezeauth.NewSMTPMailer(...)
    RequireEmailVerification: false,
})
```

---

### 3. Menggunakan Logika Autentikasi

#### Registrasi Pengguna
```go
user, token, err := authSvc.Register(breezeauth.RegisterRequest{
    Name:     "Budi Pratama",
    Username: "budipratama",
    Email:    "budi@example.com",
    Password: "passwordRahasia123",
})
```

#### Login (Bisa dengan Email atau Username)
```go
user, token, err := authSvc.Login(breezeauth.LoginRequest{
    Identifier: "budi@example.com", // atau "budipratama"
    Password:   "passwordRahasia123",
})
```

#### Lupa & Reset Password
```go
// 1. Request forgot password (akan mengirim link ke email/log)
err := authSvc.ForgotPassword(breezeauth.ForgotPasswordRequest{
    Email: "budi@example.com",
})

// 2. Reset password dengan token yang diterima
err := authSvc.ResetPassword(breezeauth.ResetPasswordRequest{
    Email:       "budi@example.com",
    Token:       "plain-token-dari-email",
    NewPassword: "kataSandiBaru456",
})
```

#### Update Password
```go
err := authSvc.UpdatePassword(userID, breezeauth.UpdatePasswordRequest{
    CurrentPassword: "passwordRahasia123",
    NewPassword:     "kataSandiBaru456",
})
```

---

### 4. Proteksi Rute (Middleware)

#### Untuk Framework Breeze v2:
```go
r := breeze.NewRouter()

// Proteksi rute
authMw := breezeauth.BreezeMiddleware("kunci-rahasia-jwt-anda")
r.HandleBlocking(breeze.GET, "/api/v1/profile", profileHandler, authMw)
```

#### Untuk Framework `net/http` Standar (Chi, Gorilla, dll):
```go
r := chi.NewRouter()

r.Use(breezeauth.AuthMiddleware("kunci-rahasia-jwt-anda"))
r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
    claims, ok := breezeauth.ClaimsFromContext(r.Context())
    userID := breezeauth.UserIDFromContext(r.Context())
    // ...
})
```

---

## 🏃 Menjalankan Aplikasi Standalone API Server

Jika Anda ingin menjalankan aplikasi ini secara mandiri:

1. **Salin konfigurasi environment:**
   ```bash
   cp .env.example .env
   ```

2. **Sesuaikan koneksi PostgreSQL di `.env`:**
   ```env
   DB_HOST=127.0.0.1
   DB_PORT=5432
   DB_USER=postgres
   DB_PASSWORD=postgres
   DB_NAME=go_breeze_auth
   DB_SSLMODE=disable
   JWT_SECRET=super-secret-jwt-key
   MAILER_DRIVER=log
   ```

3. **Jalankan server:**
   ```bash
   go run cmd/api/main.go
   ```

Server akan otomatis memigrasi database dan berjalan di port `8000`.

---

## 📡 Daftar Endpoint API

| Method | Endpoint | Auth | Deskripsi |
| :--- | :--- | :---: | :--- |
| `GET` | `/health` | Publik | Status kesehatan server |
| `POST` | `/api/v1/auth/register` | Publik | Pendaftaran pengguna baru |
| `POST` | `/api/v1/auth/login` | Publik | Login pengguna (Email / Username) |
| `POST` | `/api/v1/auth/forgot-password` | Publik | Kirim tautan reset password |
| `POST` | `/api/v1/auth/reset-password` | Publik | Reset kata sandi dengan token |
| `POST` | `/api/v1/auth/verify-email` | Publik | Verifikasi email pengguna |
| `GET` | `/api/v1/auth/me` | Bearer Token | Ambil data profil user saat ini |
| `PUT` | `/api/v1/auth/profile` | Bearer Token | Perbarui nama, username, atau email |
| `PUT` | `/api/v1/auth/password` | Bearer Token | Ubah kata sandi pengguna |
| `POST` | `/api/v1/auth/resend-verification` | Bearer Token | Kirim ulang email verifikasi |
| `POST` | `/api/v1/auth/logout` | Bearer Token | Notifikasi logout client |
| `POST` | `/api/v1/auth/users/:id/unsuspend` | Dev/Admin | Mengaktifkan kembali akun yang kena suspend throttle |
| `GET` | `/api/v1/auth/users/:id/suspend-details` | Dev/Admin | Melihat detail status dan catatan suspend tersembunyi |

---

## 🧪 Menjalankan Unit Tests

Seluruh skenario pengujian (Register, Login, Validasi JWT, Forgot Password, Reset Password, Email Verification, Mailer, dan Middleware) sudah diuji dengan database in-memory:

```bash
go test -v ./...
```

---

## 📄 Lisensi

Proyek ini didistribusikan di bawah lisensi **MIT**. Silakan gunakan secara bebas untuk keperluan personal maupun komersial.
