# Go Breeze Auth (`go-breeze-auth`)

[![Go Reference](https://pkg.go.dev/badge/github.com/HumaCode/go-breeze-auth.svg)](https://pkg.go.dev/github.com/HumaCode/go-breeze-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Go Breeze Auth** adalah authentication toolkit untuk Golang yang terinspirasi dari kesederhanaan dan kelengkapan **Laravel Breeze**. Package ini menyediakan alur autentikasi siap pakai (Login, Register, Forgot Password, Reset Password, Email Verification, dan Profile Management) yang dirancang untuk arsitektur modern berbasis **Stateless JWT** maupun form web HTML.

Proyek ini memiliki **2 Mode Penggunaan**:
1. **Sebagai Reusable Go Package (Library):** Dapat di-install dan di-import langsung (`go get`) ke dalam proyek Golang apa pun dengan framework apa pun (Breeze v2, Gin, Echo, Fiber, Chi, atau `net/http` standar).
2. **Sebagai Aplikasi Standalone (API Server):** Berjalan mandiri dengan framework **Breeze v2** dan **PostgreSQL + GORM**.

> 💡 **Kompatibilitas:** Struktur tabel `users` (menggunakan primary key **ULID** 26 karakter dan `is_active`) 100% konsisten dan kompatibel dengan [`go-rbac-menu`](https://github.com/HumaCode/go-rbac-menu). Anda dapat mengombinasikan autentikasi dari `go-breeze-auth` dan otorisasi menu dinamis dari `go-rbac-menu` dalam satu database tanpa konflik skema.

---

## 🚀 Fitur Utama

- 🔑 **Kunci Primer ULID:** Identifier 26 karakter berbasis waktu (*time-ordered*), aman dan efisien di database.
- 🔀 **Fleksibilitas Login:** Pengguna dapat login menggunakan **Email** maupun **Username**.
- 🛡️ **Anti-Brute Force Throttling & Suspend 10 Menit:**
  - Jika salah memasukkan kredensial sebanyak **3 kali berturut-turut**, akun otomatis ditangguhkan (*suspended*) selama **10 menit**.
  - Menyimpan **keterangan suspend tersembunyi** di database (`json:"-"`) yang mencatat timestamp dan alasan suspensi tanpa bocor ke respon publik.
  - Akun yang di-suspend dapat diaktifkan kembali secara instan oleh role **developer/admin** sebelum 10 menit selesai.
- ☑️ **Checklist Remember Me:** Opsi `remember_me: true` pada payload login yang memperpanjang masa aktif token JWT secara otomatis (default: **30 hari** vs **24 jam**).
- 🔒 **Proteksi XSS Otomatis:** Semua input teks (`name`, `username`) secara otomatis disanitasi dengan HTML entity escaping untuk mencegah serangan *Stored XSS*.
- 🎫 **Stateless JWT:** Token HS256 yang aman, memuat data klaim penting (`user_id`, `email`, `username`).
- ✉️ **Alur Forgot & Reset Password:** Token acak kriptografis dengan penyimpanan aman (SHA-256 hash) dan waktu kedaluwarsa otomatis.
- 📬 **Verifikasi Email:** Fitur verifikasi email yang dapat diaktifkan atau dinonaktifkan sesuai kebutuhan (`RequireEmailVerification`).
- 📨 **Dual Mailer Driver:**
  - `LogMailer` (Default): Menampilkan simulasi email dan tautan reset password langsung di terminal/konsol agar dev lokal tidak membutuhkan akun SMTP.
  - `SMTPMailer`: Pengiriman email HTML sesungguhnya ke server SMTP (Mailtrap, SendGrid, Gmail, dll).
- 🧩 **Multi-Framework Middleware:**
  - `breezeauth.BreezeMiddleware(jwtSecret)` untuk framework **Breeze v2**.
  - `breezeauth.AuthMiddleware(jwtSecret)` untuk standar **`net/http`** (kompatibel dengan Chi, Gin, Fiber adaptor, Gorilla, dll).
- 👤 **Manajemen Profil & Kata Sandi:** Endpoint get user (`/me`), update profil, dan ganti kata sandi dengan verifikasi kata sandi lama.

---

## 📦 Panduan Instalasi Package

Di dalam folder proyek Golang Anda, jalankan perintah:

```bash
go get github.com/HumaCode/go-breeze-auth/breezeauth
```

---

## 🛠️ Panduan Integrasi di Proyek Anda

### 1. Inisialisasi Database (Auto-Migration)

Cukup panggil fungsi `breezeauth.AutoMigrate` menggunakan instance `*gorm.DB` yang sudah ada di proyek Anda:

```go
package main

import (
    "github.com/HumaCode/go-breeze-auth/breezeauth"
    "gorm.io/gorm"
)

func initDB(db *gorm.DB) error {
    return breezeauth.AutoMigrate(db)
}
```

Tabel yang dibuat secara otomatis:
1. `users` (`id`, `name`, `username`, `email`, `password_hash`, `email_verified_at`, `is_active`, `failed_login_attempts`, `suspended_until`, `suspend_reason`, timestamps)
2. `password_reset_tokens` (`email`, `token_hash`, `expires_at`, `created_at`)
3. `email_verification_tokens` (`user_id`, `token_hash`, `expires_at`, `created_at`)

---

### 2. Inisialisasi Service Autentikasi

```go
package main

import (
    "time"
    "github.com/HumaCode/go-breeze-auth/breezeauth"
    "gorm.io/gorm"
)

func setupAuthService(db *gorm.DB) *breezeauth.Service {
    return breezeauth.New(db, breezeauth.Config{
        JWTSecret:                   "kunci-rahasia-jwt-anda-di-production",
        JWTExpiration:               24 * time.Hour,
        JWTRememberMeExpiration:     30 * 24 * time.Hour, // 30 hari jika remember_me aktif
        MaxFailedLoginAttempts:      3,                   // Suspend setelah 3x gagal login
        SuspendDuration:             10 * time.Minute,    // Durasi suspend 10 menit
        ResetTokenExpiration:        60 * time.Minute,
        VerificationTokenExpiration: 24 * time.Hour,
        FrontendResetPasswordURL:    "http://localhost:3000/reset-password",
        FrontendVerifyEmailURL:      "http://localhost:3000/verify-email",
        Mailer:                      breezeauth.NewLogMailer(), // atau breezeauth.NewSMTPMailer(...)
        RequireEmailVerification:    false,
    })
}
```

---

### 3. Contoh Penggunaan Logika Bisnis

#### A. Registrasi Pengguna Baru
```go
user, token, err := authSvc.Register(breezeauth.RegisterRequest{
    Name:     "Budi Pratama",
    Username: "budipratama",
    Email:    "budi@example.com",
    Password: "passwordRahasia123",
})
```

#### B. Login (Dengan Opsi Remember Me)
```go
user, token, err := authSvc.Login(breezeauth.LoginRequest{
    Identifier: "budi@example.com", // Bisa juga username: "budipratama"
    Password:   "passwordRahasia123",
    RememberMe: true,                 // Token berlaku 30 hari
})
```

#### C. Lupa & Reset Password
```go
// 1. Request link forgot password (dikirim via mailer/terminal log)
err := authSvc.ForgotPassword(breezeauth.ForgotPasswordRequest{
    Email: "budi@example.com",
})

// 2. Eksekusi reset password menggunakan token yang diterima
err := authSvc.ResetPassword(breezeauth.ResetPasswordRequest{
    Email:       "budi@example.com",
    Token:       "token-dari-link-email",
    NewPassword: "kataSandiBaru456",
})
```

#### D. Verifikasi & Pengelolaan Akun Suspend (Role Dev/Admin)
```go
// 1. Melihat detail dan keterangan suspend tersembunyi (hanya dev)
info, err := authSvc.GetSuspendDetails(targetUserID)
fmt.Printf("Status Suspend: %v, Alasan: %s, Sisa Waktu: %d detik\n", 
    info.IsSuspended, info.SuspendReason, info.RemainingSeconds)

// 2. Membuka kembali akun yang ditangguhkan sebelum 10 menit selesai
err := authSvc.UnsuspendUser(targetUserID)
```

---

### 4. Proteksi Rute (Middleware)

#### Framework Breeze v2:
```go
r := breeze.NewRouter()
authMw := breezeauth.BreezeMiddleware("kunci-rahasia-jwt-anda")

// Lindungi endpoint profil
r.HandleBlocking(breeze.GET, "/api/v1/profile", profileHandler, authMw)
```

#### Framework Standar `net/http` (Chi, Gin, Gorilla, dll):
```go
r := chi.NewRouter()

r.Use(breezeauth.AuthMiddleware("kunci-rahasia-jwt-anda"))
r.Get("/api/v1/profile", func(w http.ResponseWriter, r *http.Request) {
    claims, ok := breezeauth.ClaimsFromContext(r.Context())
    userID := breezeauth.UserIDFromContext(r.Context())
    // ...
})
```

---

## 🏃 Menjalankan Aplikasi Standalone API Server

Jika Anda ingin menjalankan repositori ini sebagai server API mandiri:

1. **Clone repositori:**
   ```bash
   git clone https://github.com/HumaCode/go-breeze-auth.git
   cd go-breeze-auth
   ```

2. **Salin file environment:**
   ```bash
   cp .env.example .env
   ```

3. **Sesuaikan koneksi PostgreSQL di `.env`:**
   ```env
   APP_PORT=8000
   DB_HOST=127.0.0.1
   DB_PORT=5432
   DB_USER=postgres
   DB_PASSWORD=postgres
   DB_NAME=go_breeze_auth
   DB_SSLMODE=disable

   JWT_SECRET=super-secret-jwt-key
   JWT_EXPIRATION_HOURS=24

   MAILER_DRIVER=log # Gunakan 'log' untuk dev lokal atau 'smtp' untuk production
   ```

4. **Jalankan server:**
   ```bash
   go run cmd/api/main.go
   ```

Server akan otomatis memigrasi tabel database dan mendengarkan request pada port `8000`.

---

## 📡 Dokumentasi Endpoint API

| Method | Endpoint | Akses | Deskripsi |
| :--- | :--- | :---: | :--- |
| `GET` | `/health` | Publik | Health check server |
| `POST` | `/api/v1/auth/register` | Publik | Registrasi pengguna baru |
| `POST` | `/api/v1/auth/login` | Publik | Login (Email/Username + Remember Me) |
| `POST` | `/api/v1/auth/forgot-password` | Publik | Permintaan tautan reset password |
| `POST` | `/api/v1/auth/reset-password` | Publik | Reset kata sandi dengan token |
| `POST` | `/api/v1/auth/verify-email` | Publik | Verifikasi email pengguna |
| `GET` | `/api/v1/auth/me` | Bearer Token | Data profil pengguna yang sedang login |
| `PUT` | `/api/v1/auth/profile` | Bearer Token | Perbarui nama, username, atau email |
| `PUT` | `/api/v1/auth/password` | Bearer Token | Ganti kata sandi pengguna |
| `POST` | `/api/v1/auth/resend-verification` | Bearer Token | Kirim ulang email verifikasi |
| `POST` | `/api/v1/auth/logout` | Bearer Token | Notifikasi logout client |
| `POST` | `/api/v1/auth/users/:id/unsuspend` | Dev / Admin | Mengaktifkan kembali akun yang kena suspend throttle |
| `GET` | `/api/v1/auth/users/:id/suspend-details` | Dev / Admin | Melihat detail status & alasan suspend tersembunyi |

---

### Contoh Payload Request & Response

#### 1. Login (`POST /api/v1/auth/login`)
**Request Body:**
```json
{
  "identifier": "budipratama",
  "password": "passwordRahasia123",
  "remember_me": true
}
```

**Response Sukses (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "01HQXYZ123456789ABCDEF0001",
      "name": "Budi Pratama",
      "username": "budipratama",
      "email": "budi@example.com",
      "is_active": 1,
      "failed_login_attempts": 0,
      "created_at": "2026-11-24T21:00:00Z",
      "updated_at": "2026-11-24T21:00:00Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Response Throttled / Suspend (429 Too Many Requests):**
*(Muncul otomatis jika salah memasukkan kredensial sebanyak 3 kali)*
```json
{
  "success": false,
  "message": "Akun Anda sedang ditangguhkan selama 10 menit karena 3 kali salah memasukkan username/password. Silakan tunggu atau hubungi developer."
}
```

---

#### 2. Dev: Inspeksi Detail Suspend (`GET /api/v1/auth/users/:id/suspend-details`)
*(Hanya untuk role dev/admin, menampilkan keterangan alasan suspend yang disembunyikan dari publik)*

**Response Sukses (200 OK):**
```json
{
  "success": true,
  "message": "Suspend details retrieved successfully",
  "data": {
    "user_id": "01HQXYZ123456789ABCDEF0001",
    "username": "budipratama",
    "email": "budi@example.com",
    "is_active": 1,
    "is_suspended": true,
    "suspended_until": "2026-11-24T22:00:00Z",
    "remaining_seconds": 580,
    "failed_login_attempts": 0,
    "suspend_reason": "Akun ditangguhkan otomatis oleh sistem: 3x gagal memasukkan password pada 2026-11-24 21:50:00"
  }
}
```

---

#### 3. Dev: Reaktivasi Akun Suspend (`POST /api/v1/auth/users/:id/unsuspend`)
**Response Sukses (200 OK):**
```json
{
  "success": true,
  "message": "User account unsuspended successfully and reactivated"
}
```

---

## 🧪 Menjalankan Unit Tests

Seluruh skenario pengujian (Register, Login, Remember Me, XSS Sanitization, Throttling & Suspend 10 Menit, Dev Unsuspend, Forgot & Reset Password, Email Verification, Mailer, dan Middleware) dapat diuji langsung menggunakan database in-memory:

```bash
go test -v ./...
```

Output:
```text
=== RUN   TestRegisterAndLogin
--- PASS: TestRegisterAndLogin (0.19s)
=== RUN   TestForgotPasswordAndReset
--- PASS: TestForgotPasswordAndReset (0.19s)
=== RUN   TestEmailVerification
--- PASS: TestEmailVerification (0.14s)
=== RUN   TestUpdateProfileAndPassword
--- PASS: TestUpdateProfileAndPassword (0.24s)
=== RUN   TestAuthMiddleware
--- PASS: TestAuthMiddleware (0.05s)
=== RUN   TestLogMailer
--- PASS: TestLogMailer (0.00s)
=== RUN   TestThrottleAndSuspend10Minutes
--- PASS: TestThrottleAndSuspend10Minutes (0.24s)
=== RUN   TestRememberMeTokenDuration
--- PASS: TestRememberMeTokenDuration (0.15s)
=== RUN   TestXSSProtection
--- PASS: TestXSSProtection (0.05s)
PASS
ok      github.com/HumaCode/go-breeze-auth/breezeauth   1.387s
```

---

## 📄 Lisensi

Proyek ini didistribusikan di bawah lisensi [MIT](LICENSE). Silakan gunakan secara bebas untuk keperluan personal maupun komersial.
