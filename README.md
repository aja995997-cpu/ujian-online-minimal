# 📘 **Sistem Ujian Online Minimal (FastAPI + SQLite + WebSocket)**

Aplikasi **Ujian Online** berbasis Python yang dibangun menggunakan:

* **FastAPI**
* **SQLite (SQLAlchemy ORM)**
* **WebSocket (Real-time START & FORCE SUBMIT)**
* **JWT Authentication**
* **Bootstrap Frontend**
* **PyInstaller (Optional desktop executable)**

Aplikasi ini menyediakan sistem ujian lengkap dengan panel **Admin** dan **Siswa**, lengkap dengan pengaturan peserta, manajemen soal, monitoring status sesi, dan eksport nilai dalam format CSV.

---

## 🧩 **Fitur Utama**

### 👨‍🏫 **Untuk Admin**

* Login Secure (SHA256 admin password + single-session login).
* Manajemen Siswa:

  * Tambah / edit siswa.
  * Reset login siswa (force logout).
  * Melihat riwayat nilai siswa.
* Upload soal melalui file **CSV** (format: `soal,a,b,c,d,kunci`).
* Membuat sesi ujian dengan durasi tertentu.
* Menambah peserta ujian.
* Start & Stop ujian (real-time lewat WebSocket).
* Download hasil ujian (CSV).
* Ganti password admin.
* Single-session enforcement untuk siswa.

### 🎓 **Untuk Siswa**

* Login dashboard siswa.
* Melihat daftar ujian yang tersedia.
* Mengikuti ujian sesuai waktu real-time.
* Ujian otomatis terkunci ketika:

  * Waktu habis
  * Admin menekan STOP
* Hasil otomatis tersimpan.

### 💡 **Fitur Teknis**

* FastAPI backend dengan template HTML inline.
* JWT authentication.
* WebSocket untuk sinyal real-time START / FORCE SUBMIT.
* Single-session login:

  * Admin boleh multiple login (force overwrite).
  * Siswa **tidak boleh login ganda**.
* Database SQLite otomatis dibuat saat aplikasi pertama dijalankan.
* Auto generate admin default:

  ```
  username: admin
  password: admin
  ```

---

## 📄 **Format CSV Soal**

File CSV harus memiliki format:

| Soal                | A      | B     | C      | D      | jawaban |
| ------------------- | ------ | ----- | ------ | ------ | ------- |
| Siapa penemu lampu? | Edison | Tesla | Newton | Pascal | A       |

Contoh isi file:

```
Matahari terbit dari?,Barat,Timur,Selatan,Utara,B
Hasil dari 5+7?,10,11,12,13,C
```

Delimiter otomatis terdeteksi: `,` atau `;`.

---

## 🔐 **Autentikasi & Keamanan**

* Admin menggunakan **hash SHA-256**.
* Siswa menggunakan plain password (lebih simple untuk operasional sekolah).
* JWT dengan masa aktif 24 jam.
* Admin dapat:

  * Reset token siswa.
  * Mengganti password admin.
* Siswa tidak dapat login ganda (session lock).

---


## 📘 Cara Menggunakan Aplikasi Ujian Online

Aplikasi ini tersedia dalam dua versi:

* **Versi Python** (langsung dijalankan dengan Python)
* **Versi Windows** (EXE hasil PyInstaller)

Tampilan halaman utama (login admin & siswa) sama-sama di:

👉 **[http://localhost:8000](http://localhost:8000)**

---

# 🚀 1. Menjalankan Versi Python

(Folder: **Python/**)

### 1. Install Python 3.8+

Pastikan Python sudah terpasang.

### 2. Install library yang dibutuhkan

```sh
pip install fastapi uvicorn sqlalchemy python-jose python-multipart jinja2
```

### 3. Jalankan aplikasi

```sh
python ujian-online-minimal.py
```

Setelah berjalan, buka di browser:

👉 **[http://localhost:8000](http://localhost:8000)**

---

# 💻 2. Menjalankan Versi Windows (EXE)

(Folder: **Windows/**)

Tersedia dua versi:

---

## ✅ A. Versi Portable (Single File EXE)

Lokasi:
`Windows/Portable/ujian-online-minimal-portable.exe`

Cara menjalankan:
👉 **Double click** file tersebut.

Server otomatis aktif, lalu buka:

👉 **[http://localhost:8000](http://localhost:8000)**

---

## ✅ B. Versi Folder / Onedir (Stabil dan Direkomendasikan)

Lokasi:
`Windows/Onedir/ujian-online.exe`

Jalankan dengan cara:
👉 Double click `ujian-online.exe`

Folder `_internal` adalah bawaan PyInstaller dan **jangan dihapus**.

Aplikasi berjalan di:

👉 **[http://localhost:8000`](http://localhost:8000`)

---

# ⚠️ Catatan Penting tentang Antivirus / Windows Defender

Beberapa antivirus dapat menandai aplikasi portable atau onedir sebagai:

* "Unknown Publisher"
* "File berbahaya"
* "Unrecognized App"

Ini **normal** untuk aplikasi PyInstaller karena:

* Tidak memiliki signature digital
* Bersifat portable
* Mengandung banyak file Python yang dipacking ke EXE

Jika muncul peringatan:
👉 Klik **More info → Run anyway**
👉 atau **Tetap Jalankan**

Aplikasi ini **aman**, tidak mengubah sistem, dan tidak mengirim data ke internet.
Semua data tetap berada di komputer pengguna.

---

# 🔑 Login Awal

Saat pertama kali dijalankan, otomatis dibuat akun admin:

* **Username:** `admin`
* **Password:** `admin`

Admin dan siswa **login dari halaman yang sama**:

👉 **[http://localhost:8000](http://localhost:8000)**

---

# 🧪 Cara Menggunakan Setelah Login

### Admin dapat:

* Menambah & edit siswa
* Upload soal (CSV)
* Membuat sesi ujian
* Menentukan durasi
* Menambah peserta
* Start & Stop ujian
* Download hasil ujian

### Siswa dapat:

* Melihat daftar ujian
* Mengerjakan soal
* Submit jawaban

---

# 📸 Screenshots

![Dashboard Admin](screenshots/dashboard_admin.png)

![Home Siswa](screenshots/home_siswa.png)
