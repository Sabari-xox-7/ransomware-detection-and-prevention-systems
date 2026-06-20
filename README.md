# 🛡️ RansomShield — ML-Based Ransomware Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> A machine learning–powered web application that detects ransomware and malicious files in real time using static analysis features including entropy, suspicious string patterns, file metadata, and behavioral indicators.

---

## 📸 Demo

![RansomShield Screenshot](static/screenshot.png)

> Upload any file → Instant ML prediction → Entropy analysis → Risk score + Recommendations

---

## 🚀 Features

- **Real-time file scanning** — drag and drop any file for instant analysis
- **Random Forest classifier** — trained on synthetic behavioral feature data
- **7 detection features** — entropy, suspicious strings, extension risk, URL/IP count, file size, string density
- **Risk scoring** — percentage-based risk meter with confidence level
- **Hash verification** — MD5 and SHA256 of every scanned file
- **Security recommendations** — actionable tips based on prediction result
- **REST API** — `/scan` endpoint for integration with other tools
- **Dark-themed UI** — clean, responsive web interface built with Flask

---

## 🧠 How It Works

```
File Upload
    │
    ▼
Feature Extraction (feature_extractor.py)
    ├── File entropy (Shannon entropy 0–8)
    ├── Suspicious keyword detection (encrypt, ransom, vssadmin...)
    ├── Risky extension check (.exe, .bat, .ps1, .vbs...)
    ├── Embedded URL and IP count
    ├── Printable string density
    └── File size
    │
    ▼
Random Forest Model (model.pkl)
    │
    ▼
Prediction: MALICIOUS / BENIGN
    + Confidence % + Risk Score + Reasons + Tips
```

---

## 📁 Project Structure

```
RansomShield/
│
├── app.py                  # Flask web application & API
├── feature_extractor.py    # Static analysis & feature engineering
├── train_model.py          # Model training script
├── model.pkl               # Trained Random Forest model
├── requirements.txt        # Python dependencies
│
├── templates/
│   └── index.html          # Frontend UI (dark theme)
│
├── static/                 # CSS, JS, images (optional)
├── dataset/
│   └── ransomware_dataset.csv   # Generated training dataset
└── uploads/                # Temp folder for scanned files (auto-cleared)
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10 or 3.11
- pip
- Git

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/RansomShield.git
cd RansomShield
```

### 2. Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Train the model

```bash
python train_model.py
```

Expected output:
```
Dataset created: 2000 samples
Training: 1600 samples | Testing: 400 samples
Training Random Forest model...
Accuracy: 98.50%
Model saved to model.pkl
Done! Now run: python app.py
```

### 5. Run the application

```bash
python app.py
```

Open your browser at: **http://localhost:5000**

---

## 🔌 API Reference

### `POST /scan`

Upload a file for analysis.

**Request** — multipart/form-data:
```
file: <binary file>
```

**Response** — JSON:
```json
{
  "filename": "suspicious.exe",
  "prediction": "MALICIOUS",
  "confidence": 97.3,
  "risk_score": 97.3,
  "reasons": [
    "Very high entropy (7.82/8.0) — file appears encrypted or packed.",
    "Suspicious keywords detected: encrypt, ransom, bitcoin.",
    "Risky file extension (.exe) — commonly used by malware."
  ],
  "tips": [
    "Do NOT open or execute this file.",
    "Scan with a reputable antivirus (Windows Defender, Malwarebytes)."
  ],
  "details": {
    "file_size": "512,000 bytes",
    "entropy": "7.8200 / 8.0",
    "extension": ".exe",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afb...",
    "strings": 12,
    "urls": 3,
    "ips": 1
  }
}
```

### `GET /`

Loads the web UI.

---

## 🤖 Machine Learning Details

| Parameter | Value |
|---|---|
| Algorithm | Random Forest Classifier |
| Training samples | 2,000 (1,000 benign + 1,000 malicious) |
| Test split | 80% train / 20% test |
| Number of trees | 100 |
| Max depth | 10 |
| Accuracy | ~98.5% |
| Features used | 7 |

### Feature Description

| Feature | Description |
|---|---|
| `entropy` | Shannon entropy of file bytes (0–8). Ransomware typically scores >6.8 due to encryption |
| `has_sus_strings` | Binary flag — presence of keywords like `encrypt`, `ransom`, `vssadmin`, `bitcoin` |
| `extension_risk` | Binary flag — risky extension (`.exe`, `.bat`, `.ps1`, `.vbs`, `.dll`, etc.) |
| `string_count` | Number of readable ASCII strings of length ≥ 4 |
| `url_count` | Number of HTTP/FTP URLs embedded in file |
| `ip_count` | Number of embedded IP addresses (potential C2 servers) |
| `file_size` | Raw file size in bytes |

---

## 🧪 Testing

Try scanning these file types to see how the model responds:

| File type | Expected result |
|---|---|
| `.exe` with high entropy | 🔴 MALICIOUS |
| `.bat` with `vssadmin` strings | 🔴 MALICIOUS |
| `.pdf` (normal document) | 🟢 BENIGN |
| `.txt` (plain text) | 🟢 BENIGN |
| `.ps1` PowerShell script | 🟡 Varies |

---

## 🛡️ Suspicious Keywords Detected

The scanner checks for these ransomware indicators:

```
encrypt, decrypt, ransom, bitcoin, wallet, payment,
CryptoLocker, WannaCry, Locky, HKEY_LOCAL_MACHINE,
cmd.exe, powershell, socket, connect, wget, curl,
DeleteFile, MoveFile, shadow, vssadmin, bcdedit,
wbadmin, IsDebuggerPresent, anti-debug, sandbox
```

---

## 📊 Dataset

The training dataset is **synthetically generated** with realistic statistical distributions derived from published ransomware behavior research (CICMalMem 2022, VirusShare analysis papers).

- **Benign samples** — low entropy (3.0–6.5), few suspicious strings, low URL/IP count
- **Malicious samples** — high entropy (6.8–8.0), suspicious keywords, risky extensions, higher network indicators

To regenerate the dataset and retrain:
```bash
python train_model.py
```

---

## 📚 References & Research Papers

1. Sgandurra, D. et al. (2016). *Automated Dynamic Analysis of Ransomware: Benefits, Limitations and use for Detection.* arXiv:1609.03020
2. Moussaileb, R. et al. (2021). *A Survey on Windows Ransomware Detection.* IEEE Access
3. Kharraz, A. et al. (2015). *Cutting the Gordian Knot: A Look Under the Hood of Ransomware Attacks.* DIMVA
4. Al-rimy, B.A.S. et al. (2018). *Ransomware threat success factors, taxonomy, and countermeasures.* Computers & Security
5. CICMalMem-2022 Dataset — Canadian Institute for Cybersecurity

---

## 🔮 Future Enhancements

- [ ] Deep learning model (LSTM / CNN) for sequential byte analysis
- [ ] Dynamic analysis using sandbox behavior monitoring
- [ ] VirusTotal API integration for hash lookup
- [ ] Real-time process monitoring agent (Windows service)
- [ ] Docker containerization for easy deployment
- [ ] Dataset expansion using real malware samples from MalwareBazaar

---

## 👨‍💻 Author

**[Your Name]**  
B.Tech — Computer Science & Engineering  
[Your Institute Name], [Year]  
Project Guide: [Guide's Name]

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is built for **educational and research purposes only** as part of an academic final year project. Do not use it to scan files on production systems without proper security review. Never execute or open files flagged as malicious.

---

<p align="center">Built with ❤️ for IIT Final Year Project — Ransomware Detection using Machine Learning</p>
