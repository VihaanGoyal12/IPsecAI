# IPsecAI: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

[![Security Standard](https://img.shields.io/badge/Standard-NIST%20SP%20800--77%20Rev.1-blue.svg)](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-emerald.svg)]()
[![Organization](https://img.shields.io/badge/Organization-NTRO-navy.svg)]()
[![Hackathon](https://img.shields.io/badge/Hackathon-Smart%20India%20Hackathon%202026-orange.svg)]()

> **Problem Statement (SIH26160)**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
> **Organization**: National Technical Research Organisation (NTRO)  
> **Category**: Software | **Focus**: Defensive Security Assessment & Observable Flow Inference

---

## 1. Executive Summary & Core Philosophy

**IPsecAI** is a defensive cybersecurity framework designed to automatically parse IPsec VPN network captures (PCAP / PCAPNG), identify cryptographic and protocol configurations (IKEv1/v2, ESP/AH, Diffie-Hellman groups, PFS, Replay Windows, SA lifetimes), evaluate configuration posture against deterministic security rules grounded in **NIST SP 800-77 Rev. 1**, and infer underlying traffic categories from observable flow metadata without breaking encryption or inspecting encrypted payloads.

### Key Tenets:
1. **Enterprise Security Console Style**: High-contrast, minimal, clear tabular layout, restrained blue accents, no AI buzzword clutter or neon styling.
2. **Zero-Friction Demo Mode**: The application runs completely offline without requiring physical VPN gateways, TShark, Zeek, Kafka, or PostgreSQL.
3. **Strict Data Honesty**:
   - **Observed**: Parameters parsed directly from packet headers and IKE proposals.
   - **Rule-Based Assessment**: Deterministic evaluation of observed parameters against NIST SP 800-77 rules.
   - **AI-Inferred**: Traffic classification derived exclusively from statistical flow metadata (packet lengths, inter-arrival times, burst counts, volume ratios).
   - **Never Payload Decryption**: Payloads remain encrypted; no claim of breaking encryption is ever made.

---

## 2. Architecture & Pipeline

```
                     INPUT
     [ PCAP / PCAPNG / Live Demo Stream ]
                       │
                       ▼
             TRAFFIC EXTRACTION
       (TShark Parser / Fallback Engine)
                       │
                       ▼
    PROTOCOL & CONFIGURATION IDENTIFICATION
       (IKEv1/v2, ESP/AH, DH Group, SA)
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
   RULE ENGINE                    ML ENGINE
(NIST SP 800-77 Rules)     (Flow Feature Classifier)
        │                             │
   DETERMINISTIC                 INFERRED
  SECURITY FINDINGS            TRAFFIC TYPES
        │                             │
        └──────────────┬──────────────┘
                       ▼
              UNIFIED ASSESSMENT
         (Prototype Security Score 0-100)
                       │
                       ▼
          TECHNICAL & EXECUTIVE REPORTS
         (HTML / Markdown / JSON / CSV)
```

---

## 3. Technology Stack

- **User Interface**: Streamlit with custom enterprise security console styling (`app/styles/main.css`)
- **Backend API**: Python FastAPI (`backend/api.py`) with Pydantic schemas
- **Rule & Scoring Engine**: YAML-configured deterministic rules (`config/security_rules.yaml`) with weighted score deduction
- **AI / Machine Learning**: Scikit-Learn / XGBoost flow metadata classifier (`backend/ml/traffic_classifier.py`)
- **Visualizations**: Plotly interactive threat matrix and feature importance ranking
- **Packet Parsers**: Modular TShark subprocess wrapper (`backend/parsers/tshark_parser.py`) with graceful fallback
- **Storage Layer**: SQLite / In-Memory JSON store with optional PostgreSQL configuration
- **Containerization**: Docker & Docker Compose (`docker-compose.yml`)

---

## 4. Quickstart Guide (Local Execution)

### Prerequisites
- Python 3.9+ (or Docker)

### Option A: Running with Virtual Environment (Recommended)

```bash
# 1. Clone repository
cd sih160

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the Streamlit Security Console (Frontend)
streamlit run app/streamlit_app.py

# 5. (Optional) In a separate terminal, start the FastAPI Backend:
uvicorn backend.api:app --reload --port 8000
```

Open `http://localhost:8501` in your browser.

---

### Option B: Running with Docker Compose

```bash
docker compose up --build
```

- **Frontend Console**: `http://localhost:8501`
- **Backend API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`

---

## 5. Standard Demo Walkthrough (2-Minute Demonstration)

The application comes pre-loaded with three distinct demonstration profiles:

1. **DEMO A (Healthy Enterprise Tunnel)**:
   - **Configuration**: Tunnel mode, AES-256-GCM, DH Group 14 (MODP-2048), PFS Enabled, Replay Protection Active (Window 128), SA Lifetime 8h.
   - **Expected Result**: High Security Score (~98/100), Low Risk Level, compliant pass across all categories.
2. **DEMO B (Weak Legacy Profile)**:
   - **Configuration**: Transport mode, AES-128-CBC + HMAC-SHA1, DH Group 2 (MODP-1024), PFS Disabled, Replay Protection Disabled, SA Lifetime 48h.
   - **Expected Result**: Lower Security Score (~42/100), Critical/High Risk Level, 5 active findings requiring remediation.
3. **DEMO C (Encrypted Multi-Flow Classification)**:
   - **Configuration**: Tunnel mode with 6 concurrent encrypted application flows.
   - **Expected Result**: Real-time AI classification into VoIP, Video Streaming, Web Browsing, Email, Messaging, and ICMP with probability distributions and observable feature explainability.

---

## 6. How the Prototype Scoring Model Works

The security score is a transparent weighted deduction model:

$$\text{Final Score} = \max\left(0, 100 - \sum \text{Rule Penalties}\right)$$

### Categories Evaluated:
- **Cryptography** (AES-GCM AEAD vs CBC vs Legacy 3DES/DES)
- **Authentication & Integrity** (AEAD / SHA-2 vs Deprecated SHA-1 / MD5)
- **Key Exchange** (DH Group 14/19/20 vs Weak Group 1/2/5)
- **Perfect Forward Secrecy (PFS)** (Child SA fresh DH rekeying enabled vs disabled)
- **Replay Protection** (Sliding anti-replay window enabled vs disabled)
- **Security Association Lifetime** (Safe thresholds $\le 24\text{h}$ vs excessive wear-out)
- **Mode & Architecture** (Tunnel encapsulation vs Transport header exposure)
- **Metadata Confidentiality** (Traffic Flow Confidentiality / TFC padding)

---

## 7. AI Traffic Classification Methodology

Encrypted VPN traffic analysis operates purely on observable flow metadata:
- Mean and standard deviation of packet lengths
- Inter-arrival times and jitter (ms)
- Directional byte volume ratio (inbound vs outbound)
- Packet count, aggregate bytes, and flow duration
- Burst frequency and cluster density

> **Explainability Guarantee**: Top contributing features are calculated per flow and visualized via Plotly bar charts.

---

## 8. Testbed Configurator & Template Generator

The Testbed tool allows security engineers to configure parameters and generate ready-to-use configuration templates:
- strongSwan `ipsec.conf`
- Modern strongSwan `swanctl.conf`
- Predicted security score and findings before deployment

---

## 9. Running Automated Tests

Run the complete test suite:

```bash
pytest -v
```

All 16 unit and integration test suites cover:
- Rule engine deterministic evaluation
- Scoring bounds (0-100) and deduction breakdown
- ML feature extraction and probability summation
- Testbed generation and config templates
- FastAPI endpoints and export formats (HTML/Markdown/JSON/CSV)

---

## 10. Research Foundation & References

1. **NIST Special Publication 800-77 Rev. 1**: *Guide to IPsec VPNs*, NIST CSRC. [Link](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
2. **Fesl & Naas (2025)**: *A comprehensive machine learning-based approach for virtual private network traffic detection, classification and hiding*, Computer Networks, DOI: 10.1016/j.comnet.2025.111530.
3. **Luo, Chu & Yang (2023)**: *IP packet-level encrypted traffic classification using machine learning with a light weight feature engineering method*, JISA, DOI: 10.1016/j.jisa.2023.103519.
4. **Roy, Shapira & Shavitt (2022)**: *Fast and lean encrypted Internet traffic classification*, Computer Communications, DOI: 10.1016/j.comcom.2022.02.003.

---

## 11. Prototype Limitations & Defensive Scope

- **Prototype Heuristic**: The security score is a weighted prototype heuristic grounded in NIST guidelines, not an official NTRO certification.
- **Observable Metadata Only**: In strict adherence to encryption ethics and standards, payloads are not decrypted or inspected.
- **Defensive Focus**: Designed strictly for security auditing, configuration review, and research testbeds.
