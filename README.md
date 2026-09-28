# IPsecAI: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

[![Security Standard](https://img.shields.io/badge/Standard-NIST%20SP%20800--77%20Rev.1-blue.svg)](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-emerald.svg)]()
[![Organization](https://img.shields.io/badge/Organization-NTRO-navy.svg)]()
[![Hackathon](https://img.shields.io/badge/Hackathon-Smart%20India%20Hackathon%202026-orange.svg)]()

> **Problem Statement (SIH26160)**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
> **Organization**: National Technical Research Organisation (NTRO)  
> **Category**: Software | **Focus**: Defensive Security Assessment & Observable Flow Inference

---

## 1. What is IPsecAI in Plain English?

### The Problem (Why This Matters)
- When government agencies, defense bodies, and enterprises connect branch offices and datacenters over public networks, they use **IPsec VPN tunnels**.
- An IPsec VPN encrypts all traffic passing through it.
- **The Core Challenge**: Because everything is encrypted, network administrators and security auditors cannot easily answer two crucial questions:
  1. *Is the VPN configuration strong and compliant, or is it using deprecated ciphers, weak Diffie-Hellman groups, or disabled anti-replay mechanisms?*
  2. *What kind of application traffic is flowing inside (e.g., video conferencing, VoIP voice calls, messaging, large data transfers, or anomalous beacons) without breaking or decrypting the payload?*

### The IPsecAI Solution
IPsecAI solves this using two distinct, ethical layers:
1. **Deterministic Rule Engine (Security Audit)**: Inspects observable IKE/ESP negotiation parameters against **NIST SP 800-77 Rev. 1** guidelines and produces an explainable **0 to 100 prototype security score** with actionable recommendations.
2. **AI Engine (Traffic Inference)**: Uses Machine Learning on **observable statistical flow metadata** (packet size distributions, inter-arrival time jitter, burst clustering, directional volume ratios) to classify encrypted traffic types (VoIP, Video, Web, Email, Messaging, ICMP) — **strictly without breaking encryption or inspecting encrypted payloads**.

---

## 2. Architecture & Pipeline

```
                    CAPTURE INGESTION
          [ PCAP / PCAPNG / Live Demo Stream ]
                           │
                           ▼
                 TRAFFIC EXTRACTION
          (TShark Safe Wrapper / Fallback)
                           │
                           ▼
         PROTOCOL & CONFIGURATION PARSING
           (IKEv1/v2, ESP/AH, DH Group, SA)
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
       RULE ENGINE                    ML ENGINE
    (NIST SP 800-77)            (Observable Features)
            │                             │
       DETERMINISTIC                  INFERRED
      SECURITY FINDINGS             TRAFFIC TYPES
            │                             │
            └──────────────┬──────────────┘
                           ▼
                  UNIFIED ASSESSMENT
             (Prototype Score: 0-100)
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

Open **`http://localhost:8501`** in your browser.

---

### Option B: Running with Docker Compose

```bash
docker compose up --build
```

- **Frontend Console**: `http://localhost:8501`
- **Backend API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`

---

## 5. Click-by-Click Testing & Demo Walkthrough

Once the UI is open at `http://localhost:8501`, follow this 5-step test sequence:

### Step 1: Overview Page
1. View the horizontal status bar:
   - **Security Score**: `98 / 100` (Low Risk)
   - **Findings**: `0`
   - **AI Confidence**: `94%`
2. **Test Weak Scenario**: Change profile dropdown to **Demo B (Weak Configuration)** and click **`[Load Demo Capture]`**.
   - The score immediately updates to **`42 / 100` (Critical Risk)**, and 5 red/yellow findings appear (*Legacy 3DES/CBC, Weak DH Group 2, PFS Disabled, Replay Window Disabled*).

### Step 2: Analyze Page
1. Click **`2. Analyze`** in the sidebar.
2. Inspect the **Protocol & Security Parameters** table (verifying clear distinction between **Observed**, **AI-Inferred**, and **Rule-Based Assessment**).
3. Scroll to **AI-Assisted Encrypted Traffic Classification** to see flows classified into VoIP, Video, Web, etc., alongside the **Observable Feature Importance** chart.
4. Toggle **"Live Demo Stream"** to watch live simulated packet arrivals with instant AI inferences.

### Step 3: Security Assessment Page
1. Click **`3. Security Assessment`** in the sidebar.
2. Review the category results table (**Pass / Review / Concern**).
3. Check the interactive **2-Axis Threat Matrix** (Likelihood vs Impact).
4. Expand *"How this score is calculated"* to review the exact rule-by-rule point deduction breakdown.

### Step 4: Testbed Page
1. Click **`4. Testbed`** in the sidebar.
2. Configure VPN parameters (Mode, Encryption, DH Group, PFS, Lifetime).
3. Click **`[Generate Test Profile & Config Templates]`** to predict security posture and export ready-to-use **strongSwan (`ipsec.conf`)** and modern **`swanctl.conf`** snippets.

### Step 5: Reports Page
1. Click **`5. Reports`** in the sidebar.
2. Toggle between **Technical Assessment Report** and **Executive Summary Briefing**.
3. Download findings in **HTML**, **Markdown**, **JSON**, or **CSV** format.
4. Download the **Sample Flow Dataset (CSV)** used for ML training.

---

## 6. How to Pitch This to Hackathon Judges (60 Seconds)

> *"Judges, IPsecAI addresses problem statement SIH26160 by automating the security assessment and traffic analysis of encrypted IPsec VPN tunnels.*  
>  
> *Unlike traditional network tools that require breaking encryption or manual packet inspection, IPsecAI operates on two ethical, compliant layers:*  
>  
> 1. *A **Deterministic Rule Engine** grounded in NIST SP 800-77 that inspects visible IKE/ESP negotiation parameters, detects weak ciphers and missing anti-replay windows, and produces a transparent 0-to-100 risk score.*  
> 2. *An **AI Flow Classifier** that infers underlying application traffic types (VoIP, Video, Web, Messaging) purely from observable packet statistical characteristics without inspecting encrypted payloads.*  
>  
> *It runs zero-friction offline, provides complete technical and executive reports, and generates testbed deployment configs for strongSwan."*

---

## 7. How the Prototype Scoring Model Works

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

## 8. AI Traffic Classification Methodology

Encrypted VPN traffic analysis operates purely on observable flow metadata:
- Mean and standard deviation of packet lengths
- Inter-arrival times and jitter (ms)
- Directional byte volume ratio (inbound vs outbound)
- Packet count, aggregate bytes, and flow duration
- Burst frequency and cluster density

> **Explainability Guarantee**: Top contributing features are calculated per flow and visualized via Plotly bar charts.

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
