---
title: Cyber Guider AI
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
pinned: false
---

# 🛡️ Cyber Guider AI: Empowering Pakistan Against Digital Scams
### *Winner - Hackathon Innovation Excellence* 🏆

**Cyber Guider AI** is a state-of-the-art, multi-modal forensic pipeline designed to protect Pakistani citizens from digital fraud. Built to tackle the rising wave of cybercrime, this platform combines high-speed local intelligence with deep AI reasoning to detect, analyze, and report scams in real-time.

---

## 🌟 The Vision: Why Cyber Guider?

In Pakistan, thousands of citizens fall victim to scams every day—from fake **BISP 8171** messages to fraudulent **PSCA E-Challan** links. Most victims don't know how to verify these threats or report them to the authorities.

**Our Mission:** To democratize cybersecurity by giving every citizen a "Digital Guard" in their pocket. We bridge the gap between complex forensic analysis and the common man.

---

## 🎯 Target Audience
- **The Common Citizen:** Vulnerable individuals receiving "Prize Draw" or "Emergency" SMS/Calls.
- **E-Challan Users:** Drivers being tricked by fake government impersonation links.
- **Banking Customers:** People targeted by OTP and account-suspension scams.
- **Law Enforcement (FIA):** Helping authorities by providing "Court-Ready" forensic evidence reports.

---

## 🚀 Key Innovations & Winning Features

### 1. 🧠 Tiered "Agentic" Decision Flow
The system uses a unique 3-Tiered approach to ensure maximum speed and accuracy:
- **Tier 1 (Instant Local Intelligence)**: Cross-references input against a high-speed SQLite database of known patterns for **0ms latency** hits.
- **Tier 2 (AI Reasoning Engine)**: Uses **Gemini 1.5 Flash** to perform deep behavioral analysis on new, unknown threats.
- **Tier 3 (Forensic Layer)**: Automatically extracts URLs and performs real-time **WHOIS, SSL, and Geolocation** forensics.

### 2. ⚡ "Smart Pivot" FIA Reporting
We solved the "Reporting Barrier" with two professional paths:
- **Draft & Report Magic**: Automatically generates a professional legal complaint, copies it to the clipboard, and opens the official FIA portal.
- **Legal PDF Generator**: Generates a **formal, court-ready English PDF application** addressed to the Director FIA, complete with technical metadata.

### 3. 🤖 Self-Learning "Cyber Brain"
- **AI Auto-Learning**: If the AI detects a new high-risk scam, it **automatically creates a new threat pattern** in the database. Next time anyone in the community receives the same scam, the detection is instant (0ms).

---

## 🛠️ Technical Knowledge (Developer Cheat Sheet)

### How it Works (Architecture)
1. **Request Received**: Text, Image (Screenshot), or Audio (Voice Note).
2. **Extraction**: Images are processed via **Gemini Vision**; Audio via **Groq Whisper-v3**.
3. **Hashing**: The content is hashed (SHA-256). If the hash exists in our DB, we return the result instantly.
4. **Forensics**: If it's a new link, we trigger `link.py` which performs socket-level SSL checks and REST API calls to VirusTotal/WHOIS.
5. **Reasoning**: Gemini Flash generates a report in **Roman Urdu** for user clarity and **Legal English** for FIA reporting.

### Key Performance Metrics
- **Instant Hit Response**: < 50ms (Local SQLite)
- **Deep AI Analysis**: 1-2 seconds (Gemini Flash Optimization)
- **Voice Transcription**: Near real-time (Groq API)

### Potential Interview Questions for Developers
- **Q: Why SQLite instead of a heavy Cloud DB?**
  - *A: For a hackathon and high-speed local intelligence, SQLite offers zero-config deployment and sub-millisecond query times for pattern matching.*
- **Q: How do you handle fake government domains?**
  - *A: We use an "Official Domain Validator" that compares keywords (like 'psca' or 'bisp') against a whitelist of `.gov.pk` domains.*
- **Q: Why use Groq for audio instead of Gemini?**
  - *A: Groq's LPU architecture provides 10x faster inference for Whisper models, which is critical for real-time scam detection in voice notes.*

---

## 🧱 Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | Custom **HTML5/Vanilla CSS** (Premium Glassmorphic Design) |
| **Backend** | **FastAPI** (High-performance Python) |
| **PDF Engine** | **fpdf2** (Optimized for Latin-1 clean reporting) |
| **Transcription** | **Groq Whisper-Large-V3** |
| **Core AI** | **Google Gemini 1.5 Flash** |
| **Intelligence** | **SQLAlchemy + SQLite** (Persistent Threat Intel) |

---

## 📂 Project Structure

```text
├── app.py              # Main Entry Point (FastAPI + Gradio Mirror)
├── index.html          # Premium Glassmorphic Frontend
├── link.py             # Advanced Domain & URL Forensics Utility
├── threat_intel.db     # Dynamic Scam Pattern Database
├── requirements.txt    # Project Dependencies
└── Dockerfile          # Hugging Face Deployment Config
```

---

## 📈 Impact & Benefits
1. **Financial Protection**: Prevents account draining by flagging OTP scams early.
2. **Legal Empowerment**: Removes the barrier to filing FIA complaints.
3. **Data Resilience**: Builds a community-driven database of Pakistani cyber-threats.
4. **Roman Urdu Support**: Accessible to 100M+ Urdu speakers.

## ⚙️ Hugging Face Deployment Setup

When deploying to Hugging Face Spaces, ensure you add the following **Secrets** in your Space's Settings:

| Secret Name | Description |
| :--- | :--- |
| `GEMINI_API_KEY` | Google AI Studio Key for core reasoning & vision. |
| `GROQ_API_KEY` | Groq API Key for high-speed Whisper transcription. |
| `VT_API_KEY` | VirusTotal API Key for domain risk scanning. |

---

## ⚖️ Disclaimer
*Cyber Guider AI is a proof-of-concept for digital safety. It aims to empower citizens with tools usually reserved for forensic experts.*

---
**Built with ❤️ for Pakistan's Digital Resilience 🚀**
