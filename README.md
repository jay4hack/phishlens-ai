# 🛡️ PhishLens AI — AI-Powered Phishing Detection Assistant

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Gemma 4 Powered](https://img.shields.io/badge/Model-Gemma%204-cyan.svg)](https://ai.google.dev/)
[![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-red.svg)](https://streamlit.io/)

**PhishLens AI** is an open-source cybersecurity threat triage assistant built for **Hacktoberfest Hack Day** (`Best Open-Source AI Project` and `Best Use of Gemma 4`).

PhishLens AI combines **Google's Gemma 4 multimodal model** with transparent deterministic URL heuristics to evaluate suspicious emails, SMS lures, deceptive web links, and login screenshots for social engineering tactics.

---

## 🌟 Hacktoberfest Category Alignment

### 1. Best Open-Source AI Project
- **Open & Transparent Architecture**: Free, permissively licensed under the [MIT License](LICENSE).
- **Separation of Concerns**: Modular split between the UI layer ([app.py](app.py)), the deterministic heuristics engine ([security_engine.py](security_engine.py)), and an automated 16-point unit test suite ([test_app.py](test_app.py)).
- **Safety by Design**: Never visits suspicious links or conducts active network scans on untrusted URLs. Does not fabricate live reputation verdicts.

### 2. Best Use of Gemma 4
- **Multimodal Reasoner**: Utilizes Google's instruction-tuned `gemma-4-26b-a4b-it` (and supports `gemma-4-31b-it`) to jointly analyze text and visual layouts.
- **Visual Social Engineering Detection**: Inspects uploaded screenshots for visual brand impersonation, spoofed corporate layouts, deceptive call-to-action buttons, and synthetic urgency lures.
- **Structured Triage Evaluation**: Guides Gemma 4 with defensive system instructions to return strictly structured JSON triage reports (`HIGH`, `MEDIUM`, `LOW`, `INCONCLUSIVE`).

---

## ⚙️ Architecture & Features

```
phishlens-ai/
├── app.py                 # Streamlit cyber dashboard UI & session state
├── security_engine.py     # Deterministic URL heuristics, input bounds & report builder
├── test_app.py            # Automated test suite (16 comprehensive unit tests)
├── requirements.txt       # Minimal, pinned dependencies
├── .env.example           # Secure environment variable template
├── .gitignore             # Secrets & cache isolation
├── LICENSE                # MIT License
└── README.md              # Complete setup, demo script, and documentation
```

### Key Capabilities
1. **Cybersecurity Glassmorphism Dashboard**: Dark navy, sky blue, and teal interface with responsive risk badges.
2. **Deterministic URL Anatomy Checks**: Offline inspection for raw IP hostnames, generic throwaway TLDs (`.xyz`, `.top`, etc.), subdomain stacking, authority credentials delimiter spoofing (`@`), and typosquatting keywords.
3. **Multimodal Screenshot Triage**: Detects subtle graphic discrepancies in fake login pages using Gemma 4.
4. **Input Size & Safety Guards**: Enforces a 15,000-character limit and a 5MB image upload ceiling.
5. **Session-Based Scan Telemetry**: In-memory scan logging preserved across active triage workflows.
6. **One-Click Plaintext Triage Reports**: Downloadable `.txt` audit reports.

---

## 🚀 Quickstart Guide (Windows PowerShell)

### 1. Clone & Enter Repository
```powershell
git clone https://github.com/your-username/phishlens-ai.git
cd D:\phishlens-ai
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Open `.env` and set your API key from [Google AI Studio](https://aistudio.google.com/app/apikey):
```env
GEMINI_API_KEY=AIzaSy...your_actual_api_key_here
GEMMA_MODEL=gemma-4-26b-a4b-it
```
*Note: For security and secret safety, PhishLens AI loads `GEMINI_API_KEY` strictly from `.env` using `python-dotenv`.*

### 3. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 4. Run Automated Tests
Verify all 18 tests pass:
```powershell
python -m unittest test_app -v
```

### 5. Launch PhishLens AI
```powershell
python -m streamlit run app.py
```
The app will open automatically at `http://localhost:8501`.

---

## 🎬 Two-Minute Video Demonstration Script

Use this script when recording your Hacktoberfest demo video (e.g. using OBS, Loom, or ScreenToGif):

| Time | Visual Action | Narration / Audio |
| :--- | :--- | :--- |
| **0:00 - 0:20** | Show dashboard header, dark navy theme, and model selector (`gemma-4-26b-a4b-it`). | *"Hello Hack Day judges! This is PhishLens AI, an open-source cybersecurity assistant powered by Google's Gemma 4 and the Google Gen AI SDK. PhishLens empowers everyday users to triage suspicious communications safely without visiting dangerous links."* |
| **0:20 - 0:50** | Paste a smishing message with a raw IP URL (`http://192.168.1.15/chase-verify`) and click **Analyze Threat Indicators**. | *"Let's test an urgent SMS lure. Notice our local engine immediately flags deterministic red flags like raw IP hostnames and unencrypted HTTP, while Gemma 4 analyzes the urgency pressure and brand impersonation. Within seconds, we get a structured HIGH RISK assessment with actionable containment steps."* |
| **0:50 - 1:25** | Upload a screenshot of a suspicious login form into the Screenshot uploader and run the scan. | *"PhishLens AI shines with Gemma 4's multimodal capabilities. Here we upload a screenshot of a fake login screen. Gemma 4 analyzes visual cues—such as mismatched logos, unbranded buttons, and layout anomalies—giving users a thorough visual triage."* |
| **1:25 - 1:45** | Click **Download Triage Report (.txt)** and inspect the **Scan History** tab. | *"Users can export a standardized plaintext triage report for incident response documentation and monitor their scan telemetry throughout the session."* |
| **1:45 - 2:00** | Run `python -m unittest test_app.py -v` in terminal to show 16 passing tests. | *"PhishLens AI is open-source under the MIT license, backed by a comprehensive 16-point automated test suite, with zero hardcoded secrets. Thank you!"* |

---

## 📹 How to Record Your Demonstration

1. **Resolution:** 1080p (1920x1080) at 30 or 60 FPS.
2. **Audio:** Clear microphone with background noise reduction.
3. **Tool:** Use free tools like [OBS Studio](https://obsproject.com/) or [Loom](https://www.loom.com/).
4. **Recording Checklist:**
   - [ ] Ensure terminal and browser windows are readable (set browser zoom to 110%).
   - [ ] Keep `.env` and secret keys hidden off-screen.
   - [ ] Run automated tests in PowerShell to prove system health.
   - [ ] Export the generated triage report to show complete workflow.

---

## ⚠️ Privacy, Security & AI Limitations

1. **Advisory Decision Support**: PhishLens AI is an assistive triage tool. It **does NOT guarantee** that an evaluated item is 100% benign or malicious.
2. **No Active Crawling or Live DNS Sandbox**: All URL evaluations are deterministic lexical pattern checks. PhishLens AI never sends HTTP requests to or executes payloads from submitted URLs.
3. **Zero Secret Retention**: API keys remain in your local session or `.env` and are never saved to a remote database.
4. **Data Minimization**: Users should never submit confidential passwords, bank details, or internal authentication tokens.

---

## 🙏 Credits & Acknowledgments

- **Model**: [Gemma 4](https://ai.google.dev/gemma) open models by the Google DeepMind and Gemma teams.
- **SDK**: [Google Gen AI Python SDK](https://github.com/googleapis/python-genai) (`google-genai`).
- **Framework**: [Streamlit](https://streamlit.io/) for modern rapid application hosting.
- **Libraries**: [Pillow](https://python-pillow.org/) for image handling, [python-dotenv](https://github.com/theskumar/python-dotenv) for configuration.

---

## 📄 License
This project is open-source and released under the [MIT License](LICENSE).
