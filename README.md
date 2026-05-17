# macOS Security Dashboard

A real-time macOS monitoring dashboard that watches for:

- Screen Recording access
- Input Monitoring access
- Accessibility access
- Microphone access
- Camera access
- Full Disk Access
- Suspicious processes
- Remote control tools
- Keylogger-like behavior

Built with:
- Python
- PyQt6
- psutil
- sqlite3

---

# Features

- Live security dashboard
- Dark mode UI
- Red/green security cards
- Real-time refresh
- Detection log
- Suspicious process detection
- TCC privacy monitoring

---

# Setup

## 1. Create venv

```bash
python3 -m venv .venv
```

## 2. Activate venv

```bash
source .venv/bin/activate
```

## 3. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

---

# Run

```bash
python3 security_dashboard.py
```

---

# Recommended macOS Settings

Enable Full Disk Access for:
- Terminal
- iTerm
- VSCode

Path:
System Settings → Privacy & Security → Full Disk Access

---

# Optional

Install suspicious tools to test detections:
- nc
- rustdesk
- teamviewer

The dashboard will flag them.

---

# Disclaimer

This is a lightweight monitoring dashboard and not a full antivirus or EDR platform.
