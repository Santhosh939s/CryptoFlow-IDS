# 🛡️ CryptoFlow-IDS: Next-Gen Cyber Defense Desktop App & IDS

**Real-Time Encrypted Traffic Intrusion Detection, In-Kernel Inspection & Automated Firewall Mitigation.**

Now fully transformed into a **distributable Windows Desktop Application** with a high-tech **Cyber HUD Dashboard**, **in-app attack simulator**, **SQLite incident logging**, and automated **GitHub Release installer CI/CD** (with cross-compatibility for Linux and eBPF).

---

## ✨ Features & Architecture

- 🖥️ **High-Tech Cyber HUD GUI**: Modern dark-mode interface with live Shannon Entropy telemetry charts, packet throughput gauges, protocol breakdown, and real-time threat feed.
- ⚡ **Next-Gen Traffic Analysis**: Side-channel metadata inspection (Shannon Entropy, Packet Size, Destination Port) combined with **Random Forest AI** and **UDP/QUIC (RFC 9000)** header heuristics.
- 🛡️ **Automated Kernel Firewall Mitigation**:
  - **Windows**: Inserts inbound `BLOCK` rules using Windows Defender Firewall (`netsh advfirewall` / WFP) directly at the kernel network boundary.
  - **Linux**: Inserts kernel `DROP` rules using `iptables`.
  - **Auto-Cleanup**: Dynamic rules are cleanly removed upon application shutdown.
- 🧪 **1-Click In-App Simulation Lab**: No need for 3 separate terminal windows! Launch simulated TCP or UDP/QUIC exfiltrations directly inside the dashboard with live telemetry visualization.
- 💾 **Persistent Incident Logging**: Embedded SQLite database (`cryptoflow.db`) tracking all threat timelines, confidence scores, and active firewall blocks.
- 📦 **Download & Install from GitHub**: Packaged as a standalone `CryptoFlow-IDS-Setup.exe` installer via Inno Setup and automated GitHub Actions.

---

## 🚀 Quickstart: Running on Windows

### Option 1: Download from GitHub Releases (Recommended for Users)
1. Go to the [Releases](https://github.com/Santhosh939s/CryptoFlow-IDS/releases) section of your GitHub repository.
2. Download **`CryptoFlow-IDS-Setup.exe`**.
3. Ensure [Npcap](https://npcap.com/#download) is installed with **"Support loopback traffic"** enabled.
4. Run the installer and launch **CryptoFlow-IDS** from your Desktop or Start Menu!

---

### Option 2: Running from Source (For Developers)

#### 1. Prerequisites
- **Python 3.8+**
- **Npcap for Windows**:
  1. Download the installer from [npcap.com/#download](https://npcap.com/#download).
  2. ⚠️ **During installation**, check:
     - ☑️ **"Support loopback traffic ("Npcap Loopback Adapter")"**
     - ☑️ **"Install Npcap in WinPcap API-compatible Mode"**

#### 2. Install Dependencies
Run the automated installer script:
```powershell
install.bat
```
*(Or manually: `pip install -r requirements.txt`)*

#### 3. Launch the Desktop App
Double-click:
```powershell
run_app.bat
```
*(This automatically requests Administrator elevation so Windows Defender Firewall mitigation rules can be added).*

The app will start the background IDS service and launch the **CryptoFlow-IDS Cyber HUD** in a desktop window or your browser at `http://127.0.0.1:8000`.

---

## 🧪 Testing with the In-App Simulation Lab

1. Launch the application via `run_app.bat`.
2. Click **START ENGINE** on the top HUD bar.
3. In the **Interactive Exfiltration Simulation Lab** section:
   - Click **"Simulate TCP Exfiltration"** to test standard encrypted TCP attacks.
   - Click **"Simulate UDP / QUIC Exfiltration"** to test HTTP/3 QUIC exfiltration.
   - Click **"Launch Full Hybrid Attack"** to test simultaneous multi-vector attacks.
4. Watch the dashboard instantly update:
   - Live **Shannon Entropy Stream** spikes above the 7.2 threshold.
   - **RED ALERT** threat cards appear with confidence scores and entropy levels.
   - The **Automated Firewall Mitigation** table displays an active `BLOCK` rule for the attacker's IP.
   - Click **"Unblock"** anytime to dynamically release the firewall rule.

---

## 🔨 Building the Windows Installer (`.exe`)

To compile the application into a standalone installer on your local machine:

1. **Install PyInstaller & Inno Setup**:
   ```powershell
   pip install pyinstaller
   # Install Inno Setup from https://jrsoftware.org/isdl.php
   ```

2. **Build the Executable**:
   ```powershell
   cd build
   pyinstaller --clean pyinstaller.spec
   ```

3. **Compile the Installer**:
   Open `build/installer.iss` in Inno Setup Compiler and click **Compile** (or run `iscc build/installer.iss`).  
   The resulting installer will be saved at `build/Output/CryptoFlow-IDS-Setup.exe`.

---

## 🤖 Automated GitHub Release CI/CD

This repository includes a GitHub Actions workflow (`.github/workflows/release.yml`) that automatically builds and publishes the installer whenever a new release tag is pushed:

```bash
git tag v2.0.0
git push origin v2.0.0
```

GitHub Actions will:
1. Spin up a Windows runner.
2. Compile the binaries with PyInstaller.
3. Generate `CryptoFlow-IDS-Setup.exe` with Inno Setup.
4. Publish a new GitHub Release with the installer and portable `.zip` attached!

---

## 📁 Repository Structure

```
CryptoFlow-IDS/
├── app/
│   ├── static/
│   │   ├── css/dashboard.css   # Modern Cyber HUD styling (glassmorphism, dark mode)
│   │   ├── js/dashboard.js     # Real-time WebSocket, Chart.js telemetry, audio alerts
│   │   └── index.html          # Interactive Cyber Defense Dashboard
│   ├── database.py             # SQLite persistence for threats & blocklist
│   ├── engine.py               # Threaded IDS capture & inference engine
│   ├── server.py               # FastAPI backend & WebSocket broadcaster
│   └── simulator.py            # In-App 1-click attack simulation controller
├── build/
│   ├── pyinstaller.spec        # PyInstaller specification
│   └── installer.iss           # Inno Setup Windows installer compiler script
├── .github/workflows/
│   └── release.yml             # GitHub Actions automated release builder
├── main.py                     # Main Desktop Application entrypoint
├── install.bat                 # 1-click Windows dependency setup
├── run_app.bat                 # 1-click Windows desktop launcher (with UAC elevation)
├── requirements.txt            # Python dependencies
├── detector.py                 # CLI IDS engine (Windows & Linux)
├── windows_mitigation.py       # Windows Defender Firewall (netsh) mitigation module
├── ebpf_sniffer.c              # In-kernel eBPF socket filter (Linux BCC)
├── ebpf_detector.py            # Linux eBPF detection engine
├── mitigation.py               # Linux iptables mitigation module
├── victim.py                   # Standalone attacker simulator
└── target_server.py            # Standalone receiver server
```
