# Mini-EDR (Behavior-Based Ransomware Detector) — Installation & Run Guide

Follow these steps to install all dependencies and run the Mini-EDR project on a Windows machine from scratch.

---

## 1. Prerequisites

* **Operating System:** Windows 10 or Windows 11 (required for Windows Volume Shadow Copy [VSS] and Authenticode signature verification).
* **Python Version:** Python 3.9 or higher (make sure **"Add Python to PATH"** is checked during Python installation).
* **Project Files:** Ensure your project folder contains:
  * `edr_engine.py`
  * `app.py`
  * `db_manager.py`
  * `fake_ransomware.py`
  * `restart_engine.py`
  * `requirements.txt`

> **Note:** Built-in Python modules (`sqlite3`, `zlib`, `hashlib`, `ctypes`, `threading`, `subprocess`, `socket`) are included with Python by default and do not require separate installation.

---

## 2. Step-by-Step Installation

### Step 1: Open Terminal in the Project Folder
1. Open **Command Prompt (CMD)** or **PowerShell**.
2. Navigate to your project directory:
   ```cmd
   cd C:\path\to\your\project_folder
   ```

### Step 2: Create & Activate a Virtual Environment (Optional but Recommended)
Using a virtual environment keeps project libraries isolated from your global Python setup:
```cmd
python -m venv venv
venv\Scripts\activate
```
*(If you are using Conda, activate your Conda environment instead: `conda activate your_env_name`.)*

### Step 3: Install All Libraries in One Command
Run the following command to install every required package listed in `requirements.txt`:
```cmd
pip install -r requirements.txt
```
Wait for the installation to complete without errors.

---

## 3. Running the Project

### Step 4: Start the Background EDR Engine
Choose one of the two modes below:

* **Option A — Admin Mode (Recommended for Full 3-Tier Recovery including Tier-1 Windows VSS):**
  ```cmd
  python restart_engine.py --admin
  ```
  Click **Yes** on the Windows UAC prompt to grant Administrator privileges.

* **Option B — Standard Mode (Tier-2 Folder-Mirrored Backup Vault only):**
  ```cmd
  python restart_engine.py
  ```

### Step 5: Launch the Security Dashboard
In the same terminal (inside your project folder), run:
```cmd
streamlit run app.py
```
The dashboard will automatically open in your default browser at:
```text
http://localhost:8501
```

---

## 4. Quick Verification After Startup

1. Check the top status banner on the dashboard: it should show **`ENDPOINT STATE: SECURE`** and **`ADMIN | TIER-1 VSS ON`** (if started with `--admin`).
2. Confirm that `Demo_Protected_Folder` and `MiniEDR_Backup_Vault` have been initialized automatically.
3. Go to **Tab 01 (Live Demo & Simulation Panel)** and click **`FULL BURST ATTACK`** or **`TRAP-EVADING BURST`** to confirm real-time detection, process termination, and automated recovery.

---

## 5. Stopping the Project

1. **Stop the Dashboard:** Press `Ctrl + C` in the terminal running Streamlit.
2. **Stop the Background Engine:** Run the following command or close its process:
   ```cmd
   python -c "import db_manager as db; db.send_command('SHUTDOWN_ENGINE')"
   ```

---

## 6. Troubleshooting

* **`streamlit` is not recognized:** Run the dashboard using Python directly:
  ```cmd
  python -m streamlit run app.py
  ```
* **`pip` is not recognized:** Install packages using:
  ```cmd
  python -m pip install -r requirements.txt
  ```
* **Tier-1 VSS Not Active:** Ensure the background sensor was launched with `python restart_engine.py --admin` and that Windows Volume Shadow Copy is supported on your drive.