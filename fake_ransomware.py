import os
import sys
import stat
import time

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_SANDBOX = os.path.abspath(os.path.join(BASE_DIR, "Demo_Protected_Folder"))
VAULT_DIR = os.path.abspath(os.path.join(BASE_DIR, "MiniEDR_Backup_Vault"))
TRAP_NAME = "!000_Trap"


def verify_safety(target_path):
    """Safety guard: simulator can ONLY operate inside the project directory."""
    abs_target = os.path.abspath(target_path)
    assert os.path.normcase(abs_target).startswith(os.path.normcase(BASE_DIR)), (
        f"SAFETY VIOLATION: Target {abs_target} is outside project folder {BASE_DIR}!"
    )


def list_trap_files(target_dir):
    trap_folder = os.path.join(target_dir, TRAP_NAME)
    verify_safety(trap_folder)
    if not os.path.isdir(trap_folder):
        return []
    return [os.path.join(trap_folder, f) for f in sorted(os.listdir(trap_folder))]


def list_main_files(target_dir):
    out = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d != TRAP_NAME]
        for f in sorted(files):
            if f.endswith(".locked"):
                continue
            out.append(os.path.join(root, f))
    return out


def attack_file(fp, mode):
    verify_safety(fp)
    if mode == "partial":
        with open(fp, "r+b") as out:
            out.seek(0)
            out.write(os.urandom(4096))
    elif mode == "trap":
        with open(fp, "wb") as out:
            out.write(os.urandom(8192))
    else:
        locked_fp = fp + ".locked"
        verify_safety(locked_fp)
        with open(locked_fp, "wb") as out:
            out.write(os.urandom(32768))
        os.remove(fp)


def simulate_vault_tamper():
    """Simulates ransomware trying to corrupt backups inside MiniEDR_Backup_Vault subfolders."""
    verify_safety(VAULT_DIR)
    if not os.path.isdir(VAULT_DIR):
        return
    for root, _, files in os.walk(VAULT_DIR):
        for fname in sorted(files):
            fp = os.path.join(root, fname)
            verify_safety(fp)
            try:
                os.chmod(fp, stat.S_IWRITE)
                with open(fp, "wb") as out:
                    out.write(os.urandom(4096))
                time.sleep(0.2)
            except Exception:
                pass


def simulate_ransomware(mode="normal", target_dir=None):
    if mode == "vault":
        simulate_vault_tamper()
        return

    target_dir = os.path.abspath(target_dir) if target_dir else DEFAULT_SANDBOX
    verify_safety(target_dir)
    if not os.path.isdir(target_dir):
        return

    if mode == "trap":
        targets = list_trap_files(target_dir)
    elif mode == "notrap":
        targets = list_main_files(target_dir)
    else:
        targets = list_trap_files(target_dir) + list_main_files(target_dir)

    delay = 1.2 if mode == "slow" else (0.18 if mode == "trap" else 0.25)
    attack_mode = "normal" if mode == "notrap" else mode

    for fp in targets:
        try:
            if not os.path.exists(fp):
                continue
            attack_file(fp, attack_mode)
            time.sleep(delay)
        except Exception:
            pass


if __name__ == "__main__":
    attack_mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    custom_target = sys.argv[2] if len(sys.argv) > 2 else None
    simulate_ransomware(attack_mode, custom_target)