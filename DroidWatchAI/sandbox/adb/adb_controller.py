# sandbox/adb/adb_controller.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — ADB Controller
# Owner: Gahan Shetty
#
# Manages ADB commands to the Android emulator.
# ─────────────────────────────────────────────────────────────

import subprocess
import time
from backend.utils.logger import get_logger

logger = get_logger("adb_controller")

ADB = "adb"  # assumes adb is in system PATH


class ADBController:
    def __init__(self, device_id: str = "emulator-5554"):
        self.device_id = device_id
        self.base_cmd = [ADB, "-s", device_id]

    def _run(self, *args, timeout: int = 30) -> tuple[int, str, str]:
        cmd = self.base_cmd + list(args)
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    # ── Device checks ─────────────────────────────────────────
    def is_device_online(self) -> bool:
        rc, out, _ = self._run("get-state")
        return rc == 0 and "device" in out

    def wait_for_device(self, timeout: int = 60) -> bool:
        logger.info("Waiting for emulator to come online...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_device_online():
                logger.info("Emulator is online.")
                return True
            time.sleep(2)
        logger.error("Emulator did not come online in time.")
        return False

    def list_devices(self) -> list[str]:
        result = subprocess.run([ADB, "devices"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]  # skip header
        return [l.split("\t")[0] for l in lines if "device" in l and "offline" not in l]

    # ── APK management ────────────────────────────────────────
    def install_apk(self, apk_path: str) -> bool:
        logger.info(f"Installing APK: {apk_path}")
        rc, out, err = self._run("install", "-r", apk_path, timeout=120)
        if rc == 0 and "Success" in out:
            logger.info("APK installed successfully.")
            return True
        logger.error(f"APK install failed: {err or out}")
        return False

    def uninstall_apk(self, package_name: str) -> bool:
        logger.info(f"Uninstalling: {package_name}")
        rc, out, _ = self._run("uninstall", package_name)
        return rc == 0

    def get_installed_packages(self) -> list[str]:
        rc, out, _ = self._run("shell", "pm", "list", "packages")
        return [line.replace("package:", "") for line in out.split("\n") if line.startswith("package:")]

    # ── App control ───────────────────────────────────────────
    def launch_app(self, package_name: str, activity: str) -> bool:
        logger.info(f"Launching: {package_name}/{activity}")
        rc, out, err = self._run("shell", "am", "start", "-n", f"{package_name}/{activity}")
        return rc == 0

    def stop_app(self, package_name: str) -> bool:
        logger.info(f"Force stopping: {package_name}")
        rc, _, _ = self._run("shell", "am", "force-stop", package_name)
        return rc == 0

    # ── File system ───────────────────────────────────────────
    def pull_file(self, remote_path: str, local_path: str) -> bool:
        rc, _, err = self._run("pull", remote_path, local_path)
        if rc != 0:
            logger.error(f"Pull failed: {err}")
        return rc == 0

    def list_dir(self, path: str) -> list[str]:
        rc, out, _ = self._run("shell", "ls", "-la", path)
        return out.split("\n") if rc == 0 else []

    # ── Screenshots ───────────────────────────────────────────
    def take_screenshot(self, save_path: str) -> bool:
        remote = "/sdcard/screenshot.png"
        rc1, _, _ = self._run("shell", "screencap", "-p", remote)
        rc2, _, _ = self._run("pull", remote, save_path)
        return rc1 == 0 and rc2 == 0

    # ── Permissions ───────────────────────────────────────────
    def revoke_permission(self, package: str, permission: str) -> bool:
        logger.info(f"Revoking {permission} from {package}")
        rc, _, _ = self._run("shell", "pm", "revoke", package, permission)
        return rc == 0

    def get_permissions(self, package: str) -> list[str]:
        rc, out, _ = self._run("shell", "dumpsys", "package", package)
        perms = []
        for line in out.split("\n"):
            if "permission" in line.lower() and "granted=true" in line.lower():
                parts = line.strip().split(":")
                if parts:
                    perms.append(parts[0].strip())
        return perms
