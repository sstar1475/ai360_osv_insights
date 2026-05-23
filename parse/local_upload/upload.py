import os
import sys
import subprocess
import venv
from pathlib import Path

REQUIRED_PACKAGES = ["paramiko", "scp"]
VENV_DIR = Path.home() / ".ai360_upload_venv"
SERVER_CONFIG = {
    "host": "заменить на данные из закрепа",
    "user": "заменить на данные из закрепа",
    "pass": "заменить на данные из закрепа",
    "dest": "заменить на данные из закрепа"
}


def setup_and_restart():
    if not VENV_DIR.exists():
        venv.create(VENV_DIR, with_pip=True)

    if sys.platform == "win32":
        python_executable = VENV_DIR / "Scripts" / "python.exe"
    else:
        python_executable = VENV_DIR / "bin" / "python"

    subprocess.check_call([
        str(python_executable), "-m", "pip", "install",
        *REQUIRED_PACKAGES, "--quiet"
    ])
    os.execv(str(python_executable), [str(python_executable)] + sys.argv)


def upload(path):
    from paramiko import SSHClient, AutoAddPolicy
    from scp import SCPClient
    import zipfile
    import tempfile

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    stats = {
        "files_count": 0,
        "total_size": 0,
        "sent_bytes": 0,
        "errors": []
    }

    last_percent = -1
    current_file_base_sent = 0

    def progress_callback(filename, size, sent):
        nonlocal last_percent
        total_progress_sent = current_file_base_sent + sent
        if stats["total_size"] > 0:
            percent = int((total_progress_sent / stats["total_size"]) * 100)
            if percent % 10 == 0 and percent != last_percent:
                print(f"Общий прогресс: {percent}%")
                last_percent = percent

    try:
        print(f"Подключение к {SERVER_CONFIG['host']}...")
        ssh.connect(
            SERVER_CONFIG["host"],
            username=SERVER_CONFIG["user"],
            password=SERVER_CONFIG["pass"]
        )

        files_to_upload = []
        tmp_dir_obj = None

        if path.lower().endswith(".zip"):
            print(f"Распаковка архива: {path}")
            tmp_dir_obj = tempfile.TemporaryDirectory()
            tmp_dir = tmp_dir_obj.name
            with zipfile.ZipFile(path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)

            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    files_to_upload.append(os.path.join(root, file))
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    files_to_upload.append(os.path.join(root, file))
        else:
            files_to_upload.append(path)

        for f_path in files_to_upload:
            stats["total_size"] += os.path.getsize(f_path)

        print(f"Запуск загрузки {len(files_to_upload)} файлов ({stats['total_size'] / 1024 / 1024:.2f} МБ)...")

        with SCPClient(ssh.get_transport(), progress=progress_callback) as scp:
            for f_path in files_to_upload:
                try:
                    file_size = os.path.getsize(f_path)
                    scp.put(f_path, remote_path=SERVER_CONFIG["dest"])
                    stats["files_count"] += 1
                    current_file_base_sent += file_size
                except Exception as e:
                    stats["errors"].append(f"Файл {os.path.basename(f_path)}: {str(e)}")

        print("\n--- ИТОГОВЫЙ ОТЧЕТ ---")
        status_text = 'Успешно, но с ошибками' if stats['errors'] else 'Успешно'
        print(f"Статус: {status_text}")
        print(f"Загружено файлов: {stats['files_count']}")
        print(f"Общий размер: {stats['total_size'] / 1024 / 1024:.2f} МБ")

        if stats["errors"]:
            print("\nОбнаруженные ошибки:")
            for err in stats["errors"]:
                print(f"  - {err}")
        print("--------------------")

    except Exception as e:
        print(f"\n Критическая ошибка: {e}")
    finally:
        ssh.close()
        if tmp_dir_obj:
            tmp_dir_obj.cleanup()


if __name__ == "__main__":
    is_venv = sys.prefix == str(VENV_DIR)
    if not is_venv:
        setup_and_restart()
    else:
        if len(sys.argv) < 2:
            sys.exit(1)
        upload(sys.argv[1])
