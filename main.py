import os
import time
import logging
import tempfile
import pyudev
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from presidio_analyzer import AnalyzerEngine
import subprocess
import curses
import random

# ========== Инициализация Presidio ========== 
analyzer = AnalyzerEngine()

# ========== Логирование ========== 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("confidata_guard.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ========== Настройки SMTP и почты ========== 
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "ddosdetectbot@gmail.com"
SMTP_PASS = "mdvf mjwr tzss udne"
SENDER_EMAIL = "ddosdetectbot@gmail.com"
ADMIN_EMAIL = "sergei2003r@gmail.com"
DESKTOP_PATH = "/home/kali/Desktop"

def send_email_alert(file_path: str, encryption_key: str):
    subject = "ALERT: Confidential Data Found"
    body = (f"Файл содержит конфиденциальную информацию:\n"
            f"{file_path}\n\n"
            "Файл зашифрован для предотвращения утечки.\n\n"
            f"Ключ шифрования: {encryption_key}\n")
    
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg.attach(MIMEText(body, "plain", _charset="utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, msg.as_string())
        logging.info(f"Письмо отправлено: {ADMIN_EMAIL}")
    except Exception as e:
        logging.error(f"Ошибка отправки письма: {e}")

def contains_sensitive_data_presidio(file_path: str) -> bool:
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            results = analyzer.analyze(text=content, language="en", entities=None, score_threshold=0.5)
            return len(results) > 0
    except Exception as e:
        logging.warning(f"Ошибка анализа файла {file_path}: {e}")
    return False

def encrypt_file(file_path: str) -> str:
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        encrypted_file_name = os.path.basename(file_path) + ".enc"
        encrypted_file_path = os.path.join(DESKTOP_PATH, encrypted_file_name)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        os.remove(file_path)
        logging.info(f"Файл {file_path} зашифрован и сохранен в {encrypted_file_path}.")
        return key.decode()
    except Exception as e:
        logging.error(f"Ошибка шифрования {file_path}: {e}")
        return None
class UsbCopyHandler(FileSystemEventHandler):
    def process_file(self, file_path):
        logging.info(f"Обнаружен файл: {file_path}")
        if contains_sensitive_data_presidio(file_path):
            logging.warning(f"Файл содержит конфиденциальные данные: {file_path}")
            encryption_key = encrypt_file(file_path)
            if encryption_key:
                send_email_alert(file_path, encryption_key)
    
    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

def monitor_usb_mount(mount_path):
    event_handler = UsbCopyHandler()
    observer = Observer()
    observer.schedule(event_handler, mount_path, recursive=True)
    observer.start()
    logging.info(f"Мониторинг: {mount_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def find_mount_path(device_node):
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) > 1 and parts[0] == device_node:
                    return parts[1]
    except Exception as e:
        logging.error(f"Ошибка чтения /proc/mounts: {e}")
    return None

def start_snow_animation():
    snow_script = """import curses, random, time

def snow_animation(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    max_y, max_x = stdscr.getmaxyx()
    
    if max_y < 5 or max_x < 10:
        stdscr.addstr(0, 0, "Окно слишком маленькое! Увеличьте терминал.")
        stdscr.refresh()
        time.sleep(3)
        return
    
    snowflakes = [[random.randint(0, max_x - 1), random.randint(0, max_y - 1), random.uniform(0.05, 0.2)] for _ in range(100)]

    try:
        while True:
            stdscr.clear()
            for flake in snowflakes:
                try:
                    stdscr.addch(int(flake[1]), flake[0], '*')
                except curses.error:
                    pass  # Игнорируем ошибки отрисовки
                flake[1] += flake[2]
                if flake[1] >= max_y:
                    flake[1] = 0
                    flake[0] = random.randint(0, max_x - 1)
                    flake[2] = random.uniform(0.05, 0.2)  # Новая скорость

            stdscr.refresh()
            time.sleep(0.05)
    except KeyboardInterrupt:
        pass  # Позволяет безопасно выйти

curses.wrapper(snow_animation)
"""

    # Создаём временный файл с кодом
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".py")
    temp_file.write(snow_script.encode())
    temp_file.close()

    try:
        # Запускаем в новом терминале
        subprocess.Popen(['x-terminal-emulator', '-e', f'python3 {temp_file.name}'])
    finally:
        # Подождём, затем удалим временный файл
        time.sleep(1)
        os.remove(temp_file.name)

def main():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')
    logging.info("Ожидание USB...")
    start_snow_animation()
    for device in iter(monitor.poll, None):
        if device.action == 'add':
            dev_node = device.device_node
            logging.info(f"Обнаружено USB: {dev_node}")
            time.sleep(30)
            mount_path = find_mount_path(dev_node)
            if mount_path:
                logging.info(f"Точка монтирования: {mount_path}")
                monitor_usb_mount(mount_path)
            else:
                logging.warning(f"Не найден путь монтирования {dev_node}.")

if __name__ == "__main__":
    main()
