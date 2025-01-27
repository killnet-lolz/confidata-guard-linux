#!/usr/bin/env python3
import os
import time
import logging
import pyudev
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import smtplib
from email.mime.text import MIMEText

# ========== Presidio ==========
from presidio_analyzer import AnalyzerEngine
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
SMTP_HOST = "smtp.gmail.com"        # Адрес SMTP-сервера
SMTP_PORT = 587                      # Порт (587 для TLS, 465 для SSL, 25 для без шифрования)
SMTP_USER = "ddosdetectbot@gmail.com"    # Логин на почтовом сервере
SMTP_PASS = "mdvf mjwr tzss udne"               # Пароль
SENDER_EMAIL = "ddosdetectbot@gmail.com" # Адрес отправителя
ADMIN_EMAIL = "sergei2003r@gmail.com"     # Адрес получателя

def send_email_alert(file_path: str):
    """
    Отправляет письмо на почту ADMIN_EMAIL, информируя о том,
    что в файле обнаружены конфиденциальные данные.
    """
    subject = "ALERT: Confidential Data Found"
    body = (
        f"Скрипт обнаружил конфиденциальную информацию в файле:\n"
        f"{file_path}\n\n"
        "Файл был удалён, чтобы предотвратить возможную утечку данных."
    )

    # Создаём MIME-сообщение
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = ADMIN_EMAIL

    try:
        # Если нужен TLS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()           # Для шифрованного TLS
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, msg.as_string())

        logging.info(f"Письмо с оповещением успешно отправлено на {ADMIN_EMAIL}")
    except Exception as e:
        logging.error(f"Не удалось отправить письмо: {e}")

def contains_sensitive_data_presidio(file_path: str) -> bool:
    """
    Сканируем файл с помощью Microsoft Presidio AnalyzerEngine.
    Если найдены PII, возвращаем True.
    """
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            results = analyzer.analyze(
                text=content,
                language="en",
                entities=None,    # Анализируем все известные типы PII
                score_threshold=0.5
            )
            if len(results) > 0:
                return True
    except Exception as e:
        logging.warning(f"Ошибка при анализе файла {file_path} через Presidio: {e}")
    return False

class UsbCopyHandler(FileSystemEventHandler):
    """Обработчик событий в директории смонтированного USB."""
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            logging.info(f"Новый файл: {file_path}")

            if contains_sensitive_data_presidio(file_path):
                logging.warning(f"Файл '{file_path}' содержит PII (Presidio)")
                try:
                    os.remove(file_path)
                    logging.info(f"Файл удалён: {file_path}")

                    # Отправляем письмо админу
                    send_email_alert(file_path)

                except Exception as e:
                    logging.error(f"Не удалось удалить файл {file_path}: {e}")

def monitor_usb_mount(mount_path):
    """Запуск watchdog для мониторинга каталога флешки."""
    event_handler = UsbCopyHandler()
    observer = Observer()
    observer.schedule(event_handler, mount_path, recursive=True)
    observer.start()

    logging.info(f"Слежение запущено в: {mount_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def find_mount_path(device_node):
    """Упрощённый поиск точки монтирования через /proc/mounts."""
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) > 1:
                    dev, mnt = parts[0], parts[1]
                    if dev == device_node:
                        return mnt
    except Exception as e:
        logging.error(f"Ошибка при чтении /proc/mounts: {e}")
    return None

def main():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')

    logging.info("Ожидание подключения USB-устройств...")

    for device in iter(monitor.poll, None):
        if device.action == 'add':
            # Проверяем, что это действительно USB
            if device.get('ID_BUS') == 'usb':
                dev_node = device.device_node
                dev_type = device.get('DEVTYPE')
                logging.info(f"Обнаружено USB: {dev_node}, тип: {dev_type}")
                time.sleep(2)  # даём время на автоподключение

                mount_path = find_mount_path(dev_node)
                if mount_path:
                    logging.info(f"Точка монтирования: {mount_path}")
                    monitor_usb_mount(mount_path)
                else:
                    logging.warning(f"Не удалось найти точку монтирования для {dev_node}.")

if __name__ == "__main__":
    main()
