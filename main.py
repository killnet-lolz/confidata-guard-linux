#!/usr/bin/env python3
import re
import os
import time
import logging
import pyudev
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Настраиваем логирование: и в файл, и в консоль.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("confidata_guard.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================
# Регулярные выражения 
# ==========================
PHONE_REGEX = re.compile(r"(?:\+?\d[\d\-\(\)\s]{5,14}\d)")
CARD_REGEX = re.compile(r"(?:\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b)")
PASSPORT_REGEX = re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b")

def contains_sensitive_data(file_path):
    """Проверяем содержимое файла на наличие конфиденциальной информации."""
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if (PHONE_REGEX.search(content) or
                CARD_REGEX.search(content) or
                PASSPORT_REGEX.search(content)):
                return True
    except Exception as e:
        logging.warning(f"Ошибка при проверке файла {file_path}: {e}")
    return False

class UsbCopyHandler(FileSystemEventHandler):
    """Обработчик для watchdog, реагируем на создание новых файлов."""
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            logging.info(f"Новый файл: {file_path}")

            if contains_sensitive_data(file_path):
                logging.warning(f"Конфиденциальная информация в файле: {file_path}")
                try:
                    os.remove(file_path)
                    logging.info(f"Файл '{file_path}' удалён.")
                except Exception as e:
                    logging.error(f"Не удалось удалить файл '{file_path}': {e}")

def monitor_usb_mount(mount_path):
    """Запускаем слежение за директорией, где смонтирована флешка."""
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
    """
    Упрощённо ищем точку монтирования, проверяя /proc/mounts.
    Ищем строку, где dev == device_node (например, /dev/sdb1).
    """
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) > 1:
                    dev, mnt = parts[0], parts[1]
                    if dev == device_node:
                        return mnt
    except Exception as e:
        logging.error(f"Ошибка при парсинге /proc/mounts: {e}")
    return None

def main():
    """
    Главный цикл: слушаем события block (диски/разделы). Если это USB, пытаемся найти точку монтирования.
    """
    context = pyudev.Context()
    # Фильтруем только подсистему "block" (чтобы ловить и диски, и разделы).
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')

    logging.info("Ожидание подключения USB-устройств...")

    # monitor.poll() — блокирующий вызов, будем крутиться в for-цикле.
    for device in iter(monitor.poll, None):
        if device.action == 'add':
            # Проверяем, действительно ли это USB
            if device.get('ID_BUS') == 'usb':
                dev_node = device.device_node     # Например, /dev/sdb или /dev/sdb1
                dev_type = device.get('DEVTYPE')  # Может быть 'disk' или 'partition'

                logging.info(f"Обнаружено USB-устройство: {dev_node} (тип: {dev_type})")

                # Дадим время системе смонтировать
                time.sleep(2)

                # Пытаемся найти точку монтирования
                mount_path = find_mount_path(dev_node)
                if mount_path:
                    logging.info(f"Точка монтирования найдена: {mount_path}")
                    monitor_usb_mount(mount_path)
                else:
                    logging.warning(f"Не удалось найти точку монтирования для {dev_node}.")

if __name__ == "__main__":
    main()
