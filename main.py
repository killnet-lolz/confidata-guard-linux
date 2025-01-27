#!/usr/bin/env python3
import re
import os
import time
import pyudev
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================
# Регулярные выражения
# ==========================
# - Примеры довольно упрощены.

# Пример номера телефона (только для демонстрации), 
# ищет последовательность из 7-11 цифр, допускает символы +, -, пробелы и скобки.
PHONE_REGEX = re.compile(r"(?:\+?\d[\d\-\(\)\s]{5,14}\d)")

# Пример номера банковской карты (16 цифр, допускаются пробелы)
CARD_REGEX = re.compile(r"(?:\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b)")

# Упрощённый пример паспортных данных (серия и номер, 10-12 цифр подряд или с пробелом).
PASSPORT_REGEX = re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b")


def contains_sensitive_data(file_path):
    """
    Проверяем содержимое файла на наличие конфиденциальной информации.
    Если находим совпадение - возвращаем True.
    """
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
        # В случае ошибки чтения файла — можно либо логировать, либо пропускать.
        print(f"[!] Ошибка при проверке файла {file_path}: {e}")
    return False


class UsbCopyHandler(FileSystemEventHandler):
    """
    Обработчик событий в директории смонтированной флешки.
    Если появляется новый файл, проверяем содержимое и, при необходимости, удаляем.
    """
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"[INFO] Обнаружен новый файл: {file_path}")

            if contains_sensitive_data(file_path):
                print(f"[ALERT] Конфиденциальная информация обнаружена в файле: {file_path}")
                try:
                    os.remove(file_path)
                    print(f"[ACTION] Файл '{file_path}' был удалён для предотвращения утечки данных.")
                except Exception as e:
                    print(f"[ERROR] Не удалось удалить файл '{file_path}': {e}")


def monitor_usb_mount(mount_path):
    """
    Функция запускает слежение за директорией, где смонтирована USB-флешка.
    Используем watchdog для отслеживания появления новых файлов.
    """
    event_handler = UsbCopyHandler()
    observer = Observer()
    observer.schedule(event_handler, mount_path, recursive=True)
    observer.start()

    print(f"[INFO] Запущен мониторинг в: {mount_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main():
    """
    Главная функция:
    1. Отслеживаем через pyudev появление новых устройств типа 'disk' (USB).
    2. Когда устройство появляется, предполагаем, что оно монтируется в /media или /run/media и т.д.
    3. Запускаем мониторинг изменений в смонтированной директории.
    """
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block', device_type='disk')

    print("[INFO] Ожидание подключения USB-устройств...")
    
    for device in iter(monitor.poll, None):
        # Здесь можно уточнять, действительно ли это USB (DRIVER = 'usb', ID_BUS = 'usb' и т.п.)
        if device.action == 'add':
            print(f"[INFO] Устройство добавлено: {device.device_node}")

            # Обычно нужно подождать, пока система смонтирует устройство (или смонтировать вручную).
            # Ниже приводится пример упрощённого поиска точки монтирования.
            # В реальности вы можете использовать вызов `lsblk -o NAME,MOUNTPOINT` или 
            # парсить содержимое /proc/mounts, чтобы получить точку монтирования.
            
            time.sleep(3)  # Даем системе время смонтировать

            mount_path = find_mount_path(device.device_node)
            if mount_path:
                print(f"[INFO] Найдена точка монтирования: {mount_path}")
                monitor_usb_mount(mount_path)
            else:
                print("[WARNING] Не удалось определить точку монтирования. "
                      "Устройство может не быть смонтировано автоматически.")


def find_mount_path(device_node):
    """
    Упрощённый вариант поиска точки монтирования для устройства.
    Пробегаемся по /proc/mounts и ищем совпадение по названию устройства.
    Например, /dev/sdb1 -> /media/usb или /run/media/пользователь/usb и т.д.
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
        print(f"[ERROR] Ошибка при парсинге /proc/mounts: {e}")
    return None


if __name__ == "__main__":
    main()
