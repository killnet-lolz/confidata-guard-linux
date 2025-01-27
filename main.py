#!/usr/bin/env python3
import os
import time
import logging
import pyudev
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========
# Presidio
# ==========
from presidio_analyzer import AnalyzerEngine

# Создаём глобальный объект анализатора Presidio.
analyzer = AnalyzerEngine()

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("confidata_guard.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

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
            # По умолчанию Presidio анализирует англоязычные структуры (phone, email, card, etc.)
            # language="en" — для англ. Вы можете добавить custom recognizers для русского.
            results = analyzer.analyze(
                text=content,
                language="en",
                entities=None,    # None = анализировать все известные сущности
                score_threshold=0.5
            )

            # Если хоть один результат (у которого confidence > 0.5 и т.д.), считаем файл конфиденциальным.
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
            # Проверяем, что это реально USB
            if device.get('ID_BUS') == 'usb':
                dev_node = device.device_node
                dev_type = device.get('DEVTYPE')
                logging.info(f"Обнаружено USB: {dev_node}, тип: {dev_type}")
                time.sleep(2)  # немного ждём автоподключение

                mount_path = find_mount_path(dev_node)
                if mount_path:
                    logging.info(f"Точка монтирования: {mount_path}")
                    monitor_usb_mount(mount_path)
                else:
                    logging.warning(f"Не удалось найти точку монтирования для {dev_node}.")

if __name__ == "__main__":
    main()
