#! /usr/bin/env python3

import locale
import subprocess
import dialog
import socket
import re
import os
import fcntl
import struct

locale.setlocale(locale.LC_ALL, '')

d = dialog.Dialog(dialog="dialog")
d.set_background_title("Конфигуратор ALDPro")

# Определяем поля формы
form = [
    ("Имя домена:", 1, 1, "", 1, 30, 20, 0, 0),
    ("Пароль администратора:", 2, 1, "", 2, 30, 20, 0, 1),
    ("Повторите пароль:", 3, 1, "", 3, 30, 20, 0, 1)
]

# Регулярное выражение для проверки валидности имени домена
domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])

while True:
    # Выводим форму и получаем введенные данные
    code, fields = d.mixedform("Введите данные", form, insecure=True)

    if code == d.CANCEL:
        os.system('clear')  # Очистка экрана
        print("Отменено")
        break

    domain_name, admin_password, confirm_password = fields

    # Проверяем валидность имени домена
    if not re.match(domain_regex, domain_name):
        d.msgbox("Некорректное имя домена. Пожалуйста, введите валидное имя домена.")
        form[0] = ("Имя домена:", 1, 1, domain_name, 1, 30, 20, 0, 0)
        continue

    # Проверяем, что пароли не пустые
    if not admin_password or not confirm_password:
        d.msgbox("Пароли не могут быть пустыми. Пожалуйста, введите пароли.")
        form[0] = ("Имя домена:", 1, 1, domain_name, 1, 30, 20, 0, 0)
        continue

    # Проверяем совпадение паролей
    if admin_password == confirm_password:
        # Получаем имя компьютера и IP-адрес
        hostname = socket.gethostname()
        #ip_address = socket.gethostbyname(hostname)
        ip_address = get_ip_address('eth0')

        # Выводим форму для выбора действия
        code, action = d.menu("Имя компьютера: {}\nIP-адрес: {}\nИмя домена: {}".format(hostname, ip_address, domain_name), choices=[("Запустить","Запустить установку"), ("Конфигурация","Вернуться к конфигурации")])

        if code == d.OK:
            if action == "Запустить":
                # Запускаем bash-скрипт с введенными параметрами
                subprocess.run(["bash", "script.sh", domain_name, admin_password, ip_address, hostname])
                break
            elif action == "Конфигурация":
                form[0] = ("Имя домена:", 1, 1, domain_name, 1, 30, 20, 0, 0)
                continue
        elif code == d.CANCEL:
            os.system('clear')  # Очистка экрана
            print("Отменено")
            break
    else:
        d.msgbox("Пароли не совпадают. Попробуйте снова.")
