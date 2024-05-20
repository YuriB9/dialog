#! /usr/bin/env python3

import locale
import subprocess
import dialog
import socket
import re
import os
import fcntl
import struct
import time
import shlex
import json
import ldap
import dns.resolver
import requests


def run_command_without_output(command):
    args = shlex.split(command)
    devnull = open(os.devnull, 'w')
    process = subprocess.Popen(args, stdout=devnull, stderr=subprocess.PIPE)
    output, error = process.communicate()
    # process.wait()
    devnull.close()

    if process.returncode != 0:
        raise Exception(
            f"Ошибка при выполнении команды: {error}. Подробный лог в /var/log/salt/minion.")


def is_valid_domain(domain):
    # try:
    # Попытка получить IP-адрес из имени домена
    #    socket.gethostbyname(domain_name)
    # except socket.gaierror:
    #    return False
    # else:
    #    return True
    try:
        # Создаем экземпляр dns.resolver.Resolver
        resolver = dns.resolver.Resolver()

        # Получаем NS-записи для указанного домена
        resolver.query(domain, 'NS')

        # Создаем список серверов имен
        # ns_records = resolver.query(domain, 'NS')
        # name_servers = [ns.target.to_text() for ns in ns_records]

        return True
    except Exception as e:
        return False


def is_domain_available(domain, port=389, base_dn=''):
    try:
        server = ldap.initialize(f'ldap://{domain}:{port}')
        server.simple_bind_s()

        # Выполняем анонимный поиск в корневом каталоге
        search_scope = ldap.SCOPE_BASE_OBJECT
        search_filter = '(objectClass=*)'
        result = server.search_s(base_dn, search_scope, search_filter)

        server.unbind_s()
        return True
    except ldap.LDAPError as e:
        return False


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])


def set_hosts(host, ip, domain):
    try:
        hosts_file = "/etc/hosts"
        new_line = f"{ip}   {host}.{domain} {host}"

        with open(hosts_file, "a") as file:
            file.write("\n" + new_line)
    except Exception as e:
        raise e


def is_ip_in_hosts(ip):
    with open("/etc/hosts", "r") as file:
        for line in file.readlines():
            if ip in line:
                return True

    return False


def set_resolv(ip, domain):
    try:
        resolv_file = "/etc/resolv.conf"
        nameserver_line = f"nameserver {ip}"
        search_line = f"search {domain}"

        with open(resolv_file, "w") as file:
            file.write(nameserver_line + "\n" + search_line)
    except Exception as e:
        raise e


def is_ip_in_resolv(ip):
    with open("/etc/resolv.conf", "r") as file:
        for line in file.readlines():
            if ip in line:
                return True

    return False


def create_minion_conf(host, domain):
    data = f'master: {host}.{domain}'
    with open('/etc/salt/minion.d/preinst.conf', 'w') as file:
        file.write(data)


def delete_minion_conf():
    os.remove('/etc/salt/minion.d/preinst.conf')


def api_login(ip, login, password):
    try:
        url = f"https://{ip}/ad/api/ds/login"
        payload = {"data": {"login": login, "password": password}}
        headers = {'accept': 'application/json',
                'Content-Type': 'application/json'}
        response = requests.post(url, json=payload, headers=headers, verify=False)

        if response.json()["success"]:
            return response.cookies
        else:
            return False
    except Exception as e:
        raise e

def api_send_request(ip, path, data, cookies):
    url = f"https://{ip}/ad/api{path}"
    headers = {'accept': 'application/json',
               'Content-Type': 'application/json'}
    response = requests.post(
        url, json=data, headers=headers, cookies=cookies, verify=False)

    if response.json()["success"]:
        print("Запрос успешно отправлен")
    else:
        return False


def api_get_job_id(ip, cookies):
    query = "?filters={\"property\":\"automationtaskjoblistitem_job_status\",\"value\":\"STARTED\",\"operator\":\"eq\",\"join\":\"OR\"}&limit=1&sortby=-automationtaskjoblistitem_job_created_date"
    url = f"https://{ip}/ad/api/ds/automation-tasks/jobs{query}"
    response = requests.get(url, cookies=cookies, verify=False)
    data = response.json()["data"]
    if data:
        return data[0]["automationtaskjoblistitem_job_id"]
    else:
        False


locale.setlocale(locale.LC_ALL, '')

d = dialog.Dialog(dialog="dialog")
d.set_background_title("Програмный комплекс ALD PRO")

item_help1_domain = "Введите валидное имя нового домена. Single-label имена запрещены"
item_help1_hostname = "Введите новое имя хоста"
item_help1_adminpassword = "Введите пароль"
item_help1_confirmpassword = "Пароль должен совпадать с введенным в предыдущее поле"

# Определяем поля формы
form1 = [
    ("Имя хоста:", 1, 1, "", 1, 30, 20, 0, 0,  item_help1_hostname),
    ("Имя домена:", 2, 1, "", 2, 30, 20, 0, 0, item_help1_domain),
    ("Пароль администратора:", 3, 1, "", 3,
     30, 20, 0, 1, item_help1_adminpassword),
    ("Повторите пароль:", 4, 1, "", 4, 30, 20, 0, 1, item_help1_confirmpassword)
]

item_help2_hostname = "Введите новое имя хоста"
item_help2_domain = "Введите имя домена для присоединения"
item_help2_ip = "Введите Ip адрес первого контроллера домена"
item_help2_adminpassword = "Введите пароль"

form2 = [
    ("Имя хоста:", 1, 1, "", 1, 30, 20, 0, 0,  item_help2_hostname),
    ("Имя домена:", 2, 1, "", 2, 30, 20, 0, 0, item_help2_domain),
    ("Ip контроллера домена:", 3, 1, "", 3, 30, 20, 0, 0, item_help2_ip),
    ("Пароль администратора домена:", 4, 1, "",
     4, 30, 20, 0, 1, item_help2_adminpassword),
]

item_help3_ip = "Введите Ip адрес первого контроллера домена"
item_help3_adminpassword = "Введите пароль"

form3 = [
    ("Ip контроллера домена:", 1, 1, "", 1, 30, 20, 0, 0, item_help3_ip),
    ("Пароль администратора домена:", 2, 1, "",
     2, 30, 20, 0, 1, item_help3_adminpassword),
]


# Регулярное выражение для проверки валидности имени домена
domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

# Регулярное выражение для проверки имени NetBIOS
netbios_regex = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,14}[a-zA-Z0-9]$'

# Регулярное выражение для проверки пароля администратора
password_regex = r'.{8,}'

wait_interval = 10

try:

    while True:

        # Получаем имя компьютера и IP-адрес
        current_hostname = socket.gethostname()
        ip_address = get_ip_address('eth0')

        # Выводим форму для выбора действия
        code, action = d.menu(
            f"Astra Linux Directory Pro. Версия 2.3.0\n\nИмя компьютера: {current_hostname}\nIP-адрес (eth0): {ip_address}",
            choices=[
                ("1 Развертывание", "первого контроллера домена"),
                ("2 Присоединение", "хоста к домену"),
                ("3 Установка", "резервного контроллера домена")
            ]
        )

        if code != d.OK:
            os.system('clear')  # Очистка экрана
            print("Отменено")
            break

        if action == "1 Развертывание":

            # Выводим форму и получаем введенные данные
            code, fields = d.mixedform(
                "Введите данные", form1, insecure=True, item_help=True)

            if code == d.CANCEL:
                continue

            hostname, domain, admin_password, confirm_password = fields

            # Проверяем валидность имени хоста
            if not re.match(netbios_regex, hostname):
                d.msgbox(
                    "Некорректное имя хоста. Пожалуйста, введите валидное netbios имя хоста.")
                form1 = [
                    ("Имя хоста:", 1, 1, "", 1, 30,
                     20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, admin_password,
                     3, 30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, confirm_password,
                     4, 30, 20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            # Проверяем валидность имени домена
            if not re.match(domain_regex, domain):
                d.msgbox(
                    "Некорректное имя домена. Пожалуйста, введите валидное имя домена.")
                form1 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, "", 2, 30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, admin_password,
                     3, 30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, confirm_password,
                     4, 30, 20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            # Проверяем DNS имя домена
            if is_valid_domain(domain):
                d.msgbox(
                    "DNS имя домена уже используется. Пожалуйста, введите другое имя домена.")
                form1 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, "", 2, 30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, admin_password,
                     3, 30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, confirm_password,
                     4, 30, 20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            # Проверяем, что пароли не пустые
            if not admin_password or not confirm_password:
                d.msgbox(
                    "Пароли не могут быть пустыми. Пожалуйста, введите пароли.")
                form1 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, "", 3,
                     30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, "", 4, 30,
                     20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            # Проверяем длину паролей
            if not re.match(password_regex, admin_password):
                d.msgbox(
                    "Длина пароля менее 8 символов. Пожалуйста, введите пароли длиннее 7 символов.")
                form1 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, "", 3,
                     30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, "", 4, 30,
                     20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            # Проверяем совпадение паролей
            if admin_password != confirm_password:
                d.msgbox("Пароли не совпадают. Попробуйте снова.")
                form1 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help1_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help1_domain),
                    ("Пароль администратора:", 3, 1, "", 3,
                     30, 20, 0, 1, item_help1_adminpassword),
                    ("Повторите пароль:", 4, 1, "", 4, 30,
                     20, 0, 1, item_help1_confirmpassword)
                ]
                continue

            d.gauge_start()

            try:

                if not hostname.endswith(f".{domain}"):
                    d.gauge_update(
                        5, 'Конфигурация /etc/hostname', update_text=True)
                    run_command_without_output(
                        f'sudo hostnamectl set-hostname {hostname}.{domain}')
                    aldpro_first_dc = f'{hostname}.{domain}'
                else:
                    hostname = hostname.split('.')[0]

                # TODO stop cloud-init to reconfigure hostname

                # FIXME hardcoded hostname
                d.gauge_update(7, 'Конфигурация RabbitMQ', update_text=True)
                run_command_without_output(
                    'sudo rabbitmqctl -n rabbit@smolensk-base stop')
                run_command_without_output(
                    'sudo rm -rf /var/lib/rabbitmq/mnesia/')

                if not is_ip_in_hosts(ip_address):
                    d.gauge_update(
                        10, 'Конфигурация /etc/hosts', update_text=True)
                    set_hosts(hostname, ip_address, domain)

                d.gauge_update(15, 'Конфигурация Salt Minion',
                               update_text=True)
                create_minion_conf(hostname, domain)

                d.gauge_update(
                    20, f'Перезапуск службы Salt Master на локальной системе.\nОжидаем {wait_interval} сек.', update_text=True)
                run_command_without_output(
                    'salt-call service.restart salt-master --local')

                time.sleep(wait_interval)

                d.gauge_update(
                    20, f'Перезапуск службы Salt Minion на локальной системе.\nОжидаем {wait_interval} сек.', update_text=True)
                run_command_without_output(
                    'salt-call service.restart salt-minion --local')
                time.sleep(wait_interval)

                # run_command_with_show_stdout('salt-key -A -y')
                d.gauge_update(
                    20, 'Применение всех ожидающих подключения ключей Salt Minion', update_text=True)
                run_command_without_output('salt-key -A -y')

                # run_command_with_show_stdout('salt-run saltutil.sync_all')
                # run_command_with_show_stdout('salt-call saltutil.sync_all --master={}'.format(hostname))
                # run_command_with_show_stdout('salt-call saltutil.refresh_modules --master={} async=False'.format(hostname))
                d.gauge_update(
                    40, 'Синхронизация локальных данных.', update_text=True)
                run_command_without_output('salt-run saltutil.sync_all')

                d.gauge_update(
                    40, 'Синхронизация данных с Salt Master.', update_text=True)
                run_command_without_output(
                    f'salt-call saltutil.sync_all --master={hostname}')

                d.gauge_update(
                    45, f'Обновление модулей и grains на Minion.\nОжидаем {wait_interval} сек', update_text=True)
                run_command_without_output(
                    f'salt-call saltutil.refresh_modules --master={hostname} async=False')
                time.sleep(wait_interval)

                # run_command_with_show_stdout('salt-call grains.set aldpro_machine_type dc')
                # run_command_with_show_stdout('salt-call state.apply utils.passwords queue=True --master={}'.format(hostname))
                d.gauge_update(
                    50, 'Применение состояния (state) utils.passwords', update_text=True)
                run_command_without_output(
                    'salt-call grains.set aldpro_machine_type dc')
                run_command_without_output(
                    f'salt-call state.apply utils.passwords queue=True --master={hostname}')

                # run_command_with_show_stdout("salt-call state.apply aldpro.dc.install pillar='{}' queue=True".format(pillar_string))
                # run_command_with_show_stdout('salt-call state.apply aldpro.dc.states.configure_salt_logs queue=True --master={}'.format(hostname))
                # run_command_with_show_stdout('salt-call state.apply utils.passwords queue=True --master={}'.format(hostname))
                # run_command_with_show_stdout('salt-call grains.delkey aldpro_machine_type')
                d.gauge_update(
                    50, 'Применение состояния (state) aldpro.dc.install\nПриблизительное время выполнения - 15 мин', update_text=True)
                pillar = {
                    'admin_password': admin_password,
                    'domain': domain,
                    'host': hostname,
                    'ip': ip_address,
                    'aldpro_first_dc': f'{hostname}.{domain}',
                    'setup_syncer': True,
                    'action': 'install',
                    'setup_gc': True
                }
                pillar_string = json.dumps(pillar)
                run_command_without_output(
                    f"salt-call state.apply aldpro.dc.install pillar='{pillar_string}'")
                run_command_without_output(
                    f'salt-call state.apply aldpro.dc.states.configure_salt_logs queue=True --master={hostname}')

                d.gauge_update(
                    70, 'Применение состояния (state) utils.passwords', update_text=True)
                run_command_without_output(
                    f'salt-call state.apply utils.passwords queue=True --master={hostname}')
                run_command_without_output(
                    'salt-call grains.delkey aldpro_machine_type')

                d.gauge_update(80, 'Конфигурация Salt Minion',
                               update_text=True)
                delete_minion_conf()

                # run_command_with_show_stdout('salt-call service.restart salt-master --local')
                d.gauge_update(
                    90, f'Перезапуск службы Salt Master на локальной системе.\nОжидаем {wait_interval} сек.', update_text=True)
                run_command_without_output(
                    'salt-call service.restart salt-master --local')
                time.sleep(wait_interval)

                # run_command_with_show_stdout('salt-call service.restart salt-minion --local')
                d.gauge_update(
                    95, f'Перезапуск службы Salt Minion на локальной системе.\nОжидаем {wait_interval} сек.', update_text=True)
                run_command_without_output(
                    'salt-call service.restart salt-minion --local')
                time.sleep(wait_interval)

                exit_code = d.gauge_stop()
                os.system('clear')  # Очистка экрана
                print(
                    'Выполнено. Для применения настроек необходимо выполнить перезагрузку вручную.')
                break

            # except subprocess.CalledProcessError as e:
            except Exception as e:
                os.system('clear')
                print(f"{e}")
                break

        elif action == "2 Присоединение":

            # Выводим форму и получаем введенные данные
            code, fields = d.mixedform(
                "Введите данные", form2, insecure=True, item_help=True)

            if code == d.CANCEL:
                continue

            hostname, domain, ip, admin_password = fields

            # Проверяем валидность имени хоста
            if not re.match(netbios_regex, hostname):
                d.msgbox(
                    "Некорректное имя хоста. Пожалуйста, введите валидное netbios имя хоста.")
                form2 = [
                    ("Имя хоста:", 1, 1, "", 1, 30,
                     20, 0, 0,  item_help2_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help2_domain),
                    ("Ip контроллера домена:", 3, 1, "",
                     3, 30, 20, 0, 0, item_help2_ip),
                    ("Пароль администратора:", 4, 1, admin_password,
                     4, 30, 20, 0, 1, item_help2_adminpassword),
                ]
                continue

            # Проверяем, что пароль не пустой
            if not admin_password:
                d.msgbox(
                    "Пароль администратора не может быть пустым. Пожалуйста, введите пароль.")
                form2 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help2_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help2_domain),
                    ("Ip контроллера домена:", 3, 1, "",
                     3, 30, 20, 0, 0, item_help2_ip),
                    ("Пароль администратора:", 4, 1, "", 4,
                     30, 20, 0, 1, item_help2_adminpassword),
                ]
                continue

            # Проверяем длину паролей
            if not re.match(password_regex, admin_password):
                d.msgbox(
                    "Длина пароля менее 8 символов. Пожалуйста, введите пароли длиннее 7 символов.")
                form2 = [
                    ("Имя хоста:", 1, 1, hostname, 1,
                     30, 20, 0, 0,  item_help2_hostname),
                    ("Имя домена:", 2, 1, domain, 2,
                     30, 20, 0, 0, item_help2_domain),
                    ("Ip контроллера домена:", 3, 1, "",
                     3, 30, 20, 0, 0, item_help2_ip),
                    ("Пароль администратора:", 4, 1, "", 4,
                     30, 20, 0, 1, item_help2_adminpassword),
                ]
                continue

            d.gauge_start()

            try:

                if not hostname.endswith(f".{domain}"):
                    d.gauge_update(
                        10, 'Конфигурация /etc/hostname', update_text=True)
                    run_command_without_output(
                        f'sudo hostnamectl set-hostname {hostname}.{domain}')
                else:
                    hostname = hostname.split('.')[0]

                # TODO stop cloud-init to reconfigure hostname

                # FIXME hardcoded hostname
                d.gauge_update(20, 'Конфигурация RabbitMQ', update_text=True)
                run_command_without_output(
                    'sudo rabbitmqctl -n rabbit@smolensk-base stop')
                run_command_without_output(
                    'sudo rm -rf /var/lib/rabbitmq/mnesia/')

                if not is_ip_in_hosts(ip_address):
                    d.gauge_update(
                        30, 'Конфигурация /etc/hosts', update_text=True)
                    set_hosts(hostname, ip_address, domain)

                d.gauge_update(
                    40, 'Конфигурация /etc/resolv.conf', update_text=True)
                run_command_without_output('sudo rm -f /etc/resolv.conf')
                set_resolv(ip, domain)
                run_command_without_output('sudo chattr +i /etc/resolv.conf')

                # Проверяем DNS имя домена
                if not is_valid_domain(domain):
                    d.msgbox(
                        f"Имя домена {domain} не может быть разрешено в DNS. Пожалуйста, введите доступное имя домена.")
                    run_command_without_output('sudo chattr -i /etc/resolv.conf')
                    os.system('clear')
                    break

                # Проверяем доступность (LDAP bind) домена
                if is_domain_available(domain):
                    d.msgbox(
                        "Домен не доступен по LDAP. Пожалуйста, введите доступный по LDAP домен.")
                    os.system('clear')
                    break

                d.gauge_update(50, 'Ввод хоста в домен', update_text=True)
                run_command_without_output(
                    f"sudo /opt/rbta/aldpro/client/bin/aldpro-client-installer --domain {domain} --account admin --password '{admin_password}' --host {hostname} --gui --force")

                exit_code = d.gauge_stop()
                os.system('clear')  # Очистка экрана
                print(
                    'Выполнено. Для применения настроек необходимо выполнить перезагрузку вручную.')
                break

            except Exception as e:
                os.system('clear')
                print(f"{e}")
                break

        elif action == "3 Установка":

            # Выводим форму и получаем введенные данные
            code, fields = d.mixedform(
                f"""
                Astra Linux Directory Pro. Версия 2.3.0
                Имя реплики: {current_hostname}
                IP-адрес (eth0) реплики: {ip_address}
                """,
                form3, insecure=True, item_help=True)

            if code == d.CANCEL:
                continue

            ip_dc, admin_password = fields

            d.gauge_start()

            try:

                d.gauge_update(
                    10, 'Аутентификация на первичном контроллере', update_text=True)

                cookies = api_login(ip_dc, 'admin', admin_password)
                if cookies == False:
                    d.msgbox(
                        f"Аутентификация не пройдена.")
                    #os.system('clear')
                    break



                exit_code = d.gauge_stop()
                #os.system('clear')  # Очистка экрана
                #print(
                #    'Выполнено. Для применения настроек необходимо выполнить перезагрузку вручную.')
                break

            except Exception as e:
                #os.system('clear')
                print(f"{e}")
                break

except KeyboardInterrupt:
    # Обработка прерывания по Ctrl+C
    os.system('clear')  # Очистка экрана
    print("\nПрограмма прервана пользователем.")
