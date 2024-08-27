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
    process = subprocess.Popen(args, stdout=devnull, stderr=subprocess.PIPE, encoding='utf8',
                               env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    output, error = process.communicate()
    devnull.close()

    if process.returncode != 0:
        raise Exception(
            f"Ошибка при выполнении команды: {error}")

def run_command_async(command):
    args = shlex.split(command)

    process = subprocess.Popen(args,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)


    try:
        process.poll()
        if process.returncode is None:
            return True
        else:
            error = process.stderr.read()
            raise Exception(f"Ошибка при запуске команды: {error}")
    except Exception as e:
        print(f"Ошибка: {e}")


def run_command_to_file(command, file):
    args = shlex.split(command)
    devnull = open(os.devnull, 'w')
    with open(file, "w") as out:
        process = subprocess.Popen(args, stdout=out, stderr=subprocess.PIPE)
    output, error = process.communicate()
    devnull.close()

    if process.returncode != 0:
        decoded_text = error.decode('utf-8')
        raise Exception(
            f"Ошибка при выполнении команды: {decoded_text}.")


def run_command_append_to_file(command, file):
    args = shlex.split(command)
    devnull = open(os.devnull, 'w')
    with open(file, "a") as out:
        process = subprocess.Popen(args, stdout=out, stderr=subprocess.PIPE)
    output, error = process.communicate()
    devnull.close()

    if process.returncode != 0:
        raise Exception(
            f"Ошибка при выполнении команды: {error}.")


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
        # resolver.query(domain, 'NS')
        resolver.resolve(domain, 'NS')

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


def create_minion_preinst(host, domain):
    data = f'master: {host}.{domain}'
    with open('/etc/salt/minion.d/preinst.conf', 'w') as file:
        file.write(data)


def create_minion_id(host, domain):
    data = f'{host}.{domain}'
    with open('/etc/salt/minion_id', 'w') as file:
        file.write(data)


def delete_minion_conf():
    os.remove('/etc/salt/minion.d/preinst.conf')


def api_login(fqdn, login, password):
    try:
        url = f"https://{fqdn}/ad/api/ds/login"
        payload = {"data": {"login": login, "password": password}}
        headers = {'accept': 'application/json',
                   'Content-Type': 'application/json'}
        response = requests.post(
            url, json=payload, headers=headers, verify=True)

        if response.json()["success"]:
            return response.cookies
        else:
            return False
    except Exception as e:
        raise e


def api_send_request(fqdn, path, data, cookies):
    url = f"https://{fqdn}/ad/api{path}"
    headers = {'accept': 'application/json',
               'Content-Type': 'application/json'}
    response = requests.post(
        url, json=data, headers=headers, cookies=cookies, verify=True)

    if response.json()["success"]:
        return True
    else:
        return False


def api_get_job_id(fqdn, cookies):
    query = "?filters={\"property\":\"automationtaskjoblistitem_job_status\",\"value\":\"STARTED\",\"operator\":\"eq\",\"join\":\"OR\"}&limit=1&sortby=-automationtaskjoblistitem_job_created_date"
    url = f"https://{fqdn}/ad/api/ds/automation-tasks/jobs{query}"
    response = requests.get(url, cookies=cookies, verify=True)
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

item_help3_fqdn = "Введите FQDN имя первого контроллера домена"
item_help3_adminpassword = "Введите пароль"

form3 = [
    ("FQDN контроллера домена:", 1, 1, "", 1, 30, 20, 0, 0, item_help3_fqdn),
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

state_percentages = {
    '[event/software_installed]': 10,
    '[/etc/salt/stack/passwords.yml]': 10,
    '[aldpro-mp]': 10,
    '[/opt/rbta/aldpro/mp/bin/aldpro-replica-configure.sh]': 10,
    '[/opt/rbta/aldpro/mp/bin/aldpro-server-install.sh]': 10,
    '[/opt/rbta/aldpro/mp/bin/aldpro-update-ms.sh]': 10,
    '[/etc/parsec/mswitch.conf]': 15,
    '[net.ipv4.tcp_timestamps]': 15,
    '[/etc/apache2/apache2.conf]': 15,
    '[/etc/apache2/conf-available/security.conf]': 15,
    '[security]': 15,
    '[/etc/apache2/site-available/000-default.conf]': 15,
    '[/etc/apache2/sites-available/000-default.conf]': 20,
    '[000-default]': 20,
    '[apache2]': 20,
    '[postgresql-11]': 20,
    '[setfacl': 20,
    '[/etc/postgresql/11/main/postgresql.conf]': 20,
    '[postgresql]': 25,
    '[postgresql@11-main]': 25,
    '[aldpro]': 25,
    '[aldpro_help_center]': 25,
    '[helpcenter]': 25,
    '[syncer]': 25,
    '[salt]': 30,
    '[rabbitmq-server]': 30,
    '[rabbitmqctl stop_app]': 30,
    '[rabbitmqctl reset]': 30,
    '[rabbitmqctl start_app]': 30,
    '[adcan]': 30,
    '[celery]': 35,
    '[core]': 35,
    '[ldap2psql]': 35,
    #'[dc01.ald.lan]': 35,
    #'[dirsrv-watcher]': 39,
    '[configure_astra_freeipa_server]': 35,
    '[/usr/sbin/ipa-server-upgrade]': 40,
    '[ipa_restart]': 40,
    '[add_class_rbta-unit]': 40,
    '[add_class_rbta-address]': 40,
    '[add_class_rbtaCustomUserAttrs]': 40,
    '[add_class_rbta-inetorgperson-ext]': 40,
    '[add_group_class]': 45,
    '[aldpro_update_file]': 45,
    '[/usr/sbin/ipa-ldap-updater': 45,
    '[aldpro_ipa_curl_site_add]': 45,
    '[aldpro_ipa_curl_server_mod]': 45,
    '[bind9-pkcs11]': 45,
    '[/usr/local/share/ca-certificates/ipa-ca]': 50,
    '[ntp_server_configure_external]': 50,
    '[ntp_server_configure_internal]': 50,
    '[create_cups_group]': 50,
    '[lpadmin_hack]': 50,
    '[/tmp/salt-binddn.update]': 50,
    '[/tmp/envuser-binddn.update]': 55,
    '[/tmp/orgunitsservice-binddn.update]': 55,
    '[/tmp/trustsservice-binddn.update]': 55,
    '[/tmp/role-binddn.update]': 55,
    '[/tmp/zabbix-binddn.update]': 55,
    #'[ipa-ldap-updater': 60,
    '[/etc/salt/master.d/ldap.conf]': 55,
    '[/etc/systemd/system/apache2.service.d/aldpro.conf]': 60,
    '[reload_daemon_after_grafana_config]': 60,
    '[apache2_restart_after_grafana_config]': 60,
    '[/etc/adcan/]': 60,
    '[/etc/adcan/adcan.env]': 60,
    '[/etc/aldpro/ldap2psql.env]': 60,
    '[migrate_rabbit_env]': 65,
    #'[/etc/postgresql/11/main/pg_hba.conf]': 70,
    '[postgres_restart_after_helpcenter]': 65,
    '[/etc/aldpro/core.env]': 65,
    '[/opt/rbta/ad/mgmtportal/api/core/.env]': 65,
    '[migrate_env_core]': 65,
    '[/etc/aldpro/services.env]': 65,
    '[/opt/rbta/aldpro/mp/api/services/.env]': 70,
    '[migrate_env_async]': 70,
    '[/etc/aldpro/help.env]': 70,
    '[/opt/rbta/aldpro/mp/api/help-center/.env]': 70,
    '[migrate_env_helpcenter]': 70,
    '[run_migration_core_migrate]': 70,
    '[run_migration_core_shell]': 75,
    '[run_migration_core_collectstatic]': 75,
    '[run_migration_services]': 75,
    '[run_migration_helpcenter_migrate]': 75,
    '[run_migration_helpcenter_flush]': 75,
    '[run_migration_helpcenter_loaddata]': 75,
    '[/tmp/aldpro/help-center]': 80,
    '[/opt/rbta/ad]': 80,
    #'[/var/log/aldpro/mp-core]': 83,
    '[/var/log/aldpro/mp-services]': 80,
    '[/etc/apache2/sites-enabled/default-ssl.conf]': 80,
    '[apache2_restart]': 80,
    '[/etc/aldpro/aldproctl.env]': 80,
    '[/opt/rbta/aldpro/mp/bin/aldproctl/aldproctl.env]': 84,
    '[/var/log/aldpro]': 85,
    #'[/var/log/rbta-ad]': 86,
    '[/etc/salt]': 87,
    '[/srv/salt]': 88,
    '[/etc/aldpro]': 89,
    '[restart_ipa]': 90,
    '[restart_celery]': 90,
    '[restart_celerybeat]': 90,
    '[restart_aldpro-mp-services]': 90,
    '[restart_dirsrv-watcher]': 90,
    '[restart_aldpro-canclient]': 90,
    '[restart_ad-salt-canrunner]': 100,
}

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

                d.gauge_update(
                    10, '1/2 : Конфигурация aldpro.list', update_text=True)
                run_command_to_file(
                    'echo "deb https://download.astralinux.ru/aldpro/frozen/01/2.3.0 1.7_x86-64 main base"', '/etc/apt/sources.list.d/aldpro.list')

                d.gauge_update(
                    15, '1/2 : Получение последней версии списка пакетов', update_text=True)
                run_command_without_output(
                    'apt update')

                d.gauge_update(
                    20, '1/2 : Скачивание и устанавка обновлений', update_text=True)
                run_command_without_output(
                    'apt dist-upgrade -y -o Dpkg::Options::=--force-confnew')

                d.gauge_update(
                    30, '1/2 : Конфигурация cloud-init', update_text=True)
                run_command_to_file(
                    'echo "network: {config: disabled}"', '/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg')
                run_command_to_file(
                    'echo "manage_etc_hosts: false"', '/etc/cloud/cloud.cfg.d/95_manage_etc_hosts.cfg')

                d.gauge_update(
                    40, '1/2 : Конфигурация сети', update_text=True)
                run_command_to_file(
                    f'echo "auto lo\r\niface lo inet loopback\r\n\r\nauto eth0\r\niface eth0 inet static\r\n    address {ip_address}/24\r\n    gateway 10.129.0.1"', '/etc/network/interfaces.d/50-cloud-init')

                if not hostname.endswith(f".{domain}"):
                    d.gauge_update(
                        50, '1/2 : Конфигурация /etc/hostname', update_text=True)
                    run_command_without_output(
                        f'hostnamectl set-hostname {hostname}.{domain}')
                else:
                    hostname = hostname.split('.')[0]

                if not is_ip_in_hosts(ip_address):
                    d.gauge_update(
                        60, '1/2 : Конфигурация /etc/hosts', update_text=True)
                    # set_hosts(hostname, ip_address, domain)
                    run_command_to_file(
                        'grep -v "^127" /etc/hosts', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "{ip_address} {hostname}.{domain} {hostname}"', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "51.250.6.116 dl.astralinux.ru"', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "51.250.6.116 download.astralinux.ru"', '/etc/hosts_temp')
                    run_command_without_output(
                        f'cp /etc/hosts_temp /etc/hosts')
                    run_command_without_output(
                        f'rm -f /etc/hosts_temp')

                d.gauge_update(
                    70, '1/2 : Установка пакетов mp, gc, syncer\nПриблизительное время выполнения - 10 мин', update_text=True)
                run_command_without_output(
                    'apt-get install -y -qq aldpro-mp aldpro-gc aldpro-syncer')

                d.gauge_update(
                    80, '1/2 : Конфигурация /etc/resolv.conf', update_text=True)
                run_command_without_output('rm -f /etc/resolv.conf')
                set_resolv(ip_address, domain)
                run_command_without_output('chattr +i /etc/resolv.conf')

                d.gauge_update(
                    90, '1/2 : Продвижение сервера до контроллера домена', update_text=True)
                #run_command_without_output(
                run_command_async(
                    f"/usr/sbin/aldpro-server-install -d {domain} -n {hostname} -p '{admin_password}' --ip {ip_address} --no-reboot --setup_syncer --setup_gc")

                d.gauge_update(
                    100, '1/2 : Продвижение сервера успешно запущено.', update_text=True)

                log_file = open('/var/log/salt/minion', 'r')
                log_file.seek(0, 2)  # Переместить курсор в конец файла
                progress = 0

                while progress < 100:
                    new_line = log_file.readline()
                    if not new_line:
                        time.sleep(1)  # Задержка для снижения нагрузки на ЦП
                        continue

                    for state, percent in state_percentages.items():
                        if state in new_line:
                            progress = max(progress, percent)
                            d.gauge_update(
                                progress, f'2/2 : Запущен стейт\n{state}', update_text=True)
                            if progress == 100:
                                break

                exit_code = d.gauge_stop()

                os.system('clear')  # Очистка экрана
                print(
                    'Выполнено. Для применения настроек необходимо выполнить перезагрузку вручную.')
                break

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

                d.gauge_update(
                    10, 'Конфигурация aldpro.list', update_text=True)
                run_command_to_file(
                    'echo "deb https://download.astralinux.ru/aldpro/frozen/01/2.3.0 1.7_x86-64 main base"', '/etc/apt/sources.list.d/aldpro.list')

                d.gauge_update(
                    15, 'Получение последней версии списка пакетов', update_text=True)
                run_command_without_output(
                    'apt update')

                d.gauge_update(
                    20, 'Скачивание и устанавка обновлений', update_text=True)
                run_command_without_output(
                    'apt dist-upgrade -y -o Dpkg::Options::=--force-confnew')

                d.gauge_update(
                    25, 'Установка пакета aldpro-client', update_text=True)
                run_command_without_output(
                    'apt-get install -y -q aldpro-client')

                d.gauge_update(
                    30, 'Конфигурация cloud-init', update_text=True)
                run_command_to_file(
                    'echo "network: {config: disabled}"', '/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg')
                run_command_to_file(
                    'echo "manage_etc_hosts: false"', '/etc/cloud/cloud.cfg.d/95_manage_etc_hosts.cfg')

                d.gauge_update(
                    35, 'Конфигурация сети', update_text=True)
                run_command_to_file(
                    f'echo "auto lo\r\niface lo inet loopback\r\n\r\nauto eth0\r\niface eth0 inet static\r\n    address {ip_address}/24\r\n    gateway 10.129.0.1"', '/etc/network/interfaces.d/50-cloud-init')

                if not hostname.endswith(f".{domain}"):
                    d.gauge_update(
                        40, 'Конфигурация /etc/hostname', update_text=True)
                    run_command_without_output(
                        f'hostnamectl set-hostname {hostname}.{domain}')
                else:
                    hostname = hostname.split('.')[0]

                if not is_ip_in_hosts(ip_address):
                    d.gauge_update(
                        45, 'Конфигурация /etc/hosts', update_text=True)
                    # set_hosts(hostname, ip_address, domain)
                    run_command_to_file(
                        'grep -v "^127" /etc/hosts', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "{ip_address} {hostname}.{domain} {hostname}"', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "51.250.6.116 dl.astralinux.ru"', '/etc/hosts_temp')
                    run_command_append_to_file(
                        f'echo "51.250.6.116 download.astralinux.ru"', '/etc/hosts_temp')

                    run_command_without_output(
                        f'cp /etc/hosts_temp /etc/hosts')
                    run_command_without_output(
                        f'rm -f /etc/hosts_temp')

                d.gauge_update(
                    50, 'Конфигурация /etc/resolv.conf', update_text=True)
                run_command_without_output('rm -f /etc/resolv.conf')
                set_resolv(ip, domain)
                run_command_without_output('chattr +i /etc/resolv.conf')

                # Проверяем DNS имя домена
                if not is_valid_domain(domain):
                    d.msgbox(
                        f"Имя домена {domain} не может быть разрешено в DNS. Пожалуйста, введите доступное имя домена.")
                    run_command_without_output(
                        'chattr -i /etc/resolv.conf')
                    os.system('clear')
                    break

                # Проверяем доступность (LDAP bind) домена
                if is_domain_available(domain):
                    d.msgbox(
                        "Домен не доступен по LDAP. Пожалуйста, введите доступный по LDAP домен.")
                    run_command_without_output(
                        'chattr -i /etc/resolv.conf')
                    os.system('clear')
                    break

                d.gauge_update(60, 'Ввод хоста в домен', update_text=True)
                run_command_without_output(
                    f"/opt/rbta/aldpro/client/bin/aldpro-client-installer --domain {domain} --account admin --password '{admin_password}' --host {hostname} --gui --force")

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

            dc_name, admin_password = fields

            d.gauge_start()

            try:

                d.gauge_update(
                    10, 'Аутентификация на первичном контроллере', update_text=True)

                cookies = api_login(dc_name, 'admin', admin_password)
                if cookies == False:
                    d.msgbox(
                        f"Аутентификация не пройдена.")
                    # os.system('clear')
                    break

                d.gauge_update(
                    20, 'Запуск задания автоматизации', update_text=True)

                req_path = "/ds/domain-controllers"
                req_data = {
                    "data": {
                        "domaincontroller_ip_address": ip_address,
                        "domaincontroller_ipa_login": "admin",
                        "domaincontroller_ipa_password": admin_password,
                        "domaincontroller_name": current_hostname,
                        "domaincontroller_roles": [],
                        "domaincontroller_site_name": "Головной офис"
                    }
                }

                request_result = api_send_request(
                    dc_name, req_path, req_data, cookies)

                if request_result == False:
                    d.msgbox(
                        f"Задание не запущено.")
                    # os.system('clear')
                    break

                d.gauge_update(
                    30, 'Проверка задания автоматизации', update_text=True)

                job_id = api_get_job_id(dc_name, cookies)

                if job_id == False:
                    d.msgbox(
                        f"Id задания не найдено.")
                    # os.system('clear')
                    break

                d.gauge_update(
                    100, 'Задание автоматизации успешно запущено', update_text=True)

                exit_code = d.gauge_stop()
                os.system('clear')  # Очистка экрана
                print(
                    'Выполнено. Для применения настроек необходимо выполнить перезагрузку вручную.')
                break

            except Exception as e:
                os.system('clear')
                print(f"{e}")
                break

except KeyboardInterrupt:
    # Обработка прерывания по Ctrl+C
    os.system('clear')  # Очистка экрана
    print("\nПрограмма прервана пользователем.")
