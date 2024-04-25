#!/bin/bash

# Получаем введенные параметры
domain_name=$1
admin_password=$2
ip_address=$3
hostname=$4

# Путь к файлу для сохранения данных
data_file="domain_data.txt"

# Записываем данные в файл
echo "Имя домена: $domain_name" > "$data_file"
echo "Пароль администратора: $admin_password" >> "$data_file"
echo "IP адрес: $ip_address" >> "$data_file"
echo "Имя хоста: $hostname" >> "$data_file"

echo "sudo aldpro-server-install -d $domain_name -n $hostname -p '$admin_password' --ip $ip_address --no-reboot"

echo "Данные успешно сохранены в файле $data_file"
