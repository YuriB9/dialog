
1. Создание структуры каталогов:
   ```
   mkdir -p aldpro_yc_installer/DEBIAN
   mkdir -p aldpro_yc_installer/usr/local/bin
   ```

2. Копирование исходных файлов:
   ```
   cp pythondialog.py install_ald.py aldpro_yc_installer/usr/local/bin
   ```

3. Создание файла control:
   Создайте файл `aldpro_yc_installer/DEBIAN/control` со следующим содержимым:
   ```
   Package: aldpro-yc-installer
   Version: 1.2
   Section: utils
   Priority: optional
   Architecture: amd64
   Maintainer: Yuriy Batkov <ibatkov@astralinux.ru>
   Description: Installer for ALD Pro on Yandex Cloud
    This package provides an installer for ALD Pro
    specifically designed for deployment on Yandex Cloud.
    It includes necessary scripts and dependencies.
   Pre-Depends: coreutils, dialog, python3
   ```

4. Создание постинсталляционного скрипта:
   Создайте файл `aldpro_yc_installer/DEBIAN/postinst` со следующим содержимым:
   ```sh
   #!/bin/sh
   set -e
   chmod 755 /usr/local/bin/install_ald.py
   exit 0
   ```
   Сделайте скрипт исполняемым:
   ```
   chmod 755 aldpro_yc_installer/DEBIAN/postinst
   ```

5. Создание скрипта для генерации MD5-сумм:
   Создайте файл `generate_md5.sh` со следующим содержимым:
   ```sh
   #!/bin/bash
   cd aldpro_yc_installer/usr/local/bin/
   md5sum * > ~/aldpro_yc_installer/DEBIAN/md5sums
   cd -
   ```
   Сделайте скрипт исполняемым и запустите его:
   ```
   chmod +x generate_md5.sh
   ./generate_md5.sh
   ```

6. Создание прединсталляционного скрипта:
   Создайте файл `aldpro_yc_installer/DEBIAN/preinst` с содержимым, которое проверяет MD5-суммы файлов перед установкой. Скрипт выполняет следующие действия:
   - Проверять наличие файла md5sums
   - Читать MD5-суммы из файла
   - Проверять соответствие MD5-сумм для каждого файла
   - Прерывать установку при несоответствии MD5-сумм

   Сделайте скрипт исполняемым:
   ```
   chmod 755 aldpro_yc_installer/DEBIAN/preinst
   ```

7. Сборка deb-пакета:
   ```
   dpkg-deb --build aldpro_yc_installer
   ```

8. Переименование пакета:
   ```
   mv aldpro_yc_installer.deb aldpro_yc_installer_1.2_amd64.deb
   ```

9. Установка пакета:
   ```
   sudo dpkg -i aldpro_yc_installer_1.2_amd64.deb
   ```
   Результат:
   ```
    (Чтение базы данных … на данный момент установлено 58866 файлов и каталогов.)
    Подготовка к распаковке aldpro_yc_installer_1.2_amd64.deb …
    Содержимое файла md5sums:
    7d13f4ddf32f4cba843e744dc41c4558  install_ald.py
    627466e893910520543e3f091b791330  pythondialog.py
    Проверяем файл: /usr/local/bin/install_ald.py
    MD5 проверка прошла успешно для /usr/local/bin/install_ald.py
    Проверяем файл: /usr/local/bin/pythondialog.py
    MD5 проверка прошла успешно для /usr/local/bin/pythondialog.py
    Проверка MD5 прошла успешно.
    Распаковывается aldpro-yc-installer (1.2) …
    Настраивается пакет aldpro-yc-installer (1.2) …
   ```

10. Запуск установленного скрипта:
    ```
    sudo install_ald.py
    ```

11. Проверка информации о пакете:
    ```
    dpkg-deb --info aldpro_yc_installer_1.2_amd64.deb
    ```
    Результат:
    ```
        new Debian package, version 2.0.
    size 18364 bytes: control archive=1244 bytes.
        211 байт(а),     8 строк       control
        99 байт(а),      2 строк       md5sums
        58 байт(а),      6 строк    *  postinst
        1713 байт(а),    50 строк   *  preinst
    Package: aldpro-yc-installer
    Version: 1.2
    Section: utils
    Priority: optional
    Architecture: amd64
    Maintainer: Yuriy Batkov <ibatkov@astralinux.ru>
    Description: Installer for ALD Pro on Yandex Cloud
     This package provides an installer for ALD Pro
     specifically designed for deployment on Yandex Cloud.
     It includes necessary scripts and dependencies.
    Pre-Depends: coreutils, dialog, python3
    ```