# Программа проверки ПК на уязвимости согласно 152-ФЗ

## Описание программы

Программа предназначена для автоматизированной проверки рабочих мест (ПК) на соответствие требованиям российского законодательства в области защиты персональных данных (152-ФЗ, приказы ФСТЭК России №21 и №17).

### Основные возможности

1. **Комплексная проверка безопасности** по 8 ключевым направлениям:
   - Проверка обновлений операционной системы
   - Наличие и актуальность антивирусной защиты
   - Настройки брандмауэра
   - Политика паролей
   - Управление учетными записями
   - Журналирование событий безопасности
   - Шифрование данных
   - Сетевые ресурсы и доступы

2. **Формирование отчетных документов**:
   - Официальное заключение по форме законодательства
   - Детальный отчет с рекомендациями по устранению нарушений
   - План мероприятий по приведению в соответствие

3. **Графический интерфейс пользователя**:
   - Интуитивно понятный дизайн
   - Визуализация результатов проверки
   - Возможность сохранения отчетов в файлы

4. **Поддержка ввода данных организации**:
   - Наименование организации
   - Состав комиссии (председатель и члены)
   - Номер и дата приказа о создании комиссии
   - Ответственный сотрудник

### Требования к системе

#### Для Windows:
- Windows 10/11 или Windows Server 2016+
- Python 3.8 или выше
- PyQt5 (`pip install PyQt5`)

#### Для Linux:
- Python 3.8 или выше
- PyQt5 (`sudo apt-get install python3-pyqt5` или `pip install PyQt5`)
- X11 или Wayland для графического интерфейса

## Установка и запуск

### Быстрый старт

1. **Клонирование репозитория**:
```bash
git clone <url-репозитория>
cd <каталог-проекта>
```

2. **Установка зависимостей**:

**Windows:**
```cmd
pip install PyQt5
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install python3-pyqt5
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install python3-qt5
```

3. **Запуск программы**:

**Windows:**
```cmd
python pd_security_checker.py
```

**Linux:**
```bash
python3 pd_security_checker.py
# или
./run_pd_checker.sh
```

### Консольный режим

При отсутствии графической среды программа автоматически запускается в консольном режиме.

## Структура отчетов

### 1. Заключение о проверке

Содержит:
- Наименование организации
- Данные о ПК (имя компьютера, ОС, пользователь)
- Дата и время проверки
- Состав комиссии
- Результаты проверки по каждому пункту
- Общая оценка соответствия
- Подписи членов комиссии

### 2. Отчет о рекомендуемых действиях

Содержит:
- Выявленные нарушения сгруппированные по степени критичности
- Рекомендации по устранению каждого нарушения
- Сроки устранения
- Ответственные сотрудники
- План мероприятий в табличной форме

## Нормативная база

Программа проверяет соответствие следующим нормативным документам:

1. Федеральный закон от 27.07.2006 № 152-ФЗ "О персональных данных"
2. Приказ ФСТЭК России от 18.02.2013 № 21 "Об утверждении Состава и содержания организационных и технических мер..."
3. Приказ ФСТЭК России от 11.02.2013 № 17 "Об утверждении Требований о защите информации..."
4. Постановление Правительства РФ от 01.11.2012 № 1119 "Об утверждении требований к защите персональных данных..."

## Примечания

1. Программа выполняет проверку на уровне доступного пользователю системных настроек
2. Для полноценной проверки могут потребоваться права администратора
3. Результаты проверки носят рекомендательный характер
4. Окончательное решение о соответствии принимает аттестационная комиссия организации
5. **Важно для Windows**: Убедитесь, что кодировка консоли установлена в UTF-8. Перед запуском выполните:
   ```cmd
   chcp 65001
   python pd_security_checker.py
   ```
   Или установите переменную окружения:
   ```cmd
   set PYTHONIOENCODING=utf-8
   python pd_security_checker.py
   ```

## Полные инструкции по устранению нарушений

### Для Windows

#### 1. Обновления ОС (Приказ ФСТЭК №21, п. 15)

**Проверка:**
```cmd
wmic qfe list brief /format:table
```

**Устранение нарушений:**
1. Откройте «Параметры» → «Обновление и безопасность» → «Центр обновления Windows»
2. Нажмите «Проверить наличие обновлений»
3. Установите все доступные обновления безопасности
4. Перезагрузите компьютер
5. Для корпоративной среды используйте WSUS или Microsoft Endpoint Configuration Manager

**Автоматическая установка через PowerShell (от имени администратора):**
```powershell
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot
```

#### 2. Антивирусная защита (Приказ ФСТЭК №21, п. 16)

**Требуется:** Сертифицированное ФСТЭК антивирусное ПО (Kaspersky, Dr.Web)

**Проверка наличия:**
```cmd
sc query | findstr /i "kavsvc drwebd spidernt"
```

**Устранение нарушений:**
1. Установите сертифицированное антивирусное ПО:
   - Kaspersky Endpoint Security для России
   - Dr.Web Enterprise Security Suite
2. Настройте автоматическое обновление антивирусных баз
3. Включите защиту в реальном времени
4. Настройте исключения для специализированного ПО

**Минимальные требования:**
- Проверка файлов при доступе
- Обновление баз не реже 1 раза в сутки
- Ведение журнала событий

#### 3. Межсетевой экран (Приказ ФСТЭК №21, п. 17)

**Проверка:**
```cmd
netsh advfirewall show allprofiles state
```

**Устранение нарушений:**
1. Включите брандмауэр Windows:
   ```cmd
   netsh advfirewall set allprofiles state on
   ```
2. Настройте правила для доменного, частного и общественного профилей
3. Заблокируйте входящие подключения по умолчанию
4. Разрешите только необходимые службы и приложения

**Настройка через PowerShell:**
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
```

#### 4. Политика паролей (Приказ ФСТЭК №21, п. 19)

**Проверка:**
```cmd
net accounts
```

**Требования:**
- Минимальная длина пароля: 8 символов
- Сложность: буквы (заглавные/строчные), цифры, спецсимволы
- Максимальный возраст пароля: 90 дней
- Минимальный возраст пароля: 1 день
- Хранение истории: 5 последних паролей

**Настройка через локальную политику безопасности:**
1. Выполните `secpol.msc`
2. Перейдите: Политики учетных записей → Политика паролей
3. Настройте параметры согласно требованиям

**Настройка через групповую политику:**
```cmd
gpedit.msc
# Конфигурация компьютера → Конфигурация Windows → Параметры безопасности
# → Политики учетных записей → Политика паролей
```

**Команды для настройки (от имени администратора):**
```cmd
net accounts /minpwlen:8 /maxpwage:90 /minpwage:1 /uniquepw:5 /reqpwcomplexity:yes
```

#### 5. Учетные записи пользователей (Приказ ФСТЭК №21, п. 18)

**Проверка:**
```cmd
net user
net localgroup administrators
```

**Устранение нарушений:**
1. Отключите учетную запись Guest:
   ```cmd
   net user guest /active:no
   ```
2. Удалите неиспользуемые учетные записи
3. Проверьте членов группы администраторов
4. Настройте блокировку после 5 неудачных попыток входа:
   ```cmd
   net accounts /lockoutthreshold:5 /lockoutduration:30
   ```
5. Переименуйте учетную запись Administrator

#### 6. Журналирование событий (Приказ ФСТЭК №21, п. 20)

**Проверка:**
```cmd
wevtutil el | findstr Security
wevtutil qe Security /c:1 /rd:true /f:text
```

**Требования:**
- Включить журнал безопасности
- Аудит успешных и неуспешных попыток входа
- Аудит доступа к объектам
- Срок хранения: не менее 6 месяцев

**Настройка аудита:**
1. Выполните `secpol.msc`
2. Перейдите: Локальные политики → Политика аудита
3. Включите:
   - Аудит событий входа в систему (успех/неудача)
   - Аудит управления учетными записями
   - Аудит доступа к объектам

**Команды для настройки:**
```cmd
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
```

**Настройка размера журнала:**
```cmd
wevtutil sl Security /ms:1073741824 /r:true
```

#### 7. Шифрование данных (Приказ ФСТЭК №21, п. 22)

**Проверка BitLocker:**
```cmd
manage-bde -status
```

**Устранение нарушений:**
1. Включите BitLocker для системного диска:
   ```cmd
   manage-bde -on C: -recoverypassword -skiphardwaretest
   ```
2. Сохраните ключ восстановления в Active Directory или распечатайте
3. Для съемных носителей:
   ```cmd
   manage-bde -on E: -used
   ```

**Альтернативы для редакций без BitLocker:**
- VeraCrypt (с сертифицированными настройками)
- КриптоПро ФС

#### 8. Сетевые ресурсы (Приказ ФСТЭК №21, п. 23)

**Проверка общих папок:**
```cmd
net share
```

**Устранение нарушений:**
1. Удалите ненужные общие ресурсы:
   ```cmd
   net share <имя_ресурса> /delete
   ```
2. Ограничьте доступ к необходимым ресурсам:
   ```cmd
   net share <имя> /grant:<пользователь>,read
   ```
3. Отключите скрытые административные共享 (при необходимости):
   Создайте в реестре: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks = 0`

---

### Для Linux

#### 1. Обновления ОС (Приказ ФСТЭК №21, п. 15)

**Проверка (Debian/Ubuntu):**
```bash
apt list --upgradable
apt update
```

**Проверка (CentOS/RHEL):**
```bash
yum check-update
# или
dnf check-update
```

**Устранение нарушений:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y

# CentOS/RHEL
sudo yum update -y
# или
sudo dnf upgrade -y
```

**Автоматизация обновлений безопасности:**
```bash
# Установка unattended-upgrades (Debian/Ubuntu)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# Настройка cron для регулярных обновлений
sudo crontab -e
# Добавьте: 0 3 * * 0 /usr/bin/apt-get update && /usr/bin/apt-get upgrade -y
```

#### 2. Антивирусная защита (Приказ ФСТЭК №21, п. 16)

**Требуется:** Сертифицированное антивирусное ПО для Linux

**Проверка Kaspersky Endpoint Security:**
```bash
systemctl status kesl
kesl-control --get-status
```

**Проверка Dr.Web:**
```bash
systemctl status drweb-daemon
drweb-ctl status
```

**Установка Kaspersky Endpoint Security:**
```bash
# Скачайте пакет с официального сайта
wget https://packages.kaspersky.com/kesl/.../kesl_<version>_amd64.deb
sudo dpkg -i kesl_*.deb
sudo kesl-setup --install

# Активация и настройка
sudo kesl-control --set-config AutoUpdate=On
sudo kesl-control --start
```

**Установка Dr.Web:**
```bash
wget https://repo.drweb.com/.../drweb-*.deb
sudo dpkg -i drweb-*.deb
sudo systemctl enable drweb-daemon
sudo systemctl start drweb-daemon
```

#### 3. Межсетевой экран (Приказ ФСТЭК №21, п. 17)

**Проверка UFW:**
```bash
sudo ufw status verbose
```

**Проверка firewalld:**
```bash
sudo firewall-cmd --state
sudo firewall-cmd --list-all
```

**Настройка UFW:**
```bash
# Включение
sudo ufw enable

# Политика по умолчанию
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Разрешение необходимых портов
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 80/tcp    # HTTP

# Проверка правил
sudo ufw status numbered
```

**Настройка firewalld:**
```bash
sudo systemctl enable firewalld
sudo systemctl start firewalld

# Добавление служб
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

**Настройка iptables (альтернатива):**
```bash
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

#### 4. Политика паролей (Приказ ФСТЭК №21, п. 19)

**Проверка текущих настроек:**
```bash
cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN"
cat /etc/pam.d/common-password
```

**Требования:**
- Минимальная длина: 8 символов
- Сложность: буквы, цифры, спецсимволы
- Максимальный возраст: 90 дней

**Настройка (/etc/login.defs):**
```bash
sudo nano /etc/login.defs
```
Измените параметры:
```
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    8
PASS_WARN_AGE   7
```

**Настройка сложности паролей (PAM):**
```bash
# Для Debian/Ubuntu
sudo nano /etc/pam.d/common-password
# Добавьте или измените строку:
password requisite pam_pwquality.so retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# Для CentOS/RHEL
sudo nano /etc/pam.d/system-auth
# Добавьте:
password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
```

**Принудительная смена паролей:**
```bash
# Для всех пользователей
sudo chage -M 90 -m 1 -W 7 username
```

#### 5. Учетные записи пользователей (Приказ ФСТЭК №21, п. 18)

**Проверка:**
```bash
cat /etc/passwd
cat /etc/shadow
grep wheel /etc/group  # или group admin
lastlog
```

**Устранение нарушений:**
1. Блокировка неиспользуемых учетных записей:
   ```bash
   sudo usermod -L username
   sudo passwd -l username
   ```

2. Удаление ненужных учетных записей:
   ```bash
   sudo userdel -r username
   ```

3. Проверка пользователей с UID 0 (кроме root):
   ```bash
   awk -F: '($3 == 0) {print}' /etc/passwd
   ```

4. Настройка блокировки при неудачных попытках (pam_tally2 или pam_faillock):
   ```bash
   # Для CentOS/RHEL 8+
   sudo authselect select sssd with-faillock
   sudo authselect enable-feature with-faillock
   
   # Настройка /etc/security/faillock.conf
   deny = 5
   unlock_time = 1800
   ```

5. Отключение root login по SSH:
   ```bash
   sudo nano /etc/ssh/sshd_config
   # PermitRootLogin no
   sudo systemctl restart sshd
   ```

#### 6. Журналирование событий (Приказ ФСТЭК №21, п. 20)

**Проверка журналов:**
```bash
ls -la /var/log/
cat /var/log/auth.log      # Debian/Ubuntu
cat /var/log/secure        # CentOS/RHEL
journalctl -xb             # systemd journal
```

**Настройка auditd:**
```bash
# Установка
sudo apt install auditd audispd-plugins    # Debian/Ubuntu
sudo yum install audit audit-libs          # CentOS/RHEL

# Включение службы
sudo systemctl enable auditd
sudo systemctl start auditd

# Настройка правил аудита
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -w /etc/sudoers -p wa -k sudoers
sudo auditctl -w /var/log/ -p wa -k logfiles

# Постоянное сохранение правил
sudo nano /etc/audit/rules.d/audit.rules
```

**Настройка rsyslog:**
```bash
sudo nano /etc/rsyslog.conf
# Настройка удаленной отправки логов (опционально)
*.* @logserver:514

sudo systemctl restart rsyslog
```

**Хранение журналов (минимум 6 месяцев):**
```bash
# Настройка logrotate
sudo nano /etc/logrotate.d/rsyslog
# weekly
# rotate 26
# compress
```

#### 7. Шифрование данных (Приказ ФСТЭК №21, п. 22)

**Проверка LUKS:**
```bash
sudo cryptsetup status /dev/sdX
lsblk -f
```

**Настройка шифрования диска:**

**Для нового диска:**
```bash
# Установка утилит
sudo apt install cryptsetup    # Debian/Ubuntu
sudo yum install cryptsetup    # CentOS/RHEL

# Инициализация LUKS
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX encrypted_disk
sudo mkfs.ext4 /dev/mapper/encrypted_disk

# Монтирование
sudo mkdir /mnt/secure
sudo mount /dev/mapper/encrypted_disk /mnt/secure

# Настройка автоматического монтирования
sudo nano /etc/crypttab
sudo nano /etc/fstab
```

**Шифрование домашнего каталога:**
```bash
# Для новых пользователей
sudo pam-auth-update  # Выберите encryption

# Существующим пользователям (резервное копирование обязательно!)
sudo apt install ecryptfs-utils
ecryptfs-migrate-home -u username
```

#### 8. Сетевые ресурсы (Приказ ФСТЭК №21, п. 23)

**Проверка NFS:**
```bash
showmount -e localhost
cat /etc/exports
```

**Проверка Samba:**
```bash
testparm -s
net share
```

**Устранение нарушений:**

**Настройка NFS:**
```bash
# Редактирование экспортов
sudo nano /etc/exports
# Пример безопасной настройки:
# /data 192.168.1.0/24(ro,sync,no_subtree_check,no_root_squash)

# Применение изменений
sudo exportfs -ra
sudo systemctl restart nfs-kernel-server

# Проверка
showmount -e
```

**Настройка Samba:**
```bash
sudo nano /etc/samba/smb.conf
# [secure_share]
# path = /srv/samba/secure
# valid users = @securegroup
# read only = yes
# create mask = 0640

sudo systemctl restart smbd
```

**Ограничение доступа:**
```bash
# Проверка открытых портов
sudo ss -tlnp
sudo netstat -tlnp

# Настройка доступа через firewall
sudo ufw deny from any to any port 139,445
sudo ufw allow from 192.168.1.0/24 to any port 22
```

---

## Контрольный список после устранения нарушений

### Для Windows:
- [ ] Все обновления безопасности установлены
- [ ] Антивирус активен и базы обновляются
- [ ] Брандмауэр включен во всех профилях
- [ ] Политика паролей соответствует требованиям
- [ ] Учетная запись Guest отключена
- [ ] Журнал безопасности включен
- [ ] BitLocker активирован (для мобильных устройств)
- [ ] Сетевые ресурсы минимизированы

### Для Linux:
- [ ] Пакеты обновлены (`apt/yum update`)
- [ ] Антивирус установлен и запущен
- [ ] Firewall настроен и активен
- [ ] PAM настроен для сложных паролей
- [ ] Неиспользуемые учетные записи заблокированы
- [ ] auditd настроен и работает
- [ ] Критичные данные зашифрованы (LUKS)
- [ ] NFS/Samba доступы ограничены

## Лицензия

Программа распространяется свободно. При использовании необходимо ссылаться на источник.

## Контакты и поддержка

По вопросам работы программы обращайтесь к разработчику.
