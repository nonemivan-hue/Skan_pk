# Инструкция по созданию установочного файла

## Для Windows

### Вариант 1: Использование PyInstaller (рекомендуется)

#### Шаг 1: Установка PyInstaller
```cmd
pip install pyinstaller
```

#### Шаг 2: Создание исполняемого файла
Перейдите в каталог с программой и выполните:
```cmd
pyinstaller --onefile --windowed --name "PD_Security_Checker" --icon=icon.ico pd_security_checker.py
```

Параметры:
- `--onefile` - создать один исполняемый файл
- `--windowed` - запуск без консольного окна (для GUI приложений)
- `--name` - имя выходного файла
- `--icon` - иконка приложения (опционально, нужен файл icon.ico)

#### Шаг 3: Поиск готового файла
Готовый исполняемый файл будет находиться в папке `dist/PD_Security_Checker.exe`

#### Шаг 4: Создание установщика с Inno Setup (опционально)

1. Скачайте и установите [Inno Setup](https://jrsoftware.org/isdl.php)
2. Создайте файл скрипта `setup.iss`:

```iss
[Setup]
AppName=Проверка безопасности ПДн
AppVersion=1.0
DefaultDirName={pf}\PD_Security_Checker
DefaultGroupName=Проверка безопасности ПДн
OutputBaseFilename=PD_Security_Checker_Setup
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\PD_Security_Checker.exe"; DestDir: "{app}"
Source: "README.md"; DestDir: "{app}"; Flags: isreadme

[Icons]
Name: "{group}\Проверка безопасности ПДн"; Filename: "{app}\PD_Security_Checker.exe"
Name: "{commondesktop}\Проверка безопасности ПДн"; Filename: "{app}\PD_Security_Checker.exe"

[Run]
Filename: "{app}\PD_Security_Checker.exe"; Description: "Запустить программу"; Flags: nowait postinstall skipifsilent
```

3. Скомпилируйте установщик:
```cmd
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup.iss
```

Готовый установщик будет в файле `PD_Security_Checker_Setup.exe`

### Вариант 2: Использование cx_Freeze

#### Шаг 1: Установка cx_Freeze
```cmd
pip install cx_Freeze
```

#### Шаг 2: Создание setup.py
Создайте файл `setup.py`:

```python
from cx_Freeze import setup, Executable

build_exe_options = {
    "packages": ["PyQt5"],
    "include_files": ["README.md"]
}

setup(
    name="PD_Security_Checker",
    version="1.0",
    description="Программа проверки безопасности ПДн",
    options={"build_exe": build_exe_options},
    executables=[Executable("pd_security_checker.py", base="Win32GUI")]
)
```

#### Шаг 3: Сборка
```cmd
python setup.py build
```

---

## Для Linux

### Вариант 1: Создание исполняемого скрипта

#### Шаг 1: Добавление shebang
Убедитесь, что первая строка `pd_security_checker.py` содержит:
```python
#!/usr/bin/env python3
```

#### Шаг 2: Установка прав на выполнение
```bash
chmod +x pd_security_checker.py
```

#### Шаг 3: Копирование в системный каталог (опционально)
```bash
sudo cp pd_security_checker.py /usr/local/bin/pd-security-checker
```

Теперь программу можно запустить командой `pd-security-checker`

### Вариант 2: Создание .deb пакета (Debian/Ubuntu)

#### Шаг 1: Установка инструментов
```bash
sudo apt-get install dpkg-dev debhelper
```

#### Шаг 2: Создание структуры каталогов
```bash
mkdir -p pd-security-checker_{version}/DEBIAN
mkdir -p pd-security-checker_{version}/usr/share/pd-security-checker
mkdir -p pd-security-checker_{version}/usr/share/applications
mkdir -p pd-security-checker_{version}/usr/share/icons
```

#### Шаг 3: Создание файла управления
Создайте файл `pd-security-checker_{version}/DEBIAN/control`:

```
Package: pd-security-checker
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Depends: python3, python3-pyqt5
Maintainer: Ваше Имя <your@email.com>
Description: Программа проверки безопасности ПДн
 Проверка ПК на соответствие требованиям 152-ФЗ
```

#### Шаг 4: Копирование файлов
```bash
cp pd_security_checker.py pd-security-checker_{version}/usr/share/pd-security-checker/
cp README.md pd-security-checker_{version}/usr/share/pd-security-checker/
```

#### Шаг 5: Создание исполняемого скрипта
Создайте файл `pd-security-checker_{version}/usr/bin/pd-security-checker`:

```bash
#!/bin/bash
python3 /usr/share/pd-security-checker/pd_security_checker.py "$@"
```

Сделайте его исполняемым:
```bash
chmod +x pd-security-checker_{version}/usr/bin/pd-security-checker
```

#### Шаг 6: Создание .desktop файла
Создайте файл `pd-security-checker_{version}/usr/share/applications/pd-security-checker.desktop`:

```ini
[Desktop Entry]
Name=Проверка безопасности ПДн
Comment=Проверка ПК на соответствие 152-ФЗ
Exec=/usr/bin/pd-security-checker
Icon=security-high
Terminal=false
Type=Application
Categories=Utility;Security;
```

#### Шаг 7: Сборка пакета
```bash
dpkg-deb --build pd-security-checker_1.0
```

Будет создан файл `pd-security-checker_1.0_all.deb`

#### Шаг 8: Установка пакета
```bash
sudo dpkg -i pd-security-checker_1.0_all.deb
```

### Вариант 3: Создание .rpm пакета (CentOS/RHEL/Fedora)

#### Шаг 1: Установка инструментов
```bash
sudo yum install rpmdevtools rpmlint
```

#### Шаг 2: Подготовка структуры
```bash
rpmdev-setuptree
cd ~/rpmbuild
```

#### Шаг 3: Копирование исходников
```bash
cp pd_security_checker.py SOURCES/
cp README.md SOURCES/
```

#### Шаг 4: Создание spec файла
Создайте файл `SPECS/pd-security-checker.spec`:

```spec
Name:           pd-security-checker
Version:        1.0
Release:        1%{?dist}
Summary:        Программа проверки безопасности ПДн
License:        MIT
URL:            https://example.com/pd-security-checker
Source0:        %{name}.py
Source1:        README.md

BuildArch:      noarch
Requires:       python3 python3-qt5

%description
Программа для проверки ПК на соответствие требованиям 
российского законодательства в области защиты персональных данных.

%prep
%autosetup -n %{name}-%{version}

%install
mkdir -p %{buildroot}/usr/share/%{name}
mkdir -p %{buildroot}/usr/bin

install -m 755 %{SOURCE0} %{buildroot}/usr/share/%{name}/
install -m 644 %{SOURCE1} %{buildroot}/usr/share/%{name}/

cat > %{buildroot}/usr/bin/%{name} << EOF
#!/bin/bash
python3 /usr/share/%{name}/pd_security_checker.py "\$@"
EOF

chmod +x %{buildroot}/usr/bin/%{name}

%files
/usr/share/%{name}/*
/usr/bin/%{name}

%changelog
* Mon Jan 01 2024 Your Name <your@email.com> - 1.0-1
- Initial package
```

#### Шаг 5: Сборка RPM
```bash
rpmbuild -ba SPECS/pd-security-checker.spec
```

Готовый пакет будет в `RPMS/noarch/pd-security-checker-1.0-1.noarch.rpm`

#### Шаг 6: Установка пакета
```bash
sudo rpm -ivh ~/rpmbuild/RPMS/noarch/pd-security-checker-1.0-1.noarch.rpm
```

---

## Проверка работоспособности

После создания установочного файла обязательно проверьте:

1. **Запуск программы** - убедитесь, что приложение запускается без ошибок
2. **Графический интерфейс** - проверьте отображение всех элементов GUI
3. **Функциональность** - протестируйте выполнение проверки и сохранение отчетов
4. **Зависимости** - убедитесь, что все необходимые библиотеки включены или установлены

## Устранение проблем

### Проблема: Отсутствуют некоторые модули в исполняемом файле
**Решение**: Добавьте их явно через параметр `--hidden-import`:
```cmd
pyinstaller --hidden-import=модуль --onefile pd_security_checker.py
```

### Проблема: Большой размер исполняемого файла
**Решение**: Используйте UPX для сжатия:
```cmd
pyinstaller --upx-dir=/path/to/upx --onefile pd_security_checker.py
```

### Проблема: Ошибки при работе с PyQt5
**Решение**: Добавьте hook-файл или используйте `--collect-all`:
```cmd
pyinstaller --collect-all PyQt5 --onefile pd_security_checker.py
```

## Дополнительные рекомендации

1. Всегда тестируйте установщик на чистой системе
2. Включайте в дистрибутив файл README с инструкцией
3. Рассмотрите возможность добавления цифрового подписи для Windows
4. Для корпоративного распространения настройте групповые политики (GPO)
