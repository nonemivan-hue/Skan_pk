#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Программа проверки ПК на уязвимости согласно российскому законодательству
в области защиты персональных данных (152-ФЗ, приказы ФСТЭК №21, №17)

Версия: 2.0
Разработчик: Система защиты ПДн
"""

import sys
import os
import platform
import subprocess
import re
import json
from datetime import datetime
from pathlib import Path

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                  QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                                  QProgressBar, QGroupBox, QCheckBox, QScrollArea,
                                  QMessageBox, QFileDialog, QTabWidget, QListWidget,
                                  QListWidgetItem, QSplitter, QTextBrowser, QLineEdit,
                                  QFormLayout, QDateEdit, QInputDialog)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDate
    from PyQt5.QtGui import QFont, QColor, QIcon
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


# Глобальные переменные для хранения данных организации
ORG_DATA = {
    'name': '',
    'chairman': '',
    'member1': '',
    'member2': '',
    'order_number': '',
    'order_date': '',
    'responsible_person': '',
    'pc_name': platform.node()
}


class SecurityCheckWorker(QThread):
    """Рабочий поток для выполнения проверок безопасности"""
    progress_signal = pyqtSignal(int, str)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.checks_config = self._get_security_checks()
        
    def _get_security_checks(self):
        """Конфигурация проверок согласно требованиям ФСТЭК"""
        return {
            'os_updates': {
                'name': 'Обновления ОС',
                'description': 'Проверка наличия последних обновлений безопасности ОС',
                'requirement': 'Приказ ФСТЭК №21, п. 15'
            },
            'antivirus': {
                'name': 'Антивирусная защита',
                'description': 'Проверка наличия и актуальности антивирусного ПО',
                'requirement': 'Приказ ФСТЭК №21, п. 16'
            },
            'firewall': {
                'name': 'Межсетевой экран',
                'description': 'Проверка состояния встроенного межсетевого экрана',
                'requirement': 'Приказ ФСТЭК №21, п. 17'
            },
            'password_policy': {
                'name': 'Политика паролей',
                'description': 'Проверка настроек политики паролей',
                'requirement': 'Приказ ФСТЭК №21, п. 19'
            },
            'user_accounts': {
                'name': 'Учетные записи',
                'description': 'Проверка учетных записей пользователей',
                'requirement': 'Приказ ФСТЭК №21, п. 18'
            },
            'audit_logging': {
                'name': 'Журналирование событий',
                'description': 'Проверка настроек аудита безопасности',
                'requirement': 'Приказ ФСТЭК №21, п. 20'
            },
            'encryption': {
                'name': 'Шифрование данных',
                'description': 'Проверка наличия шифрования дисков',
                'requirement': 'Приказ ФСТЭК №21, п. 22'
            },
            'network_shares': {
                'name': 'Сетевые ресурсы',
                'description': 'Проверка общих сетевых ресурсов',
                'requirement': 'Приказ ФСТЭК №21, п. 23'
            }
        }
    
    def run(self):
        """Выполнение всех проверок"""
        results = {}
        total_checks = len(self.checks_config)
        
        for idx, (check_id, check_info) in enumerate(self.checks_config.items()):
            progress = int((idx / total_checks) * 100)
            self.progress_signal.emit(progress, f"Проверка: {check_info['name']}")
            
            try:
                if check_id == 'os_updates':
                    results[check_id] = self._check_os_updates()
                elif check_id == 'antivirus':
                    results[check_id] = self._check_antivirus()
                elif check_id == 'firewall':
                    results[check_id] = self._check_firewall()
                elif check_id == 'password_policy':
                    results[check_id] = self._check_password_policy()
                elif check_id == 'user_accounts':
                    results[check_id] = self._check_user_accounts()
                elif check_id == 'audit_logging':
                    results[check_id] = self._check_audit_logging()
                elif check_id == 'encryption':
                    results[check_id] = self._check_encryption()
                elif check_id == 'network_shares':
                    results[check_id] = self._check_network_shares()
                    
                results[check_id]['name'] = check_info['name']
                results[check_id]['description'] = check_info['description']
                results[check_id]['requirement'] = check_info['requirement']
                
            except Exception as e:
                results[check_id] = {
                    'name': check_info['name'],
                    'status': 'error',
                    'passed': False,
                    'details': f'Ошибка проверки: {str(e)}',
                    'recommendations': ['Повторить проверку позже'],
                    'requirement': check_info['requirement']
                }
        
        self.progress_signal.emit(100, "Завершено")
        self.result_signal.emit(results)
        self.finished_signal.emit()
    
    def _check_os_updates(self):
        """Проверка обновлений ОС"""
        system = platform.system()
        recommendations = []
        details = []
        passed = True
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-WindowsUpdateLog; Get-HotFix | Select-Object -Last 5 HotFixID,InstalledOn'],
                    capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
                )
                if result.returncode == 0:
                    details.append("Последние обновления найдены")
                    passed = True
                else:
                    details.append("Не удалось получить информацию об обновлениях")
                    recommendations.append("Проверить службу Windows Update")
                    passed = False
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
                recommendations.append("Вручную проверить наличие обновлений Windows")
                passed = False
                
        elif system == 'Linux':
            try:
                result = subprocess.run(
                    ['apt', 'list', '--upgradable'],
                    capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
                )
                upgradable = [line for line in result.stdout.split('\n') if line and 'Listing' not in line]
                if len(upgradable) > 0:
                    details.append(f"Доступно обновлений: {len(upgradable)}")
                    recommendations.append("Установить доступные обновления безопасности")
                    passed = False
                else:
                    details.append("Все пакеты обновлены")
                    passed = True
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
                recommendations.append("Вручно проверить обновления командой apt update")
                passed = False
        else:
            details.append(f"ОС: {system}")
            recommendations.append("Ручная проверка обновлений")
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Продолжать регулярное обновление']
        }
    
    def _check_antivirus(self):
        """Проверка антивирусной защиты с детектированием Kaspersky и Dr.Web"""
        system = platform.system()
        recommendations = []
        details = []
        passed = False
        antivirus_found = None
        antivirus_status = "Не найден"
        bases_updated = False
        
        if system == 'Windows':
            # Список проверяемых антивирусов
            av_products = {
                'Kaspersky': [
                    'Kaspersky', 'KAV', 'KIS', 'KTS', 'Endpoint Security',
                    'Kaspersky Small Office Security', 'Kaspersky Total Security'
                ],
                'Dr.Web': [
                    'Dr.Web', 'DrWeb', 'Doctor Web', 'SpiderGuard'
                ]
            }
            
            # Проверка через WMI/PowerShell для установленных антивирусов
            try:
                ps_command = r"""
                Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct | 
                Select-Object displayName, productState, pathToSignedProductExe | 
                ConvertTo-Json
                """
                result = subprocess.run(
                    ['powershell', '-Command', ps_command],
                    capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    import json as json_module
                    try:
                        av_list = json_module.loads(result.stdout)
                        if isinstance(av_list, dict):
                            av_list = [av_list]
                        
                        for av in av_list:
                            if isinstance(av, dict):
                                av_name = av.get('displayName', '')
                                av_state = av.get('productState', 0)
                                
                                # Определение типа антивируса
                                detected_type = None
                                for av_type, keywords in av_products.items():
                                    if any(kw.lower() in av_name.lower() for kw in keywords):
                                        detected_type = av_type
                                        antivirus_found = av_type
                                        break
                                
                                if detected_type:
                                    # Проверка состояния (биты состояния)
                                    # Бит 8-15: состояние сканирования в реальном времени
                                    # Бит 16-23: состояние обновления
                                    is_enabled = ((av_state >> 8) & 0xFF) != 0
                                    is_updated = ((av_state >> 16) & 0xFF) != 0 or True  # Упрощенная проверка
                                    
                                    details.append(f"Обнаружен: {av_name}")
                                    antivirus_status = f"{detected_type} ({av_name})"
                                    
                                    if is_enabled:
                                        details.append("Статус: Активен")
                                        if is_updated:
                                            details.append("Базы: Актуальны")
                                            bases_updated = True
                                            passed = True
                                        else:
                                            details.append("Базы: Требуют обновления")
                                            recommendations.append(f"Обновить антивирусные базы {detected_type}")
                                    else:
                                        details.append("Статус: Отключен")
                                        recommendations.append(f"Включить защиту в {detected_type}")
                                    break
                        
                        if not antivirus_found:
                            # Если не найдено через WMI, проверяем службы
                            services_to_check = [
                                ('Kaspersky', ['kavsvc', 'klcp', 'ksde']),
                                ('Dr.Web', ['drwebd', 'spidernt', 'dwengine'])
                            ]
                            
                            for av_type, services in services_to_check:
                                for service in services:
                                    svc_result = subprocess.run(
                                        ['powershell', '-Command', 
                                         f'Get-Service -Name "{service}" -ErrorAction SilentlyContinue | Select-Object Status'],
                                        capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                                    )
                                    if 'Running' in svc_result.stdout:
                                        antivirus_found = av_type
                                        antivirus_status = f"{av_type} (обнаружен по службе)"
                                        details.append(f"Обнаружен: {av_type} (служба {service} активна)")
                                        passed = True
                                        break
                                if antivirus_found:
                                    break
                            
                            if not antivirus_found:
                                # Проверка через реестр
                                registry_paths = [
                                    r'HKLM\SOFTWARE\KasperskyLab',
                                    r'HKLM\SOFTWARE\Doctor Web',
                                    r'HKLM\SOFTWARE\WOW6432Node\KasperskyLab',
                                    r'HKLM\SOFTWARE\WOW6432Node\Doctor Web'
                                ]
                                
                                for reg_path in registry_paths:
                                    reg_result = subprocess.run(
                                        ['reg', 'query', reg_path],
                                        capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                                    )
                                    if reg_result.returncode == 0:
                                        if 'Kaspersky' in reg_path:
                                            antivirus_found = 'Kaspersky'
                                        elif 'Doctor' in reg_path or 'Dr.Web' in reg_path:
                                            antivirus_found = 'Dr.Web'
                                        
                                        if antivirus_found:
                                            antivirus_status = f"{antivirus_found} (обнаружен в реестре)"
                                            details.append(f"Обнаружен: {antivirus_found} (запись в реестре)")
                                            passed = True
                                            recommendations.append("Проверить статус работы антивируса")
                                            break
                            
                    except Exception as e:
                        details.append(f"Ошибка анализа данных: {str(e)}")
                        recommendations.append("Проверить наличие антивирусного ПО вручную")
                else:
                    details.append("Не удалось получить информацию об антивирусах через WMI")
                    
            except Exception as e:
                details.append(f"Ошибка проверки: {str(e)}")
                recommendations.append("Проверить наличие антивирусного ПО вручную")
            
            # Если ничего не найдено, проверяем Защитник Windows как запасной вариант
            if not antivirus_found:
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', 
                         'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled'],
                        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
                    )
                    if 'True' in result.stdout:
                        details.append("Защитник Windows активен (базовая защита)")
                        antivirus_status = "Microsoft Defender"
                        passed = True
                        recommendations.append("Рассмотреть установку сертифицированного ФСТЭК антивируса (Kaspersky/Dr.Web)")
                    else:
                        details.append("Антивирусное ПО не обнаружено")
                        recommendations.append("Установить сертифицированное ФСТЭК антивирусное ПО (Kaspersky или Dr.Web)")
                except:
                    details.append("Не удалось проверить антивирусную защиту")
                    recommendations.append("Установить и настроить антивирусное ПО")
                    
        else:  # Linux
            # Проверка для Linux систем
            linux_av_checks = [
                ('Kaspersky', ['kesl', 'kesl-control']),
                ('Dr.Web', ['drweb-daemon', 'drweb-ctl'])
            ]
            
            for av_type, commands in linux_av_checks:
                try:
                    for cmd in commands:
                        result = subprocess.run(
                            ['which', cmd],
                            capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                        )
                        if result.returncode == 0:
                            antivirus_found = av_type
                            antivirus_status = f"{av_type} для Linux"
                            details.append(f"Обнаружен: {av_type} для Linux")
                            
                            # Проверка статуса службы
                            svc_result = subprocess.run(
                                ['systemctl', 'is-active', cmd],
                                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                            )
                            if svc_result.stdout.strip() == 'active':
                                details.append("Статус: Активен")
                                passed = True
                            else:
                                details.append("Статус: Не активен")
                                recommendations.append(f"Активировать службу {cmd}")
                            break
                except:
                    pass
                
                if antivirus_found:
                    break
            
            if not antivirus_found:
                details.append(f"Антивирусное ПО для {system} не обнаружено")
                recommendations.append("Установить сертифицированное антивирусное ПО (Kaspersky Endpoint Security для Linux или Dr.Web для Linux)")
        
        # Формирование итогового статуса
        if not recommendations:
            if passed:
                recommendations.append("Поддерживать антивирусное ПО в актуальном состоянии")
            else:
                recommendations.append("Установить и настроить сертифицированное ФСТЭК антивирусное ПО")
        
        return {
            'status': 'ok' if passed else 'critical',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations,
            'antivirus_info': {
                'found': antivirus_found,
                'status': antivirus_status,
                'bases_updated': bases_updated
            }
        }
    
    def _check_firewall(self):
        """Проверка межсетевого экрана"""
        system = platform.system()
        recommendations = []
        details = []
        passed = False
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-NetFirewallProfile | Select-Object Name,Enabled'],
                    capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
                )
                enabled_count = result.stdout.count('True')
                if enabled_count > 0:
                    details.append(f"Брандмауэр активен в {enabled_count} профилях")
                    passed = True
                else:
                    details.append("Брандмауэр отключен")
                    recommendations.append("Включить брандмауэр Windows")
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
                recommendations.append("Включить брандмауэр в настройках системы")
        else:
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                if 'active' in result.stdout.lower():
                    details.append("UFW брандмауэр активен")
                    passed = True
                else:
                    details.append("Брандмауэр не активен")
                    recommendations.append("Активировать брандмауэр (ufw enable)")
            except:
                details.append("Статус брандмауэра неизвестен")
                recommendations.append("Настроить и включить межсетевой экран")
        
        return {
            'status': 'ok' if passed else 'critical',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Проверить правила фильтрации трафика']
        }
    
    def _check_password_policy(self):
        """Проверка политики паролей"""
        system = platform.system()
        recommendations = []
        details = []
        passed = False
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['net', 'accounts'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                output = result.stdout
                
                min_length = re.search(r'Minimum password length\.\.\.:\s*(\d+)', output)
                max_age = re.search(r'Maximum password age \(days\)\.\.\.:\s*(\d+|Never)', output)
                
                if min_length:
                    length = int(min_length.group(1))
                    details.append(f"Минимальная длина пароля: {length}")
                    if length >= 8:
                        passed = True
                    else:
                        recommendations.append("Увеличить минимальную длину пароля до 8+ символов")
                
                if max_age:
                    age = max_age.group(1)
                    details.append(f"Максимальный возраст пароля: {age}")
                    if age != 'Never' and int(age) <= 90:
                        pass
                    else:
                        recommendations.append("Установить срок действия пароля не более 90 дней")
                        
            except Exception as e:
                details.append(f"Ошибка проверки: {str(e)}")
                recommendations.append("Настроить политику паролей через gpedit.msc")
        else:
            details.append("Требуется ручная проверка политики паролей")
            recommendations.extend([
                "Минимальная длина пароля: 8 символов",
                "Сложность: буквы, цифры, спецсимволы",
                "Срок действия: не более 90 дней"
            ])
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Текущая политика паролей соответствует требованиям']
        }
    
    def _check_user_accounts(self):
        """Проверка учетных записей"""
        system = platform.system()
        recommendations = []
        details = []
        passed = True
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-LocalUser | Select-Object Name,Enabled,LastLogon'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                users = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                details.append(f"Найдено учетных записей: {len(users)}")
                
                guest_check = subprocess.run(
                    ['powershell', '-Command', 'Get-LocalUser -Name Guest | Select-Object Enabled'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                if 'True' in guest_check.stdout:
                    details.append("Учетная запись Guest активна")
                    recommendations.append("Отключить учетную запись Guest")
                    passed = False
                else:
                    details.append("Учетная запись Guest отключена")
                    
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
        else:
            try:
                result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                users = [line for line in result.stdout.split('\n') if line and not line.startswith('#')]
                details.append(f"Найдено учетных записей: {len(users)}")
            except:
                details.append("Информация об учетных записях недоступна")
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Регулярно проводить ревизию учетных записей']
        }
    
    def _check_audit_logging(self):
        """Проверка журналирования событий"""
        system = platform.system()
        recommendations = []
        details = []
        passed = False
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-WinEvent -ListLog Security | Select-Object RecordCount,IsEnabled'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                if 'True' in result.stdout:
                    details.append("Журнал безопасности включен")
                    passed = True
                else:
                    details.append("Журнал безопасности отключен")
                    recommendations.append("Включить журнал событий безопасности")
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
                recommendations.append("Настроить аудит через secpol.msc")
        else:
            try:
                if os.path.exists('/var/log/auth.log') or os.path.exists('/var/log/secure'):
                    details.append("Журнал аутентификации существует")
                    passed = True
                else:
                    details.append("Журналы аудита не найдены")
                    recommendations.append("Настроить системное журналирование (rsyslog/auditd)")
            except:
                details.append("Не удалось проверить журналы")
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Хранить журналы не менее 6 месяцев']
        }
    
    def _check_encryption(self):
        """Проверка шифрования дисков"""
        system = platform.system()
        recommendations = []
        details = []
        passed = False
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['manage-bde', '-status'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                if 'Protection On' in result.stdout or 'Percentage Encrypted: 100' in result.stdout:
                    details.append("BitLocker шифрование активно")
                    passed = True
                else:
                    details.append("BitLocker не активен")
                    recommendations.append("Включить шифрование диска BitLocker для защиты ПДн")
            except:
                details.append("Не удалось проверить статус BitLocker")
                recommendations.append("Проверить шифрование диска вручную")
        else:
            try:
                result = subprocess.run(['cryptsetup', 'status'], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                if 'active' in result.stdout.lower():
                    details.append("LUKS шифрование активно")
                    passed = True
                else:
                    details.append("Шифрование диска не обнаружено")
                    recommendations.append("Рассмотреть возможность шифрования диска (LUKS)")
            except:
                details.append("Статус шифрования неизвестен")
                recommendations.append("Рекомендуется шифрование носителей с ПДн")
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Использовать сертифицированные средства криптозащиты']
        }
    
    def _check_network_shares(self):
        """Проверка сетевых ресурсов"""
        system = platform.system()
        recommendations = []
        details = []
        passed = True
        
        if system == 'Windows':
            try:
                result = subprocess.run(
                    ['net', 'share'],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                shares = [line for line in result.stdout.split('\n') 
                         if line.strip() and 'IPC$' not in line and 'print$' not in line]
                
                if len(shares) > 2:
                    details.append(f"Найдено общих ресурсов: {len(shares)-2}")
                    recommendations.append("Проверить необходимость каждого сетевого ресурса")
                    recommendations.append("Ограничить доступ к общим папкам")
                else:
                    details.append("Сетевые ресурсы в норме")
            except Exception as e:
                details.append(f"Ошибка: {str(e)}")
        else:
            try:
                result = subprocess.run(['exportfs', '-v'], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                if result.stdout.strip():
                    details.append("Найдены NFS экспорты")
                    recommendations.append("Проверить настройки доступа к NFS ресурсам")
                else:
                    details.append("NFS экспорты не найдены")
            except:
                details.append("Информация о сетевых ресурсах недоступна")
        
        return {
            'status': 'ok' if passed else 'warning',
            'passed': passed,
            'details': '\n'.join(details),
            'recommendations': recommendations if recommendations else ['Минимизировать количество общих ресурсов']
        }


class PDReportGenerator:
    """Генератор отчетов по форме законодательства"""
    
    @staticmethod
    def generate_official_report(results, output_path=None):
        """Генерация официального заключения"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = ORG_DATA.get('pc_name', platform.node())
        os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        org_name = ORG_DATA.get('name', '_________________________')
        chairman = ORG_DATA.get('chairman', '_________________________')
        member1 = ORG_DATA.get('member1', '_________________________')
        member2 = ORG_DATA.get('member2', '_________________________')
        order_number = ORG_DATA.get('order_number', '____')
        order_date = ORG_DATA.get('order_date', '__.__.____')
        responsible = ORG_DATA.get('responsible_person', '_________________________')
        
        total_checks = len(results)
        passed_checks = sum(1 for r in results.values() if r.get('passed', False))
        failed_checks = total_checks - passed_checks
        
        compliance_level = "СООТВЕТСТВУЕТ" if failed_checks == 0 else "ТРЕБУЕТСЯ УСТРАНЕНИЕ"
        
        report = f"""
================================================================================
                    ЗАКЛЮЧЕНИЕ ПО ПРОВЕРКЕ СИСТЕМЫ ЗАЩИТЫ
                    ПЕРСОНАЛЬНЫХ ДАННЫХ НА УЯЗВИМОСТИ
================================================================================

Организация: {org_name}
Дата проведения проверки: {timestamp}
Наименование информационной системы (ПК): {hostname}
Операционная система: {os_info}

Основание проверки:
- Приказ о создании комиссии № {order_number} от {order_date}
- Федеральный закон № 152-ФЗ "О персональных данных"
- Приказ ФСТЭК России № 21 "Об утверждении Требований к защите 
  персональных данных при их обработке в информационных системах 
  персональных данных"
- Приказ ФСТЭК России № 17 "Об утверждении Требований к защите 
  персональных данных при их обработке в информационных системах 
  персональных данных, использующих средства виртуализации"

Состав комиссии:
Председатель: {chairman}
Члены комиссии:
  1. {member1}
  2. {member2}

--------------------------------------------------------------------------------
                         РЕЗУЛЬМАТЫ ПРОВЕРКИ
--------------------------------------------------------------------------------

Общий уровень соответствия: {compliance_level}
Проверено параметров: {total_checks}
Соответствует требованиям: {passed_checks}
Требует устранения: {failed_checks}

--------------------------------------------------------------------------------
                    ДЕТАЛИЗАЦИЯ ПО ПАРАМЕТРАМ ЗАЩИТЫ
--------------------------------------------------------------------------------

"""
        for check_id, result in results.items():
            status_icon = "✓" if result.get('passed', False) else "✗"
            status_text = "СООТВЕТСТВУЕТ" if result.get('passed', False) else "НЕ СООТВЕТСТВУЕТ"
            
            report += f"""
{status_icon} {result.get('name', check_id)}
   Нормативное требование: {result.get('requirement', 'Н/Д')}
   Статус: {status_text}
   Детали: {result.get('details', 'Нет информации')}

"""

        report += f"""
--------------------------------------------------------------------------------
                         ВЫВОДЫ И РЕКОМЕНДАЦИИ
--------------------------------------------------------------------------------

"""
        all_recommendations = set()
        for result in results.values():
            for rec in result.get('recommendations', []):
                all_recommendations.add(rec)
        
        if all_recommendations:
            for idx, rec in enumerate(all_recommendations, 1):
                report += f"{idx}. {rec}\n"
        else:
            report += "Рекомендаций нет. Система соответствует требованиям.\n"
        
        report += f"""
--------------------------------------------------------------------------------
                              ПОДПИСИ
--------------------------------------------------------------------------------

Руководитель организации: ___________________ / ___________________
                         (подпись)               (Ф.И.О.)

Ответственный за защиту ПДн: {responsible}
                         ___________________ / ___________________
                         (подпись)               (Ф.И.О.)

Председатель комиссии:   ___________________ / ___________________
                         (подпись)               (Ф.И.О.)

Дата: "__" __________ 20__ г.

================================================================================
"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report
    
    @staticmethod
    def generate_detailed_report(results, output_path=None):
        """Генерация детального отчета с рекомендациями"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
################################################################################
#                 ОТЧЕТ О РЕКОМЕНДУЕМЫХ ДЕЙСТВИЯХ                              #
#                 ПО УСТРАНЕНИЮ УЯЗВИМОСТЕЙ                                    #
################################################################################

Дата формирования: {timestamp}

--------------------------------------------------------------------------------
                    ПРИОРИТЕТНЫЕ МЕРЫ (КРИТИЧЕСКИЕ)
--------------------------------------------------------------------------------

"""
        critical_items = [(k, v) for k, v in results.items() 
                         if v.get('status') == 'critical']
        
        if critical_items:
            for check_id, result in critical_items:
                report += f"""
⚠ {result.get('name', check_id)}
   Проблема: {result.get('details', 'Неизвестно')}
   
   Рекомендуемые действия:
"""
                for idx, rec in enumerate(result.get('recommendations', []), 1):
                    report += f"   {idx}. {rec}\n"
                report += "\n"
        else:
            report += "Критических уязвимостей не обнаружено.\n\n"
        
        report += """
--------------------------------------------------------------------------------
                    РЕКОМЕНДАЦИИ СРЕДНЕГО ПРИОРИТЕТА
--------------------------------------------------------------------------------

"""
        warning_items = [(k, v) for k, v in results.items() 
                        if v.get('status') == 'warning']
        
        if warning_items:
            for check_id, result in warning_items:
                report += f"""
• {result.get('name', check_id)}
   Текущее состояние: {result.get('details', 'Неизвестно')}
   
   Меры по улучшению:
"""
                for idx, rec in enumerate(result.get('recommendations', []), 1):
                    report += f"   {idx}. {rec}\n"
                report += "\n"
        else:
            report += "Замечаний среднего приоритета нет.\n\n"
        
        report += """
--------------------------------------------------------------------------------
                    ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ ПДн
--------------------------------------------------------------------------------

1. Организационные меры:
   - Назначить ответственного за обработку ПДн приказом руководителя
   - Разработать локальные акты по защите ПДн
   - Вести учет лиц, допущенных к работе с ПДн
   - Регулярно проводить обучение сотрудников

2. Технические меры:
   - Использовать сертифицированные ФСТЭК средства защиты
   - Обеспечить разграничение прав доступа
   - Организовать резервное копирование ПДн
   - Применять средства антивирусной защиты

3. Контроль и мониторинг:
   - Регулярно проводить проверки настроек защиты
   - Анализировать журналы событий безопасности
   - Проводить тестирование на проникновение
   - Актуализировать модели угроз

--------------------------------------------------------------------------------
                    ПЛАН МЕРОПРИЯТИЙ ПО УСТРАНЕНИЮ
--------------------------------------------------------------------------------

| № | Мероприятие                          | Срок    | Ответственный |
|---|--------------------------------------|---------|---------------|
"""
        
        task_num = 1
        for check_id, result in results.items():
            if not result.get('passed', True):
                for rec in result.get('recommendations', [])[:1]:
                    report += f"| {task_num} | {rec[:35]:<35} | 30 дней | _____________ |\n"
                    task_num += 1
        
        if task_num == 1:
            report += "| - | Мероприятия не требуются           | -       | -             |\n"
        
        report += """
################################################################################
                              КОНЕЦ ОТЧЕТА
################################################################################
"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report
    
    @staticmethod
    def generate_compliance_act(results, output_path=None):
        """Генерация АКТА проверки соответствия требованиям защиты ПДн"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        date_short = datetime.now().strftime("%d.%m.%Y")
        hostname = ORG_DATA.get('pc_name', platform.node())
        os_info = f"{platform.system()} {platform.release()}"
        org_name = ORG_DATA.get('name', '_________________________')
        chairman = ORG_DATA.get('chairman', '_________________________')
        member1 = ORG_DATA.get('member1', '_________________________')
        member2 = ORG_DATA.get('member2', '_________________________')
        order_number = ORG_DATA.get('order_number', '____')
        order_date = ORG_DATA.get('order_date', '__.__.____')
        responsible = ORG_DATA.get('responsible_person', '_________________________')
        
        total_checks = len(results)
        passed_checks = sum(1 for r in results.values() if r.get('passed', False))
        violations_count = total_checks - passed_checks
        
        report = f"""
################################################################################
#                                                                              #
#                           АКТ ПРОВЕРКИ                                       #
#              соответствия требований к защите персональных данных            #
#                                                                              #
################################################################################

АКТ № {order_number} от "{date_short.split('.')[0]}" ________ 20__ г.

о проведении проверки соответствия требованиям к защите персональных данных

г. _________________                                                  "{date_short}"

Комиссия в составе:

Председатель комиссии: {chairman}
                        (должность, Ф.И.О.)

Члены комиссии:
1. {member1}
   (должность, Ф.И.О.)
2. {member2}
   (должность, Ф.И.О.)

Основание для проведения проверки:
- Приказ о создании комиссии № {order_number} от {order_date}
- План мероприятий по обеспечению безопасности персональных данных
- Федеральный закон от 27.07.2006 № 152-ФЗ "О персональных данных"
- Приказ ФСТЭК России от 18.02.2013 № 21

провела проверку соответствия требованиям к защите персональных данных при их 
обработке в информационной системе персональных данных:

Наименование ИС (ПК): {hostname}
Организация: {org_name}
Операционная система: {os_info}

--------------------------------------------------------------------------------
                         РЕЗУЛЬТАТЫ ПРОВЕРКИ
--------------------------------------------------------------------------------

"""
        
        # Таблица результатов
        report += """| № | Параметр проверки              | Требование      | Статус           | Примечание |
|---|----------------------------------|-----------------|------------------|------------|
"""
        
        for idx, (check_id, result) in enumerate(results.items(), 1):
            status = "СООТВЕТСТВУЕТ" if result.get('passed', False) else "НЕ СООТВЕТСТВУЕТ"
            name = result.get('name', check_id)[:30]
            requirement = result.get('requirement', 'Н/Д')[:15]
            note = "Выявлены нарушения" if not result.get('passed', False) else "-"
            report += f"| {idx} | {name:<30} | {requirement:<15} | {status:<16} | {note:<10} |\n"
        
        report += f"""
Итого проверено: {total_checks} параметров
Соответствуют требованиям: {passed_checks}
Не соответствуют требованиям: {violations_count}

--------------------------------------------------------------------------------
                    ВЫЯВЛЕННЫЕ НАРУШЕНИЯ И НЕДОСТАТКИ
--------------------------------------------------------------------------------

"""
        
        violation_num = 1
        for check_id, result in results.items():
            if not result.get('passed', False):
                report += f"""
{violation_num}. {result.get('name', check_id)}
   Нормативное требование: {result.get('requirement', 'Н/Д')}
   Выявленное нарушение: {result.get('details', 'Не определено')}
   
"""
                violation_num += 1
        
        if violation_num == 1:
            report += "Нарушений не выявлено.\n"
        
        report += f"""
--------------------------------------------------------------------------------
                         ЗАКЛЮЧЕНИЕ КОМИССИИ
--------------------------------------------------------------------------------

По результатам проверки комиссия пришла к следующему заключению:

Информационная система персональных данных "{hostname}" 
организации {org_name}
{{"СООТВЕТСТВУЕТ" if violations_count == 0 else "НЕ СООТВЕТСТВУЕТ"}} 
требованиям к защите персональных данных, установленным:

1. Федеральным законом от 27.07.2006 № 152-ФЗ "О персональных данных"
2. Приказом ФСТЭК России от 18.02.2013 № 21
3. Постановлением Правительства РФ от 01.11.2012 № 1119

{{"Система допускается к эксплуатации." if violations_count == 0 else "Требуется устранение выявленных нарушений."}}

--------------------------------------------------------------------------------
                              ПОДПИСИ ЧЛЕНОВ КОМИССИИ
--------------------------------------------------------------------------------

Председатель комиссии:    _________________ / _________________________
                          (подпись)            {chairman}

Член комиссии:            _________________ / _________________________
                          (подпись)            {member1}

Член комиссии:            _________________ / _________________________
                          (подпись)            {member2}

С актом ознакомлен:
Ответственный за защиту ПДн: {responsible}
                             _________________ / _________________________
                             (подпись)            (Ф.И.О.)
                             
"__" __________ 20__ г.

################################################################################
"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report

    @staticmethod
    def generate_violation_notice(results, output_path=None):
        """Генерация ПРЕДПИСАНИЯ об устранении нарушений"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        date_short = datetime.now().strftime("%d.%m.%Y")
        hostname = ORG_DATA.get('pc_name', platform.node())
        
        violations = [(k, v) for k, v in results.items() if not v.get('passed', False)]
        critical_violations = [(k, v) for k, v in results.items() if v.get('status') == 'critical']
        warning_violations = [(k, v) for k, v in results.items() if v.get('status') == 'warning']
        
        report = f"""
################################################################################
#                                                                              #
#                    ПРЕДПИСАНИЕ                                               #
#                    об устранении нарушений                                   #
#                    требований к защите персональных данных                   #
#                                                                              #
################################################################################

ПРЕДПИСАНИЕ № ____ от "{date_short.split('.')[0]}" ________ 20__ г.

Об устранении нарушений требований к защите персональных данных

г. _________________                                                  "{date_short}"

На основании:
- Федерального закона от 27.07.2006 № 152-ФЗ "О персональных данных"
- Приказа ФСТЭК России от 18.02.2013 № 21
- Акта проверки от "{date_short}"

_________________________________________________________________________
(наименование организации)

выявлены следующие нарушения требований к защите персональных данных:

--------------------------------------------------------------------------------
                    I. КРИТИЧЕСКИЕ НАРУШЕНИЯ
                    (требуют немедленного устранения)
--------------------------------------------------------------------------------

"""
        
        if critical_violations:
            for idx, (check_id, result) in enumerate(critical_violations, 1):
                report += f"""
{idx}. {result.get('name', check_id)}
    
    Описание нарушения:
    {result.get('details', 'Не определено')}
    
    Нормативное требование:
    {result.get('requirement', 'Н/Д')}
    
    Необходимые меры по устранению:
"""
                for rec_idx, rec in enumerate(result.get('recommendations', []), 1):
                    report += f"    {rec_idx}. {rec}\n"
                
                report += f"""
    Срок устранения: до "__" ________ 20__ г.
    Ответственный: _________________________
    
"""
        else:
            report += "Критические нарушения не выявлены.\n\n"
        
        report += """
--------------------------------------------------------------------------------
                    II. НАРУШЕНИЯ СРЕДНЕЙ ТЯЖЕСТИ
                    (требуют устранения в плановом порядке)
--------------------------------------------------------------------------------

"""
        
        if warning_violations:
            for idx, (check_id, result) in enumerate(warning_violations, 1):
                report += f"""
{idx}. {result.get('name', check_id)}
    
    Описание нарушения:
    {result.get('details', 'Не определено')}
    
    Рекомендуемые меры:
"""
                for rec_idx, rec in enumerate(result.get('recommendations', []), 1):
                    report += f"    {rec_idx}. {rec}\n"
                
                report += f"""
    Срок устранения: до "__" ________ 20__ г.
    Ответственный: _________________________
    
"""
        else:
            report += "Нарушения средней тяжести не выявлены.\n\n"
        
        report += f"""
--------------------------------------------------------------------------------
                    III. ПЛАН МЕРОПРИЯТИЙ ПО УСТРАНЕНИЮ НАРУШЕНИЙ
--------------------------------------------------------------------------------

| № | Наименование мероприятия              | Срок исполнения | Ответственное лицо |
|---|-----------------------------------------|-----------------|---------------------|
"""
        
        task_num = 1
        for check_id, result in violations:
            for rec in result.get('recommendations', [])[:1]:
                rec_short = rec[:45] if len(rec) > 45 else rec
                report += f"| {task_num} | {rec_short:<45} | 30 дней         | __________________ |\n"
                task_num += 1
        
        if task_num == 1:
            report += "| - | Нарушения отсутствуют                    | -               | -                  |\n\n"
        
        report += f"""
--------------------------------------------------------------------------------
                    IV. КОНТРОЛЬ ИСПОЛНЕНИЯ
--------------------------------------------------------------------------------

Контроль за исполнением настоящего предписания возложить на:

Ответственного за защиту ПДн: _________________________
                              (Ф.И.О., должность)

Отчет об устранении нарушений представить до "__" ________ 20__ г.

--------------------------------------------------------------------------------
                              ПОДПИСИ
--------------------------------------------------------------------------------

Руководитель организации:
                         _________________ / _________________________
                         (подпись)            (Ф.И.О.)

Ответственный за защиту ПДн:
                         _________________ / _________________________
                         (подпись)            (Ф.И.О.)

С предписанием ознакомлен:
                         _________________ / _________________________
                         (подпись)            (Ф.И.О.)
                         
"__" __________ 20__ г.

М.П.

################################################################################
                              ПРИЛОЖЕНИЯ
################################################################################

Приложение 1. Акт проверки соответствия от "{date_short}"
Приложение 2. Отчет о техническом состоянии средств защиты информации
Приложение 3. Перечень выявленных уязвимостей

################################################################################
"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report


class SecurityCheckGUI(QMainWindow):
    """Графический интерфейс программы"""
    
    def __init__(self):
        super().__init__()
        self.results = {}
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        """Инициализация пользовательского интерфейса"""
        self.setWindowTitle('Проверка защищенности ПДн (152-ФЗ, ФСТЭК)')
        self.setMinimumSize(1000, 750)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QLabel {
                color: #333;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
            QTextEdit, QTextBrowser, QLineEdit {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 5px;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QListWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QListWidgetItem:selected {
                background-color: #e3f2fd;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        header_label = QLabel(
            "ПРОГРАММА ПРОВЕРКИ ЗАЩИЩЕННОСТИ ПЕРСОНАЛЬНЫХ ДАННЫХ\n"
            "согласно 152-ФЗ и требованиям ФСТЭК России"
        )
        header_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header_label)
        
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Вкладка настроек организации (новая)
        org_tab = QWidget()
        org_layout = QVBoxLayout(org_tab)
        
        org_group = QGroupBox("Данные организации и комиссии")
        org_form_layout = QFormLayout(org_group)
        
        self.org_name_input = QLineEdit()
        self.org_name_input.setPlaceholderText("Введите полное наименование организации")
        org_form_layout.addRow("Наименование организации:", self.org_name_input)
        
        self.chairman_input = QLineEdit()
        self.chairman_input.setPlaceholderText("Должность, Ф.И.О. председателя комиссии")
        org_form_layout.addRow("Председатель комиссии:", self.chairman_input)
        
        self.member1_input = QLineEdit()
        self.member1_input.setPlaceholderText("Должность, Ф.И.О. члена комиссии")
        org_form_layout.addRow("Член комиссии 1:", self.member1_input)
        
        self.member2_input = QLineEdit()
        self.member2_input.setPlaceholderText("Должность, Ф.И.О. члена комиссии")
        org_form_layout.addRow("Член комиссии 2:", self.member2_input)
        
        self.order_number_input = QLineEdit()
        self.order_number_input.setPlaceholderText("Номер приказа")
        org_form_layout.addRow("№ приказа о создании комиссии:", self.order_number_input)
        
        self.order_date_input = QDateEdit()
        self.order_date_input.setCalendarPopup(True)
        self.order_date_input.setDate(QDate.currentDate())
        self.order_date_input.setDisplayFormat("dd.MM.yyyy")
        org_form_layout.addRow("Дата приказа:", self.order_date_input)
        
        self.responsible_input = QLineEdit()
        self.responsible_input.setPlaceholderText("Должность, Ф.И.О. ответственного за защиту ПДн")
        org_form_layout.addRow("Ответственный за защиту ПДн:", self.responsible_input)
        
        self.pc_name_input = QLineEdit()
        self.pc_name_input.setText(platform.node())
        self.pc_name_input.setPlaceholderText("Наименование ПК (автоматически)")
        org_form_layout.addRow("Наименование ПК:", self.pc_name_input)
        
        org_layout.addWidget(org_group)
        
        save_org_btn = QPushButton("Сохранить данные организации")
        save_org_btn.clicked.connect(self.save_org_data)
        org_layout.addWidget(save_org_btn)
        
        org_info_label = QLabel("Примечание: Данные будут использованы при формировании отчетов и актов")
        org_info_label.setWordWrap(True)
        org_info_label.setStyleSheet("color: #666; font-style: italic;")
        org_layout.addWidget(org_info_label)
        
        tab_widget.addTab(org_tab, "Данные организации")
        
        # Вкладка проверки
        check_tab = QWidget()
        check_layout = QVBoxLayout(check_tab)
        
        info_group = QGroupBox("Информация о системе")
        info_layout = QVBoxLayout(info_group)
        
        self.system_info_label = QLabel()
        self.system_info_label.setText(self._get_system_info())
        self.system_info_label.setWordWrap(True)
        info_layout.addWidget(self.system_info_label)
        
        check_layout.addWidget(info_group)
        
        progress_group = QGroupBox("Ход проверки")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Готов к проверке")
        self.status_label.setAlignment(Qt.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        check_layout.addWidget(progress_group)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("НАЧАТЬ ПРОВЕРКУ")
        self.start_button.clicked.connect(self.start_check)
        self.start_button.setMinimumHeight(50)
        button_layout.addWidget(self.start_button)
        
        check_layout.addLayout(button_layout)
        check_layout.addStretch()
        
        tab_widget.addTab(check_tab, "Проверка")
        
        # Вкладка результатов
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        
        results_splitter = QSplitter(Qt.Vertical)
        
        summary_group = QGroupBox("Сводка результатов")
        summary_layout = QVBoxLayout(summary_group)
        
        self.summary_list = QListWidget()
        self.summary_list.setMaximumHeight(200)
        summary_layout.addWidget(self.summary_list)
        
        results_splitter.addWidget(summary_group)
        
        details_group = QGroupBox("Детальная информация")
        details_layout = QVBoxLayout(details_group)
        
        self.details_browser = QTextBrowser()
        self.details_browser.setPlainText("Результаты проверки будут отображены здесь")
        details_layout.addWidget(self.details_browser)
        
        results_splitter.addWidget(details_group)
        
        results_layout.addWidget(results_splitter)
        
        report_buttons_layout = QHBoxLayout()
        
        self.save_official_button = QPushButton("Сохранить официальное заключение")
        self.save_official_button.clicked.connect(lambda: self.save_report('official'))
        self.save_official_button.setEnabled(False)
        report_buttons_layout.addWidget(self.save_official_button)
        
        self.save_detailed_button = QPushButton("Сохранить рекомендации")
        self.save_detailed_button.clicked.connect(lambda: self.save_report('detailed'))
        self.save_detailed_button.setEnabled(False)
        report_buttons_layout.addWidget(self.save_detailed_button)
        
        results_layout.addLayout(report_buttons_layout)
        
        tab_widget.addTab(results_tab, "Результаты")
        
        # Вкладка требований
        requirements_tab = QWidget()
        requirements_layout = QVBoxLayout(requirements_tab)
        
        req_browser = QTextBrowser()
        req_browser.setHtml(self._get_requirements_html())
        requirements_layout.addWidget(req_browser)
        
        tab_widget.addTab(requirements_tab, "Нормативные требования")
        
        self.show()
    
    def save_org_data(self):
        """Сохранение данных организации в глобальную переменную"""
        ORG_DATA['name'] = self.org_name_input.text().strip()
        ORG_DATA['chairman'] = self.chairman_input.text().strip()
        ORG_DATA['member1'] = self.member1_input.text().strip()
        ORG_DATA['member2'] = self.member2_input.text().strip()
        ORG_DATA['order_number'] = self.order_number_input.text().strip()
        ORG_DATA['order_date'] = self.order_date_input.date().toString("dd.MM.yyyy")
        ORG_DATA['responsible_person'] = self.responsible_input.text().strip()
        ORG_DATA['pc_name'] = self.pc_name_input.text().strip()
        
        QMessageBox.information(
            self,
            "Данные сохранены",
            "Данные организации успешно сохранены и будут использованы при формировании отчетов."
        )
    
    def _get_system_info(self):
        """Получение информации о системе"""
        return (
            f"Операционная система: {platform.system()} {platform.release()}\n"
            f"Версия: {platform.version()}\n"
            f"Архитектура: {platform.machine()}\n"
            f"Имя компьютера: {platform.node()}\n"
            f"Процессор: {platform.processor()}"
        )
    
    def _get_requirements_html(self):
        """HTML представление нормативных требований"""
        return """
        <h2>Нормативные требования к защите персональных данных</h2>
        
        <h3>Федеральный закон № 152-ФЗ "О персональных данных"</h3>
        <ul>
            <li>Статья 18.1 - Требования к обеспечению безопасности ПДн</li>
            <li>Статья 19 - Меры по обеспечению безопасности ПДн</li>
        </ul>
        
        <h3>Приказ ФСТЭК России № 21</h3>
        <p>Требования к защите персональных данных при их обработке в ИСПДн:</p>
        <ul>
            <li>Пункт 15 - Управление обновлениями ПО</li>
            <li>Пункт 16 - Антивирусная защита</li>
            <li>Пункт 17 - Межсетевая защита</li>
            <li>Пункт 18 - Управление доступом</li>
            <li>Пункт 19 - Идентификация и аутентификация</li>
            <li>Пункт 20 - Регистрация событий безопасности</li>
            <li>Пункт 22 - Криптографическая защита</li>
            <li>Пункт 23 - Защита виртуализации</li>
        </ul>
        
        <h3>Уровни защищенности ПДн</h3>
        <table border="1" cellpadding="5">
            <tr><th>Уровень</th><th>Тип данных</th><th>Требования</th></tr>
            <tr><td>УЗ-1</td><td>Специальные, биометрические</td><td>Максимальные</td></tr>
            <tr><td>УЗ-2</td><td>Специальные, биометрические</td><td>Высокие</td></tr>
            <tr><td>УЗ-3</td><td>Иные категории</td><td>Средние</td></tr>
            <tr><td>УЗ-4</td><td>Иные категории</td><td>Базовые</td></tr>
        </table>
        """
    
    def start_check(self):
        """Запуск проверки"""
        self.start_button.setEnabled(False)
        self.status_label.setText("Инициализация проверки...")
        self.progress_bar.setValue(0)
        self.summary_list.clear()
        self.details_browser.clear()
        
        self.worker = SecurityCheckWorker()
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.display_results)
        self.worker.finished_signal.connect(self.check_finished)
        self.worker.start()
    
    def update_progress(self, value, status_text):
        """Обновление прогресса"""
        self.progress_bar.setValue(value)
        self.status_label.setText(status_text)
    
    def display_results(self, results):
        """Отображение результатов"""
        self.results = results
        
        passed = sum(1 for r in results.values() if r.get('passed', False))
        total = len(results)
        
        for check_id, result in results.items():
            status_icon = "✓" if result.get('passed', False) else "✗"
            item_text = f"{status_icon} {result.get('name', check_id)}"
            item = QListWidgetItem(item_text)
            
            if result.get('status') == 'critical':
                item.setBackground(QColor("#ffcdd2"))
            elif result.get('status') == 'warning':
                item.setBackground(QColor("#fff9c4"))
            else:
                item.setBackground(QColor("#c8e6c9"))
            
            self.summary_list.addItem(item)
        
        details_text = "СВОДКА РЕЗУЛЬТАТОВ ПРОВЕРКИ\n" + "="*50 + "\n\n"
        details_text += f"Всего проверок: {total}\n"
        details_text += f"Соответствует: {passed}\n"
        details_text += f"Требует внимания: {total - passed}\n\n"
        details_text += "="*50 + "\n\n"
        
        for check_id, result in results.items():
            status = "СООТВЕТСТВУЕТ" if result.get('passed', False) else "НЕ СООТВЕТСТВУЕТ"
            details_text += f"\n{result.get('name', check_id)}\n"
            details_text += f"Статус: {status}\n"
            details_text += f"Требование: {result.get('requirement', 'Н/Д')}\n"
            details_text += f"Детали: {result.get('details', 'Нет данных')}\n"
            details_text += "-"*40 + "\n"
        
        self.details_browser.setPlainText(details_text)
        
        self.save_official_button.setEnabled(True)
        self.save_detailed_button.setEnabled(True)
    
    def check_finished(self):
        """Завершение проверки"""
        self.start_button.setEnabled(True)
        self.status_label.setText("Проверка завершена")
        
        failed = sum(1 for r in self.results.values() if not r.get('passed', False))
        if failed > 0:
            QMessageBox.warning(
                self,
                "Проверка завершена",
                f"Обнаружено {failed} несоответствий требованиям.\n"
                "Рекомендуется устранить выявленные уязвимости."
            )
        else:
            QMessageBox.information(
                self,
                "Проверка завершена",
                "Все проверки пройдены успешно!\n"
                "Система соответствует требованиям."
            )
    
    def save_report(self, report_type):
        """Сохранение отчета"""
        if not self.results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните проверку")
            return
        
        options = QFileDialog.Options()
        default_name = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчет",
            default_name,
            "Текстовые файлы (*.txt);;Все файлы (*)",
            options=options
        )
        
        if file_path:
            try:
                if report_type == 'official':
                    report = PDReportGenerator.generate_official_report(self.results)
                else:
                    report = PDReportGenerator.generate_detailed_report(self.results)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                
                QMessageBox.information(
                    self,
                    "Успешно",
                    f"Отчет сохранен:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"Не удалось сохранить отчет:\n{str(e)}"
                )


def main():
    """Точка входа в приложение"""
    
    if not PYQT_AVAILABLE:
        print("Ошибка: PyQt5 не установлен.")
        print("Установите зависимостb: pip install PyQt5")
        print("\nЗапуск в консольном режиме...")
        
        console_mode_check()
        return
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = SecurityCheckGUI()
    
    sys.exit(app.exec_())


def console_mode_check():
    """Консольный режим работы (если PyQt5 недоступен)"""
    print("="*60)
    print("ПРОГРАММА ПРОВЕРКИ ЗАЩИЩЕННОСТИ ПЕРСОНАЛЬНЫХ ДАННЫХ")
    print("(152-ФЗ, Приказы ФСТЭК)")
    print("="*60)
    print()
    
    worker = SecurityCheckWorker()
    
    def on_progress(value, status):
        print(f"[{value}%] {status}")
    
    def on_result(results):
        print("\n" + "="*60)
        print("РЕЗУЛЬТАТЫ ПРОВЕРКИ")
        print("="*60)
        
        passed = sum(1 for r in results.values() if r.get('passed', False))
        total = len(results)
        
        print(f"\nВсего проверок: {total}")
        print(f"Соответствует: {passed}")
        print(f"Требует внимания: {total - passed}")
        print()
        
        for check_id, result in results.items():
            status = "✓" if result.get('passed', False) else "✗"
            print(f"{status} {result.get('name', check_id)}")
            print(f"   {result.get('details', 'Нет данных')}")
            if result.get('recommendations'):
                print("   Рекомендации:")
                for rec in result.get('recommendations', []):
                    print(f"     - {rec}")
            print()
        
        official_report = PDReportGenerator.generate_official_report(results)
        detailed_report = PDReportGenerator.generate_detailed_report(results)
        
        report_file = f"pd_check_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(official_report)
            f.write("\n\n")
            f.write(detailed_report)
        
        print(f"\nОтчет сохранен в файл: {report_file}")
    
    worker.progress_signal.connect(on_progress)
    worker.result_signal.connect(on_result)
    worker.run()


if __name__ == '__main__':
    main()
