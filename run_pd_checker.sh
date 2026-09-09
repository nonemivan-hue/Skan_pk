#!/bin/bash
# Скрипт запуска программы проверки защищенности ПДн

echo "Запуск программы проверки защищенности персональных данных"
echo "согласно 152-ФЗ и требованиям ФСТЭК России"
echo ""

# Проверка наличия PyQt5
python3 -c "import PyQt5" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "PyQt5 не установлен. Установка..."
    pip install PyQt5
fi

# Определение типа среды для выбора платформы Qt
if [ -n "$DISPLAY" ] && command -v xrandr &> /dev/null; then
    # Графическая среда доступна
    QT_QPA_PLATFORM=xcb python3 /workspace/pd_security_checker.py "$@"
else
    # Без графической среды (offscreen для тестирования или серверов)
    QT_QPA_PLATFORM=offscreen python3 /workspace/pd_security_checker.py "$@"
fi
