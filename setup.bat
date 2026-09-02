@echo off
chcp 65001 >nul
echo === Настройка winssh-tunnel ===
echo.
echo (ключ для связи с frps теперь программа создаёт сама при первом
echo  запуске — этим шагом заниматься не надо)
echo.

findstr /C:"ПРИДУМАЙ_ПАРОЛЬ" frpc.toml >nul
if not errorlevel 1 (
    echo Придумай пароль, которым будешь заходить по ssh, и введи его сейчас.
    echo ^(он останется виден на экране, ничего страшного для личного пользования^)
    set /p WINSSH_PWD=Пароль: 
    powershell -NoProfile -Command "(Get-Content frpc.toml) -replace 'ПРИДУМАЙ_ПАРОЛЬ', $env:WINSSH_PWD | Set-Content frpc.toml"
    echo Пароль вписан прямо в frpc.toml, рядом с остальными настройками.
) else (
    echo В frpc.toml уже стоит пароль, пропускаю этот шаг.
)
echo.

echo === Остался один шаг руками ===
echo Открой frpc.toml в блокноте и впиши туда адрес своего VPS
echo (там, где сейчас написано ВАШ_VPS_IP_ИЛИ_ДОМЕН).
echo.
echo Когда впишешь — просто дважды кликни winssh-tunnel.exe
echo.
pause
