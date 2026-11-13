# Эксплуатация сервера

## Управление службой

Сервер устанавливается и обновляется через tools/deploy-server.sh. Полная процедура, требования, поведение rollback и границы очистки описаны в [DEPLOYMENT.md](DEPLOYMENT.md).

Основные команды:

~~~
sudo bash tools/deploy-server.sh status
sudo systemctl restart ghulakh-server.service
sudo journalctl -u ghulakh-server.service -f
~~~

Сетевую egress policy обслуживает отдельная ghulakh-egress.service. Она устанавливается перед серверной службой, применяет только принадлежащие приложению nftables tables и удаляет только эти таблицы при остановке. Не запускайте параллельно второй экземпляр configure-egress-nftables.sh для тех же таблиц.

## Секреты и конфигурация

- /etc/ghulakh: root:ghulakh, mode 0750; каталог не доступен на запись service account.
- /etc/ghulakh/server.env: EnvironmentFile, root:ghulakh, mode 0640.
- /etc/ghulakh/device-credentials.sha256: только SHA-256 digests, root:ghulakh, mode 0640; service account читает файл, но не может его заменить или изменить. Выдача нового credential отклоняется при symlink, hard link, неверном типе файла, владельце, группе или режиме; запись сериализована file lock.
- /etc/ghulakh/noise_private.hex: private Noise key, service-owned, mode 0600.
- /etc/ghulakh/noise_public.hex: public Noise key, service-owned, mode 0644.
- /var/lib/ghulakh: persistent service state directory.

Не заменяйте Noise keypair при обычном обновлении. Устройства закрепляют публичный ключ сервера. Device credentials выпускаются отдельно для каждого устройства командой deploy-server.sh credential.

## Сетевые требования

До запуска должны быть настроены администратором:
- IPv4 forwarding;
- IPv6 forwarding;
- WAN-интерфейс и маршруты;
- доступ к UDP gateway port через существующий host INPUT firewall.

WAN interface и IPv6 mode сохраняются в управляемом egress unit; update сравнивает их до staging и отказывает при изменении. Системные sysctl и маршруты установщик не меняет. Не применяйте глобальную политику FORWARD DROP или широкие правила ACCEPT без отдельного аудита хостового firewall.

## Восстановление и удаление

При неудачном обновлении установщик возвращает предыдущую активную release-ссылку и пытается перезапустить прежнюю версию. Если управляемого unit-файла нет, но systemd уже видит одноимённый vendor/generated/transient unit, установка прекращается до его перекрытия. Старые релизы не удаляются автоматически. При первой неудачной установке пустой ownership marker остаётся как reservation созданного установщиком корневого каталога, чтобы безопасно повторить установку; созданные unit-файлы и current удаляются, постоянные конфигурация, ключи и credentials сохраняются. При ошибке установки второго systemd unit или ownership marker выполняется rollback обоих unit-файлов и marker; при невозможности rollback резервные файлы сохраняются и путь к ним выводится в ошибке. HUP/INT/TERM обрабатываются с попыткой rollback. Защита от внезапного отключения питания или SIGKILL посреди замены не заявляется.

Удаление требует интерактивного подтверждения и удаляет только принадлежащие приложению units, releases и nftables tables. Конфигурация, ключи, credential digests и service account остаются. Это сделано намеренно: удаление бинарников не должно уничтожать идентичность сервера или доступ устройств.

## Ограничения

Успешная установка не доказывает live VK Calls relay compatibility или сквозную работу VPN. Необходимы отдельные испытания на VPS и физическом Android-устройстве, включая проверку UDP reachability, egress, IPv6, DNS, reconnect, leak resistance и длительной стабильности.
