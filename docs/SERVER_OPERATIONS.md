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

- /etc/ghulakh/server.env: EnvironmentFile, root-owned, group ghulakh, mode 0640.
- /etc/ghulakh/noise_private.hex: private Noise key, service-owned, mode 0600.
- /etc/ghulakh/noise_public.hex: public Noise key, service-owned, mode 0644.
- /etc/ghulakh/device-credentials.sha256: только SHA-256 digests, service-owned, mode 0600.
- /var/lib/ghulakh: persistent service state directory.

Не заменяйте Noise keypair при обычном обновлении. Устройства закрепляют публичный ключ сервера. Device credentials выпускаются отдельно для каждого устройства командой deploy-server.sh credential.

## Сетевые требования

До запуска должны быть настроены администратором:
- IPv4 forwarding;
- IPv6 forwarding;
- WAN-интерфейс и маршруты;
- доступ к UDP gateway port через существующий host INPUT firewall.

Системные sysctl и маршруты установщик не меняет. Не применяйте глобальную политику FORWARD DROP или широкие правила ACCEPT без отдельного аудита хостового firewall.

## Восстановление и удаление

При неудачном обновлении установщик возвращает предыдущую активную release-ссылку и пытается перезапустить прежнюю версию. Старые релизы не удаляются автоматически.

Удаление требует интерактивного подтверждения и удаляет только принадлежащие приложению units, releases и nftables tables. Конфигурация, ключи, credential digests и service account остаются. Это сделано намеренно: удаление бинарников не должно уничтожать идентичность сервера или доступ устройств.

## Ограничения

Успешная установка не доказывает live VK Calls relay compatibility или сквозную работу VPN. Необходимы отдельные испытания на VPS и физическом Android-устройстве, включая проверку UDP reachability, egress, IPv6, DNS, reconnect, leak resistance и длительной стабильности.
