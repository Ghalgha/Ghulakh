# Эксплуатация сервера

## Управление службой

Сервер устанавливается и обновляется через tools/deploy-server.sh. Полная процедура, требования, поведение rollback и границы очистки описаны в [DEPLOYMENT.md](DEPLOYMENT.md).

Команда status проверяет владельца и режим managed directories и marker, checksum обоих systemd units, расположение active release и table-level ownership nftables; она возвращает ненулевой код при нарушении этих проверок или если любая из двух служб не active. Для диагностики используйте systemctl и journalctl отдельно.

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

Перед staging выполняется read-only preflight UDP/4434, владельца сокета, TUN-интерфейса и конфликтующих systemd units. Занятый ресурс допускается только при проверяемой принадлежности текущему серверному процессу; иначе операция прекращается без вмешательства. WAN interface и IPv6 mode сохраняются в управляемом egress unit; update сравнивает их до staging и отказывает при изменении. Системные sysctl и маршруты установщик не меняет. Не применяйте глобальную политику FORWARD DROP или широкие правила ACCEPT без отдельного аудита хостового firewall.

## Восстановление и удаление

При неудачном обновлении установщик возвращает предыдущую активную release-ссылку и пытается перезапустить прежнюю версию. Если управляемого unit-файла нет, но systemd уже видит одноимённый vendor/generated/transient unit, установка прекращается до его перекрытия. Старые релизы не удаляются автоматически. При первой неудачной установке пустой ownership marker остаётся как reservation созданного установщиком корневого каталога, чтобы безопасно повторить установку; созданные unit-файлы и current удаляются, постоянные конфигурация, ключи и credentials сохраняются. При ошибке установки второго systemd unit или ownership marker выполняется rollback обоих unit-файлов и marker; при невозможности rollback резервные файлы сохраняются и путь к ним выводится в ошибке. HUP/INT/TERM обрабатываются с попыткой rollback. Защита от внезапного отключения питания или SIGKILL посреди замены не заявляется.

Если остановка/отключение службы завершается ошибкой, удаление прекращается до удаления файлов. Если daemon-reload завершается ошибкой после удаления unit-файлов, установщик восстанавливает оба unit-файла и active-ссылку из временной копии; если восстановление неполное, путь к резервным копиям выводится явно. При ошибке очистки release directory остатки сохраняются вместе с root-owned recovery journal, создаваемый до удаления units и active-ссылки. Повторный uninstall проверяет журнал, отсутствие units/current и безопасность оставшегося release tree, затем предлагает продолжить очистку; persistent configuration не затрагивается. Пустой ownership marker без systemd units и active-ссылки распознаётся как незавершённая первая установка: удаляется только staging reservation и release tree, persistent configuration остаётся. Любая неоднозначность приводит к отказу. Удаление до подтверждения проверяет ownership marker на уровне JSON-объекта каждой таблицы и прекращается, если не может получить и разобрать полный список nftables tables. Оно также отказывается удалять release tree с symlink, hard link или объектами не root:root. Удаление требует интерактивного подтверждения и удаляет только принадлежащие приложению units, releases и nftables tables. Конфигурация, ключи, credential digests и service account остаются. Это сделано намеренно: удаление бинарников не должно уничтожать идентичность сервера или доступ устройств.

## Ограничения

Успешная установка не доказывает live VK Calls relay compatibility или сквозную работу VPN. Необходимы отдельные испытания на VPS и физическом Android-устройстве, включая проверку UDP reachability, egress, IPv6, DNS, reconnect, leak resistance и длительной стабильности.
