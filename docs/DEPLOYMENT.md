# Развёртывание сервера

Документ описывает установку, обновление и удаление серверного runtime. Установщик управляет только собственными каталогами, двумя systemd units и собственными nftables tables. Он не устанавливает пакеты, не меняет sysctl, маршруты, глобальную политику firewall, INPUT rules или чужие службы.

## Требования

- Linux с работающим systemd.
- Root для установки и управления службами.
- /dev/net/tun как character device.
- net.ipv4.ip_forward=1 и net.ipv6.conf.all.forwarding=1, настроенные администратором и сохранённые в конфигурации ОС.
- Команды ip, nft, runuser, useradd, python3, systemctl, systemd-analyze.
- Доступный WAN-интерфейс.
- Linux release binary ghulakh-server, собранный для архитектуры сервера.

Установщик не загружает бинарники из сети и не устанавливает системные пакеты. Перед передачей бинарника на сервер проверьте его происхождение и SHA-256 по доверенному каналу.

## Сборка

На Linux build host из корня репозитория:

~~~
cargo build --release --locked -p ghulakh-server
~~~

Ожидаемый бинарник: `target/release/ghulakh-server`.

## Первая установка

Если на сервере уже существуют /etc/ghulakh или /var/lib/ghulakh, установщик проверит владельца и права каталогов и остановится при несовпадении. Требуются /etc/ghulakh root:ghulakh 0750 и /var/lib/ghulakh ghulakh:ghulakh 0700; мигрируйте права вручную после проверки содержимого.

Скопируйте бинарник и каталог tools/ на сервер, сохранив рядом файлы:
- deploy-server.sh
- configure-egress-nftables.sh
- create_credential.py

Укажите фактический WAN-интерфейс и подходящий режим IPv6:

~~~
sudo bash tools/deploy-server.sh install \
  --binary /absolute/path/to/ghulakh-server \
  --wan-interface eth0 \
  --ipv6-mode nat66
~~~

Используйте routed вместо nat66 только при наличии проверенного upstream-маршрута к клиентскому IPv6-префиксу.

При первой установке создаются системная учётная запись ghulakh, постоянные каталоги, Noise keypair, digest-файл device credentials, EnvironmentFile, release directory и systemd units. Секрет первого устройства и публичный Noise key выводятся в терминал. Сохраните credential и закрепите public key в Android profile. Credential показывается только при создании; digest хранится на сервере.

Перед выдачей каждого credential утилита открывает каталог и файл через file descriptors с запретом следования symlink, затем проверяет тип объекта, UID/GID, режим и отсутствие дополнительных hard links через fstat. Файл блокируется на время append. Если запись или fsync завершается ошибкой, размер файла возвращается к исходному значению, а секрет не выводится. Несоответствие пути или прав приводит к отказу без изменения файла.

Установщик включает и запускает:
- ghulakh-egress.service: устанавливает только принадлежащие приложению nftables tables через configure-egress-nftables.sh; при остановке удаляет только эти таблицы после проверки ownership marker;
- ghulakh-server.service: запускает сервер от непривилегированного пользователя ghulakh с CAP_NET_ADMIN и доступом к /dev/net/tun.

Каталог /etc/ghulakh принадлежит root:ghulakh (0750), EnvironmentFile и credential digest — root:ghulakh (0640), а Noise private key доступен service account только через отдельный файл. Сервер не может заменять конфигурацию или credential digest через права каталога. Сервис не может менять sysctl благодаря systemd hardening. Серверный EnvironmentFile находится в /etc/ghulakh/server.env. Для согласованности egress policy установщик проверяет фиксированные значения TUN name, gateway bind (0.0.0.0:4434), forwarding flags и путей к секретам; изменение этих параметров требует отдельного изменения deployment unit и firewall policy.

## Добавление устройства

~~~
sudo bash tools/deploy-server.sh credential
~~~

Команда генерирует отдельный 256-битный credential, добавляет только SHA-256 digest в серверный файл и выводит исходный секрет один раз. Передайте его устройству по защищённому каналу. Не копируйте секрет в логи, Git или тикеты.

## Обновление

Соберите и передайте новый бинарник, затем выполните ту же команду с действующими WAN/IPv6 параметрами:

~~~
sudo bash tools/deploy-server.sh update \
  --binary /absolute/path/to/new-ghulakh-server \
  --wan-interface eth0 \
  --ipv6-mode nat66
~~~

Новая версия размещается в отдельном release directory. Активная ссылка переключается атомарно. Если перезапуск не проходит, установщик возвращает предыдущую ссылку и пытается восстановить прежнюю службу. Предыдущие release directories сохраняются для ручного восстановления. WAN interface и IPv6 mode нельзя менять через update: для изменения сетевой топологии требуется отдельная проверенная процедура.

Оба systemd unit-файла сначала формируются и проверяются во временном каталоге. До замены сохраняются предыдущие версии обоих файлов и ownership marker. Замена каждого файла выполняется через rename в пределах /etc/systemd/system; если установка второго unit или обновление marker завершается ошибкой, оба unit-файла и marker восстанавливаются. Обработчики HUP/INT/TERM также запускают rollback. Если сам rollback не удаётся, резервные файлы сохраняются, а ошибка явно выводится; в таком случае не продолжайте обновление и восстановите файлы вручную по сообщению установщика.

Обновление не перезаписывает server.env, Noise keys или credential digests.

## Проверка состояния

~~~
sudo bash tools/deploy-server.sh status
sudo systemctl status ghulakh-server.service ghulakh-egress.service
sudo journalctl -u ghulakh-server.service -u ghulakh-egress.service
~~~

## Удаление

~~~
sudo bash tools/deploy-server.sh uninstall
~~~

Требуется точный ввод REMOVE GHULAKH. Удаляются только проверенные собственные systemd units, release directories, активная ссылка и принадлежащие приложению nftables tables. Сохраняются /etc/ghulakh (EnvironmentFile, Noise keys, credential digests), /var/lib/ghulakh и системная учётная запись. Они оставлены намеренно, чтобы удаление runtime не уничтожало ключи и учётные данные. Удалять их можно отдельно после резервного копирования и ручной проверки.

Если unit-файл изменён администратором или не содержит маркер установщика, удаление останавливается вместо удаления неизвестной конфигурации.

## Сетевые границы

Установщик не меняет:
- net.ipv4.ip_forward, IPv6 forwarding или другие sysctl;
- маршруты, policy routing и RA;
- host INPUT rules и UDP-доступ к gateway;
- чужие nftables tables/chains;
- настройки SSH, DNS, package manager, Docker или другие службы.

Egress unit использует только собственные таблицы inet ghulakh_egress, ip ghulakh_nat4 и, для nat66, ip6 ghulakh_nat6. Если такие таблицы уже установлены вручную, перед запуском unit удалите их только штатной командой sudo bash tools/configure-egress-nftables.sh --remove после проверки ownership marker. Не сохраняйте параллельную копию этих таблиц в другом firewall startup config.

Входящий UDP-порт gateway по умолчанию 4434. Разрешение входящего трафика в существующем INPUT firewall остаётся отдельным решением администратора. Установщик его не открывает.

## Проверки и ограничения

Автоматические deployment checks проверяют shell syntax, ключевые lifecycle invariants, отсутствие глобальных сетевых мутаций и отсутствие широкого удаления системных каталогов. Отдельные Python regression tests проверяют успешную выдачу digest и отказ для file symlink, symlink каталога, FIFO, hard link, неверного режима и неверной группы; при отказе проверяется неизменность целевого файла и отсутствие выдачи секрета. Статические проверки подтверждают наличие резервирования и rollback пары systemd units. Linux namespace tests отдельно проверяют egress policy.

Эти тесты не имитируют полноценную systemd VM и не проверяют отключение питания или SIGKILL в произвольной точке транзакции. Реальный install/update/reboot/rollback/uninstall на отдельной VM/VPS остаётся обязательным этапом.

Эти проверки не доказывают успешный запуск на конкретном VPS, доступность UDP-порта у провайдера, корректность host firewall, live VK TURN relay или сквозной Android → relay → VPS → Internet маршрут. До таких проверок проект остаётся исследовательской системой, а не production VPN.
