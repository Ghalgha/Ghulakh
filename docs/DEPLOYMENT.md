# Развёртывание сервера (текущая ручная процедура)

Документ описывает существующий runtime и административные действия. Полного автоматического installer/update/uninstaller в репозитории нет. Системные sysctl, маршруты и host firewall настраивает и подтверждает администратор; приложение не меняет их скрытно. Автоматические тесты проверяют локальную композицию и изолированную Linux egress policy, но live VK Calls relay и сквозной Android/VPS путь не подтверждены.

## 1. Создать постоянную Noise keypair

Выполнить один раз на сервере:

~~~sh
cargo run -p ghulakh-server -- --generate-noise-keypair /etc/ghulakh/noise_private.hex /etc/ghulakh/noise_public.hex
~~~

Команда отказывается перезаписывать существующие файлы; private key создаётся с правами 0600 на Unix. Хранить private key только для service account. Публичный ключ закрепить в Android profile. Не генерировать новую пару при обычном перезапуске.

## 2. Создать device credential

Создать высокоэнтропийный отдельный credential для каждого устройства. На сервере хранить только SHA-256 digest — по одному lowercase hex digest на строку:

~~~sh
printf '%s' "$DEVICE_CREDENTIAL" | sha256sum | awk '{print $1}'
~~~

Raw credential вводится в Android profile. Не смешивать его с VK access token, временными TURN credentials или Noise private key. Файл digest должен быть доступен только серверному service account.

## 3. Настроить серверный runtime

~~~sh
GHULAKH_CREDENTIAL_HASHES=/etc/ghulakh/device-credentials.sha256
GHULAKH_TUN_ENABLED=true
GHULAKH_FORWARDING_ENABLED=true
GHULAKH_TUN_NAME=ghulakh0
GHULAKH_TURN_GATEWAY_BIND=0.0.0.0:4434
GHULAKH_NOISE_PRIVATE_KEY=/etc/ghulakh/noise_private.hex
GHULAKH_NOISE_PUBLIC_KEY=/etc/ghulakh/noise_public.hex
~~~

Открыть выбранный UDP gateway port только в соответствии с проверенной host firewall policy. Точные VK relay address ranges не придумывать: они не подтверждены live capture.

Сервер проверяет наличие включённого IPv4 forwarding и global IPv6 forwarding, но не включает их автоматически. Администратор должен настроить persistent sysctl после оценки влияния на хост:

~~~ini
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
~~~

TUN использует IPv4 10.77.0.1/16, IPv6 fd77:77::1/64, MTU 1100. Клиентские IPv4/IPv6 адреса выделяются и проверяются сервером отдельно. Публичный IPv6 egress не возникает автоматически из-за наличия IPv6 адреса в TUN.

## 4. Проверить маршруты и установить egress policy

Сначала определить фактический WAN interface и выбрать режим:
- nat66 — если upstream не маршрутизирует клиентский ULA prefix;
- routed — только если upstream имеет явный рабочий маршрут к выделенному клиентскому IPv6 prefix.

Установка policy:

~~~sh
sudo bash tools/configure-egress-nftables.sh ghulakh0 <WAN_IF> nat66
~~~

Для routed IPv6 заменить последний аргумент на routed.

Скрипт управляет только таблицами inet ghulakh_egress, ip ghulakh_nat4 и ip6 ghulakh_nat6. Он ограничивает TUN source prefixes, блокирует private/special destinations и unsolicited return traffic, разрешает established replies и настраивает IPv4 NAT плюс выбранную IPv6 policy. Он не меняет глобальный FORWARD policy, INPUT rules, sysctl, маршруты или чужие nftables tables. Drop в другой base chain по-прежнему может блокировать traffic.

Проверить полную конфигурацию до включения GHULAKH_FORWARDING_ENABLED=true. Удалить только собственные таблицы:

~~~sh
sudo bash tools/configure-egress-nftables.sh --remove
~~~

Удаление этих таблиц не восстанавливает sysctl или маршруты, поскольку скрипт их не меняет.

## 5. Настроить Android profile

Указать gateway hostname/IP и UDP port, отдельный device credential, VK account access token и pinned Noise server public key. VK access token вводится вручную и сохраняется в составе полного connection profile, зашифрованного Android Keystore AES-GCM. In-app OAuth/login не реализован. При потере Keystore key профиль не расшифровывается и не заменяется автоматически.

Во время соединения приложение получает временные TURN credentials через VK Calls provider. Эти credentials краткоживущие и не являются ключами шифрования туннеля.

## 6. Проверить изолированную сетевую политику

~~~sh
sudo bash tools/test-network-namespaces.sh
~~~

Тест создаёт network namespaces/veth, проверяет IPv4 NAT, IPv6 NAT66 и routed mode, обратный established traffic и firewall drops. Он не меняет внешние маршруты хоста и не подтверждает поведение конкретного VPS provider. Дополнительно вручную проверить WAN interface/default routes, конфликты nftables, UDP gateway port, sysctl/IPv6 RA и отсутствие forwarding к private, loopback, link-local и multicast destinations.

## 7. Ограничения

- Только UDP TURN endpoint; TCP/TLS/TURNS не поддерживаются текущим socket driver.
- Live VK Calls API, relay allocation, auth profile, quota/expiry и endpoint rotation не подтверждены.
- IPv6 tunnel transport реализован; публичный IPv6 egress требует корректного upstream route или NAT66.
- Server deployment lifecycle автоматизирован не полностью. Не запускать непроверенные install scripts на том же хосте.
- Физические Android/VPS тесты остаются заключительным этапом.
