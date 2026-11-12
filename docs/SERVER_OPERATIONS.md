# Эксплуатация сервера

## Выпуск device credential

На доверенной административной машине выполните:

```sh
python3 tools/create_credential.py --digest-file /etc/ghulakh/credential-hashes.txt
```

Скрипт генерирует 256-битный случайный секрет, добавляет в файл сервера только его SHA-256 digest и выводит исходный секрет один раз. Передайте секрет соответствующему устройству по защищённому каналу. Не помещайте его в Git, тикеты, общие логи или командную строку.

Файл digest должен быть доступен только системному пользователю сервера (рекомендуемый режим `0600`). Сервер читает его при запуске. Для отзыва устройства удалите соответствующую строку digest и перезапустите сервер. Текущий механизм не поддерживает горячую ротацию.

## TLS

Укажите сертификат и закрытый ключ через `GHULAKH_TLS_CERT` и `GHULAKH_TLS_KEY`. Сертификат должен соответствовать имени узла, которое проверяет клиент. Клиент должен доверять указанному CA/root certificate и проверять имя сервера. Не отключайте проверку сертификата. Закрытый ключ должен быть доступен только серверному процессу.

## Запуск управляющего сервера без TUN

```sh
export GHULAKH_CREDENTIAL_HASHES=/etc/ghulakh/credential-hashes.txt
export GHULAKH_TLS_CERT=/etc/ghulakh/tls/fullchain.pem
export GHULAKH_TLS_KEY=/etc/ghulakh/tls/privkey.pem
export GHULAKH_QUIC_BIND=0.0.0.0:4433
export GHULAKH_TUN_ENABLED=false
cargo run --release -p ghulakh-server
```

Разрешите входящий UDP-трафик на выбранный QUIC-порт. При выключенном TUN сервер проверяет и принимает аутентифицированные IP-датаграммы, но не маршрутизирует их.

## Включение серверного IPv4 TUN

TUN-подсистема пока экспериментальная. Используйте отдельный Linux-сервер или тестовую VM с `/dev/net/tun` и правом `CAP_NET_ADMIN`. По умолчанию TUN выключен.

Параметры текущей реализации:

- интерфейс по умолчанию: `ghulakh0`;
- адрес сервера: `10.77.0.1/16`;
- клиентский пул: `10.77.0.2`–`10.77.255.254`;
- MTU интерфейса: 1100;
- очередь пакетов от клиентов к TUN: 512;
- адреса сессий не переиспользуются до перезапуска процесса;
- IPv6 пока не маршрутизируется;
- egress ACL по умолчанию блокирует RFC1918, loopback, link-local, multicast, broadcast, unspecified, CGNAT, IETF protocol-assignment, documentation и benchmarking диапазоны.

Включать TUN следует только после настройки IP forwarding и firewall. Пример ниже предназначен для отдельного хоста, где этот процесс может управлять всей цепочкой FORWARD. Не вставляйте политику DROP в существующий firewall без проверки его текущих правил.

```sh
# Включить IPv4 forwarding до запуска сервера.
sudo sysctl -w net.ipv4.ip_forward=1

# Замените eth0 на внешний интерфейс сервера.
WAN_IF=eth0

sudo nft add table inet ghulakh
sudo nft 'add chain inet ghulakh forward { type filter hook forward priority filter; policy drop; }'
sudo nft add rule inet ghulakh forward iifname "ghulakh0" oifname "$WAN_IF" ip saddr 10.77.0.0/16 accept
sudo nft add rule inet ghulakh forward iifname "$WAN_IF" oifname "ghulakh0" ip daddr 10.77.0.0/16 ct state established,related accept

sudo nft add table ip ghulakh_nat
sudo nft 'add chain ip ghulakh_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft add rule ip ghulakh_nat postrouting ip saddr 10.77.0.0/16 oifname "$WAN_IF" masquerade

export GHULAKH_TUN_ENABLED=true
export GHULAKH_TUN_NAME=ghulakh0
# Установить true только после проверки sysctl и всех firewall/NAT правил.
export GHULAKH_FORWARDING_ENABLED=true
cargo run --release -p ghulakh-server
```

Команды nftables приведены как минимальный пример для выделенного хоста. Для существующей системы объедините правила с действующей политикой firewall, сохраните их в постоянной конфигурации и проверьте обратный трафик. Сервер не включает IP forwarding и не меняет firewall автоматически. Даже при созданном TUN Android-клиент откажется активировать маршруты, пока администратор явно не установит `GHULAKH_FORWARDING_ENABLED=true`. Этот флаг является подтверждением администратора, а не автоматической проверкой корректности firewall.

## Ограничения

Сервер назначает IPv4-адрес после успешной аутентификации. Клиентские пакеты проверяются по назначенному source IP и проходят базовую egress ACL. Пакеты с неподдерживаемым IPv6, подменённым source IP или запрещённым destination IP отбрасываются. Переполнение ограниченной очереди TUN также приводит к потере пакета.

Эта версия не обеспечивает IPv6, доступ к частным сетям, DNS-конфигурацию, автоматическое восстановление после смены сети, управление устройствами через API или production-grade firewall orchestration. Не включайте маршрутизацию на рабочем сервере до завершения CI, изолированных интеграционных и нагрузочных проверок.
