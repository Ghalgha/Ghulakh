# Модель угроз

## Защищаемые активы

- VK access token и временные TURN credentials;
- device credential и закреплённый Noise server public key;
- конфиденциальность и целостность пользовательских IP-пакетов;
- целостность tunnel configuration и path membership;
- доступность Android TUN, TURN allocations, server TUN и bounded queues.

## Противники

- пассивный наблюдатель и активный сетевой посредник;
- relay peer, который может задерживать, терять, повторять или переупорядочивать UDP payloads;
- удалённый отправитель некорректных handshake/data datagrams;
- злоумышленник с credential одного устройства;
- локальный процесс с ограниченными правами;
- скомпрометированная ОС или сервер.

## Границы доверия

- Android-приложение ↔ Android OS/VpnService/Keystore;
- Android ↔ VK Calls credential API;
- Android TURN client ↔ внешний TURN relay;
- TURN relay ↔ собственный UDP gateway;
- Noise-authenticated session ↔ server TUN/kernel forwarding;
- администратор ↔ device credential hashes, Noise private key и firewall.

TURN relay считается недоверенным посредником доставки. Он может наблюдать метаданные соединения и блокировать/изменять/повторять датаграммы, но не должен иметь возможности читать или незаметно изменять пользовательские IP-пакеты.

## Реализованные меры

- Noise XX handshake с pinning server static public key;
- device credential передаётся только внутри зашифрованного Noise сообщения и проверяется сервером до установления сессии;
- HKDF-SHA256 выводит независимые directional AEAD keys;
- защищённые кадры аутентифицируют session ID, направление и sequence number; replay window ограничивает повторы;
- handshake envelopes имеют version/phase/ID/length, bounded retries и exact-byte response cache;
- сервер связывает сессию с фактическим relay source tuple и назначенным virtual IPv4;
- gateway проверяет source tuple, AEAD/replay и назначенный inner IPv4/IPv6 source до TUN ingress;
- path group проверяет общий group ID/path count/virtual IPv4, уникальность path ID и generation-bound replacement;
- handshake admission, peer rate table, replay cache, transaction concurrency и очереди ограничены;
- Rust TURN username/password хранятся в `Zeroizing` и redacted `Debug`; временные Rust JSON/JNI-буферы очищаются при освобождении. Android передаёт TURN JSON в native один раз и снимает ссылки после handoff; JVM не гарантирует физическое стирание immutable `String`. VK access token и device credential шифруются с помощью Android Keystore;
- Android вызывает `VpnService.protect(fd)` для каждого TURN UDP socket до использования его внутри VPN;
- IPv4 и IPv6 маршруты захватываются Android; оба семейства передаются в dual-stack server TUN, где проверяются source addresses. Публичный IPv6 egress зависит от серверного upstream route/NAT66;
- отдельный host nftables egress policy script (его должен явно установить администратор) блокирует spoofed TUN source, частные/служебные IPv4 и IPv6 назначения, unsolicited traffic к TUN и исходящий forwarding в другие интерфейсы. Без установки этого ruleset защита egress на уровне ядра не активна.

## Остаточные риски и ограничения

- VK Calls credential flow и текущий TURN long-term auth profile не подтверждены на реальном relay; возможны изменения API, challenge attributes, quotas и credential lifetime.
- TURN relay видит сетевые метаданные и может блокировать трафик; туннель не обещает анонимность или устойчивость к любому DPI.
- Noise library и собственная композиция handshake/session framing не прошли независимый формальный аудит.
- Компрометация Android OS, сервера или device credential может раскрыть пользовательский трафик/доступ.
- TURN quota и ограничения allocation контролируются внешним сервисом и не гарантируются клиентом.
- In-app OAuth UI/автоматическое получение VK access token, DNS service, LAN access и автоматическое управление существующим firewall хоста не реализовано; правила устанавливаются отдельным административным скриптом и требуют согласования с политикой хоста. TURN credential refresh/recovery реализован для сессии; поведение реальной VK quota/rotation требует live-проверки.
- Ошибочная конфигурация IP forwarding/NAT/firewall может нарушить маршрутизацию; флаг администратора не является автоматической проверкой firewall.
- MTU 1100 и поведение path health/recovery требуют дальнейшей симуляции и в конце проекта — физических испытаний.

## Не входит в обещания

Нельзя обещать анонимность, доступность через любую сеть, прохождение любых фильтров или неограниченное число TURN allocations. Наличие нескольких независимых paths повышает потенциальную совокупную пропускную способность разных flows, но не гарантирует линейного ускорения и не увеличивает пропускную способность одного flow при текущем flow-affinity scheduler.

## Проверки перед выпуском

- негативные тесты Noise identity pinning, credential verification, replay и handshake cache;
- fuzz/property tests STUN/TURN/handshake/IP parsers;
- детерминированные тесты packet loss, reordering, stale nonce, Allocate/Refresh failures и partial path recovery;
- нагрузочные тесты bounded queues, session admission и path replacement;
- анализ зависимостей/SBOM и проверка секретов в логах/crash reports/backup;
- Android permission/revoke/service shutdown и защищённый socket lifecycle;
- проверка server TUN, routing, NAT и firewall в изолированной VM;
- реальные Android/VPS испытания только после завершения программной вертикали.
