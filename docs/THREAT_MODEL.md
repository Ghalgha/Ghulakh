# Модель угроз

**Сверено с main `c337b98243f95b15256b4fb56995ff1597684bc2` (2026-11-13); fwmark regression test из PR №12 уже включён в main.** Актуальный статус реализации и границы подтверждения — в [STATUS.md](STATUS.md).

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
- Rust TURN username/password, challenge strings, STUN attribute values, partially decoded attributes, SHA-1/SHA-256 signing/verification staging buffers, pending transaction bytes, retransmission copies и TURN socket actor control/command/receive buffers очищаются через `Zeroizing` или явный `zeroize` при завершении соответствующего lifetime. TURN URI query keys/values очищаются при уничтожении endpoint, а частично собранные query очищаются при ошибке разбора. Это уменьшает контролируемые приложением копии, но не гарантирует очистку внутренних состояний криптографических библиотек/ядра или любых копий, созданных вне контролируемого кода. Android передаёт TURN JSON в native через one-shot handoff; JNI временные Rust-копии JSON и tunnel credential оборачивает в `Zeroizing`. После сериализации Kotlin очищает ссылки из промежуточных `JSONObject`/`JSONArray`, а service-local VK access token освобождается после передачи credential broker. `VkCallsSession` и broker снимают ссылки при finish. JVM immutable `String` (VK access token, TURN JSON, session key, URL-encoded HTTP body) и копии в `org.json`, HTTP/JNI и runtime физически обнулить гарантированно нельзя. VK access token и device credential шифруются с помощью Android Keystore;
- Android вызывает `VpnService.protect(fd)` для каждого TURN UDP socket до использования его внутри VPN;
- IPv4 и IPv6 маршруты захватываются Android; оба семейства передаются в dual-stack server TUN, где проверяются source addresses. Публичный IPv6 egress зависит от серверного upstream route/NAT66;
- отдельный host nftables egress policy script (его должен явно установить администратор) блокирует spoofed TUN source, частные/служебные IPv4 и IPv6 назначения, unsolicited traffic к TUN и исходящий forwarding в другие интерфейсы. Без установки этого ruleset защита egress на уровне ядра не активна. Установка и удаление ограничены собственными nftables tables с ownership marker `ghulakh-egress-v1`; удаление заранее проверяет маркер всех затрагиваемых таблиц и не должно удалять таблицы без подтверждённого владения.

## Жизненный цикл STUN/TURN секретных буферов

В PR №14 добавлена очистка контролируемых Rust-копий на основном control-plane пути: `TurnChallenge` очищает realm/nonce/algorithm offer; `StunMessage` очищает значения атрибутов при drop, а частично декодированные атрибуты очищаются и при ошибке; SHA-1/SHA-256 signing и verification staging buffers и fingerprint staging используют `Zeroizing`; `TransactionManager` очищает сохранённый запрос, а retransmission event очищает отдельную копию; socket actor очищает исходящие command datagrams, входящие control wire bytes и receive buffer. `TurnAuthContext` удерживает username/realm/nonce/key/algorithm offer в zeroizing storage. `Debug` для TURN challenge, STUN attributes/messages, pending transactions и retransmission events скрывает содержимое секретных полей. Kotlin JSON containers очищаются в `finally` после обработки token, call-start и TURN-parameter responses, в том числе при ошибке проверки или разбора.

Ограничения: JVM immutable strings и сторонние runtime/API могут сохранять копии; очистка JSON containers удаляет ссылки, но не стирает содержимое уже созданных String. Также не очищаются гарантированно внутренние буферы HMAC/MD5 реализаций и kernel socket buffers. Проверки требуют CI на актуальном HEAD и не заменяют независимый криптографический review.
## Проверка policy-routing обхода

В PR №12 изолированный network namespace test помечает IPv4 и IPv6 пакеты, поступающие с TUN, через `fwmark`, а policy rules намеренно направляют их к постороннему интерфейсу. Проверяется, что оба пакета не достигают rogue peer, а egress firewall отбрасывает forwarding с TUN. Это регрессионная проверка конкретной топологии Linux namespaces; она не заменяет аудит произвольных host rules, реального VPS и фактической конфигурации провайдера.

## Остаточные риски и ограничения

- VK Calls credential flow и текущий TURN long-term auth profile не подтверждены на реальном relay; возможны изменения API, challenge attributes, quotas и credential lifetime.
- TURN relay видит сетевые метаданные и может блокировать трафик; туннель не обещает анонимность или устойчивость к любому DPI.
- Noise library и собственная композиция handshake/session framing не прошли независимый формальный аудит. В используемом `snow 0.10.0` default X25519 resolver копирует статический private key во внутренний `Dh25519.privkey: [u8; 32]`; эта структура не реализует `Drop`/zeroize для массива. Поэтому очистка внешнего `NoiseServerKeyPair` и временных файловых буферов не доказывает очистку внутренних копий в Noise handshake state. Это остаточный риск до перехода на проверенный resolver/library path с гарантированной очисткой.
- Компрометация Android OS, сервера или device credential может раскрыть пользовательский трафик/доступ.
- TURN quota и ограничения allocation контролируются внешним сервисом и не гарантируются клиентом.
- In-app OAuth UI/автоматическое получение VK access token, DNS service, LAN access и автоматическое управление существующим firewall хоста не реализовано; правила устанавливаются отдельным административным скриптом и требуют согласования с политикой хоста. TURN credential refresh/recovery реализован: authenticated 401/441 и исчерпанный bounded 438 retry приводят к классификации пути для замены credentials; реальное поведение VK quota/rotation требует live-проверки.
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
