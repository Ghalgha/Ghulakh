# Текущий статус

Дата фиксации: 2026-11-10.

## Целевая функция

Основной и единственный транспорт первой версии — защищённый IP-туннель через TURN-реле инфраструктуры звонков VK (VK Calls). Текущий QUIC-туннель не является целевой реализацией и должен рассматриваться только как экспериментальный каркас.

## Что уже есть

- Rust workspace и общий протокольный crate.
- STUN codec: framing, method/class, TLV attributes, XOR address IPv4/IPv6, MESSAGE-INTEGRITY HMAC-SHA1/SHA-256, FINGERPRINT CRC-32; отдельный bounded parser TURN challenge 401/438.
- Экспериментальный QUIC-клиент и QUIC-сервер с TLS 1.3.
- Экспериментальная передача IP-датаграмм через QUIC DATAGRAM.
- Серверный IPv4 TUN, адресный пул, source-IP validation и базовая egress ACL.
- Android VpnService, JNI-мост к Rust-клиенту, Keystore-хранилище.
- CI-сборка Android и проверки Rust.
- Документация VPN/TUN-инфраструктуры и модели угроз.

## Ключевое, чего пока нет

- VK Calls credential provider.
- TURN client/allocation manager в Ghulakh.
- TURN long-term credential/key derivation и сетевой auth flow; bounded parser challenge 401/438 и request/response builders реализованы, но auth flow и allocation state machine пока не связаны.
- TURN UDP/TCP/TLS data path между Android-клиентом и серверным gateway.
- Вертикальный end-to-end срез одного allocation и обратного relay-пути.
- Защищённый data framing для целевого TURN-пути.
- Подтверждённый двусторонний relay routing и server-side session mapping.
- Fragmentation/reassembly, replay protection и управление потерями для TURN data path.
- Автоматическое восстановление allocation и обновление credentials.
- Интеграционные тесты полного TURN-пути.

Следовательно, текущая сборка не реализует главную функцию проекта и не должна позиционироваться как готовый VPN.

## Результаты исследования

README всех шести указанных пользователем исходных репозиториев подтверждают общий подход: передача защищённого туннельного трафика через TURN-инфраструктуру звонков VK. В реализациях встречаются TURN/DTLS и TURN/RTP-подходы, а также разные способы AEAD-упаковки и управления relay allocation.

Статический анализ отдельных исходников дополнительно выявил:
- TURN Allocate с username/password, полученными через VK call credentials;
- поддержание allocation, permission и channel binding;
- UDP и в некоторых вариантах TCP/TLS для клиентского соединения с TURN endpoint;
- RTP-подобное кадрирование и AEAD;
- DTLS-путь и отдельный путь с самостоятельной AEAD-защитой;
- серверный UDP gateway, принимающий данные, прошедшие через TURN relay.

Это не подтверждает, что все режимы доступны на текущей инфраструктуре VK Calls. Получение credentials, wire format и обратная адресация требуют полного анализа клиентского и серверного кода. Код исходных проектов в Ghulakh не переносился.

## Реализовано в STUN codec

- Декодирование и кодирование STUN header и transaction ID.
- Декодирование/кодирование method и class.
- Строгое ограничение message length, проверка magic cookie и TLV boundaries/padding.
- Сохранение неизвестных атрибутов.
- XOR address для IPv4 и IPv6.
- MESSAGE-INTEGRITY HMAC-SHA1: добавление и constant-time проверка с внешним ключом, включая корректную обработку следующего FINGERPRINT.
- FINGERPRINT CRC-32: добавление и проверка; не используется как аутентификация.
- Unit tests round-trip для STUN classes, integrity/fingerprint tampering, malformed framing, XOR address и challenge parser cases.

Кодек не является TURN-клиентом: long-term credential/key derivation, authentication challenge handling, transaction retries и allocation state machine ещё не реализованы. Integrity verification требует внешнего ключа и пока не встроена в сетевой приёмник. Сетевые сообщения нельзя считать аутентифицированными без обязательной проверки MESSAGE-INTEGRITY.

## Следующие этапы

1. Завершить статический аудит полного TURN data path и credential flow во всех исходных материалах.
2. Зафиксировать независимую спецификацию TURN session, data frame, crypto profile и server reverse path.
3. Определить правовой статус и лицензионные ограничения каждого технического источника; не копировать код без разрешения.
4. Реализовать VK Calls TURN allocation и data path в Rust, с mock peers и unit tests.
5. Реализовать серверный gateway и двустороннюю маршрутизацию.
6. Подключить Android VpnService к новому transport core через JNI.
7. Добавить fuzz/property tests, сетевую симуляцию и нагрузочные тесты.
8. Физические Android/VPS испытания — ближе к завершению проекта.

## Новые результаты статического аудита

- Серверный gateway в одном из исследованных raw-IP путей — обычный UDP listener с защищённым packet wrapper, а не собственный TURN server.
- Relay datagrams принимаются с UDP peer tuple TURN-реле; обратные пакеты отправляются на relay peer tuple, чтобы TURN allocation доставил их клиенту.
- Серверный TUN downlink маршрутизируется по назначенному клиентскому destination IP к одной из активных relay-сессий устройства.
- В сложных реализациях допускаются несколько allocation workers на устройство; балансировка и chunk scheduling должны появиться только после рабочего single-allocation пути.
- Один из современных Rust-клиентов содержит TURN control plane (Allocate/Refresh/CreatePermission/ChannelBind), UDP и framed stream transports, ChannelData framing, bounded queues и allocation lifecycle driver. Это клиентская реализация; наличие отдельного совместимого сервера в том же репозитории не предполагается.
- Текущая архитектура Ghulakh должна заменить QUIC connection registry на relay session registry и UDP gateway ingress для целевого data path.

Подробности: [Исследование двустороннего TURN data path](RELAY_PATH_FINDINGS.md).

## Физические испытания

Не проводились. Они отложены до завершения спецификации, локальных интеграционных тестов и проверок безопасности.


## TURN control plane

- Реализованы STUN framing/address/integrity primitives и bounded parser challenge 401/438.
- Добавлен UDP transaction manager с криптографически случайными transaction ID, строгим response matching, лимитом 10 outstanding requests на endpoint, retransmission schedule по RFC 8489 и детерминированными тестами.
- Пока отсутствуют socket integration, TURN credential acquisition/key derivation, Allocate/Refresh/CreatePermission/ChannelBind lifecycle и relay data plane. Профиль аутентификации VK Calls не считается подтверждённым.


### TURN request layer

Добавлены независимые конструкторы Allocate/Refresh/CreatePermission/ChannelBind и структурный разбор успешных Allocate/Refresh ответов. Они не подменяют проверку подлинности: вызывающий код обязан проверить совпадение transaction ID/method/source endpoint и MESSAGE-INTEGRITY до применения результата. VK Calls credential provider и конкретный алгоритм MESSAGE-INTEGRITY остаются не подтверждены.

- Добавлена поддержка `MESSAGE-INTEGRITY-SHA256` по RFC 8489 с полной 32-байтовой подписью, проверкой constant-time и тестом совместного расположения SHA-1 → SHA-256 → FINGERPRINT. Вывод ключа остаётся за внешним auth provider.


### TURN password algorithm attributes

- Added bounded parsing/encoding for RFC 8489 `PASSWORD-ALGORITHMS` and `PASSWORD-ALGORITHM`.
- Unknown algorithm identifiers are retained; duplicate IDs, malformed lengths, and oversized parameter blocks are rejected.
- Generic selection prefers SHA-256 when offered and otherwise MD5. This is protocol negotiation logic only, not evidence that VK Calls currently offers either algorithm.
- Credential normalization, key derivation, and VK Calls profile confirmation remain unimplemented.


### TURN allocation lifecycle

- Added an event-driven allocation manager for Allocate/Refresh state transitions.
- Tracks relayed address, granted lifetime, monotonic expiry and an 80%-lifetime refresh deadline.
- Rejects transaction mismatches and unexpected response types; supports refresh failure recovery and expiry/deletion.
- No socket integration, credentials, permission/channel binding lifecycle or data plane is implied by this state machine.
