# Протокол: начальная спецификация

Статус: draft, не является стабильным wire-стандартом.

## Текущий статус транспорта

Целевой транспорт первой версии — защищённый IP-туннель через TURN-реле инфраструктуры звонков VK (VK Calls). QUIC-формат ниже сохранён только как описание экспериментального прототипа и не должен использоваться для передачи пользовательских IP-пакетов в целевой конфигурации.

В `ghulakh-protocol::stun` реализован начальный ограниченный STUN framing codec: заголовок, transaction ID, class/method, TLV attributes с padding и XOR-MAPPED/XOR-RELAYED address encoding/decoding для IPv4/IPv6. Кодек реализует MESSAGE-INTEGRITY на HMAC-SHA1 с внешним ключом и FINGERPRINT на CRC-32. Он не выводит long-term ключи, не реализует TURN transaction state machine, TLS/DTLS, allocation lifecycle или сетевой обмен и не является готовым TURN-клиентом.

Следующие обязательные компоненты: подтверждение фактического TURN credential/auth profile VK Calls, Allocate/Refresh/CreatePermission/ChannelBind state machine, relay data channel, затем gateway reverse path. Для криптографических операций использовать audited crates, не самописные реализации.

## Экспериментальный QUIC прототип (не целевой транспорт)

- QUIC и TLS 1.3 реализуют шифрование, целостность, согласование ключей и защиту транспорта от replay. Сервер и клиент используют Quinn 0.11.12 и явно фиксируют quinn-proto 0.11.19.
- ALPN: `ghulakh/1`.
- Клиент обязан проверить цепочку сертификата и имя сервера либо закреплённый доверенный ключ.
- Отключение проверки сертификата запрещено.
- 0-RTT для изменяющих состояние команд отключён.

## Экспериментальный QUIC управляющий поток v1

Каждое управляющее сообщение передаётся в отдельном QUIC bidirectional stream. Клиент закрывает свою сторону отправки после одного JSON envelope; сервер читает не более 16 KiB, проверяет структуру и отвечает в том же stream.

Envelope:

```json
{
  "version": 1,
  "message": {
    "type": "client_hello",
    "body": {
      "credential": "<per-device random secret>",
      "request_id": "client-generated-id"
    }
  }
}
```

Пример ответа сервера:

```json
{
  "version": 1,
  "message": {
    "type": "server_hello",
    "body": {
      "session_id": "<random-session-id>",
      "client_ipv4": "10.77.0.2",
      "tunnel_enabled": false,
      "forwarding_enabled": false,
      "request_id": "client-generated-id"
    }
  }
}
```

Поддерживаемые типы:
- `client_hello` — аутентификация клиента;
- `server_hello` — подтверждение аутентификации, случайный идентификатор сессии, назначенный IPv4-адрес, признак доступности серверного TUN и административное подтверждение готовности IP forwarding/NAT/firewall;
- `ping` / `pong` — проверка управляющего канала;
- `close` — закрытие соединения.

В каждом сообщении обязателен непустой `request_id` длиной не более 128 байт. Размер тела ограничен 16 KiB. Неизвестная версия, некорректный JSON, неожиданный тип сообщения и превышение лимита приводят к отказу соединения.

## Идентификация

Каждое устройство получает уникальный случайный credential размером 256 бит. Сервер принимает credential длиной от 1 до 256 байт и хранит SHA-256 digest credential в файле, заданном через `GHULAKH_CREDENTIAL_HASHES`, по одному 64-символьному hex digest на строку. Пустые строки и строки-комментарии, начинающиеся с `#`, игнорируются. Сравнение выполняется с constant-time equality.

Credential передаётся только внутри аутентифицированного TLS 1.3/QUIC соединения. Его запрещено помещать в URL, логи, crash reports или открытые конфигурационные файлы. Для отзыва credential соответствующий digest удаляется из файла, после чего сервер перезапускается.

## Экспериментальный формат QUIC DATAGRAM v1

Пользовательские IP-пакеты передаются в QUIC DATAGRAM. QUIC DATAGRAM сохраняет защиту TLS/QUIC, но не гарантирует доставку и порядок пакетов.

| Смещение | Размер | Поле |
|---:|---:|---|
| 0 | 4 байта | Magic ASCII `GHLK` |
| 4 | 1 байт | Версия формата: `1` |
| 5 | 1 байт | Тип IP: `4` IPv4 или `6` IPv6 |
| 6 | 2 байта | Длина IP-пакета, unsigned big-endian |
| 8 | переменный | Полный IP-пакет |

Максимальный размер всего datagram — 1200 байт, включая 8-байтовый заголовок. Пакет должен быть непустым, его версия IP должна совпадать с типом в заголовке, а объявленная длина — точно соответствовать фактической. Отправитель дополнительно обязан проверять лимит `max_datagram_size`, сообщаемый QUIC-соединением: он может быть меньше 1200 байт.

Общий crate реализует кодирование и декодирование. Сервер принимает QUIC DATAGRAM только после аутентификации, ограничивает буфер, проверяет framing и source IPv4 клиента. При включённом серверном TUN пакеты проходят базовую egress ACL и направляются через ограниченную очередь в TUN. Обратные IPv4-пакеты маршрутизируются по назначенному адресу клиента и отправляются через QUIC DATAGRAM. Адреса клиентских сессий не переиспользуются до перезапуска сервера. Egress ACL блокирует частные, loopback, link-local, multicast, broadcast, unspecified, CGNAT и часть зарезервированных диапазонов. Сервер пересылает клиентские пакеты только при одновременном `GHULAKH_TUN_ENABLED=true` и `GHULAKH_FORWARDING_ENABLED=true`; иначе пакеты проверяются и отбрасываются.

## Совместимость

Изменения wire-формата сопровождаются увеличением версии или согласованным расширением. Неизвестные типы сообщений и несовместимые версии отклоняются. Необязательные расширения JSON пока не определены.


## STUN/TURN codec v0 (начальная реализация)

STUN сообщения используют 20-байтовый заголовок: 14-битный method/class type, длину тела в байтах, magic cookie `0x2112A442` и 96-битный transaction ID. Attributes кодируются как TLV с 32-битным выравниванием; padding не включается в объявленную длину атрибута.

Реализованы разбор и сериализация сообщения, сохранение неизвестных атрибутов, поиск атрибута по типу и XOR address для IPv4/IPv6. В кодеке определены базовые TURN method identifiers: Allocate, Refresh, Send, Data, CreatePermission и ChannelBind.

Кодек проверяет:
- минимальную длину заголовка и точное соответствие body length;
- нулевые старшие два бита STUN message type;
- magic cookie;
- кратность длины тела четырём;
- границы каждого TLV и padding;
- допустимые family и длину XOR address.

MESSAGE-INTEGRITY проверяется HMAC-SHA1 с constant-time MAC verification. FINGERPRINT проверяется CRC-32 и служит только для обнаружения повреждений, а не для аутентификации. Проверка MESSAGE-INTEGRITY требует заранее выведенного ключа; механизм его вывода и согласование auth profile с VK Calls ещё не реализованы. До проверки MESSAGE-INTEGRITY сообщения от сети нельзя считать аутентифицированными. Приём STUN-пакета сам по себе не должен менять состояние allocation; state transition разрешается только после проверки transaction ID, ожидаемого method, source endpoint и integrity согласно выбранному TURN auth profile.


### Integrity primitives

- `append_message_integrity` добавляет MESSAGE-INTEGRITY с HMAC-SHA1; ключ передаётся вызывающей стороной.
- `verify_message_integrity` проверяет единственный MESSAGE-INTEGRITY, допускает следующий за ним final FINGERPRINT и корректно учитывает STUN header length при вычислении HMAC.
- `append_fingerprint` и `verify_fingerprint` реализуют CRC-32 XOR 0x5354554e. FINGERPRINT не является аутентификацией.
- Проверка HMAC выполняется constant-time через криптографическую библиотеку.

TURN challenge parser (401/438) реализован отдельно от credential derivation. Модуль `ghulakh_protocol::turn_transaction` реализует ограниченный UDP transaction manager: случайные 96-битные ID через системный генератор, лимит 10 незавершённых запросов на endpoint, сопоставление ответа по ID/method/source endpoint, RFC 8489 retransmission schedule (500 ms initial RTO, 7 отправок, финальное ожидание 16×RTO), отмену и маркировку повторно отправленных транзакций для Karn's algorithm. Он не выполняет socket I/O, не проверяет MESSAGE-INTEGRITY сам и не реализует TURN allocation lifecycle.


### TURN authentication challenge parser

Модуль `ghulakh_protocol::turn_auth` извлекает ограниченные по размеру challenge-ответы 401 и 438 для ожидаемого метода. Он проверяет класс/метод ответа, формат ERROR-CODE, уникальность ERROR-CODE/REALM/NONCE, UTF-8 и границы длины текстовых атрибутов. Вызывающий TURN transaction manager обязан до принятия challenge сопоставить transaction ID и адрес источника с ожидающим запросом.

Парсер не выводит ключ, не выбирает PASSWORD-ALGORITHM и не считает challenge доказательством подлинности сервера. Эти решения остаются за будущим auth provider после подтверждения фактического профиля TURN endpoint.


### TURN transaction manager

Менеджер транзакций является детерминированным механизмом состояния без собственного сокета и таймера. Вызывающий код отправляет исходный STUN Request, периодически вызывает `poll()` и исполняет возвращённые retransmit-события. Входящий ответ передаётся в `accept_response()`; совпадение transaction ID, method и source endpoint необходимо, но недостаточно: вызывающий код обязан проверить MESSAGE-INTEGRITY согласно согласованному профилю до изменения состояния TURN. Для UDP используются параметры по умолчанию RFC 8489: RTO 500 мс, всего 7 отправок и финальное ожидание 8 секунд после последней отправки (общий примерный тайм-аут 39,5 секунды).

### TURN request builders and response parsing

`ghulakh_protocol::turn_request` provides constructors for Allocate (mandatory UDP REQUESTED-TRANSPORT), Refresh (including lifetime zero for deletion), CreatePermission (one or more peer addresses of a single address family), and ChannelBind (channel range 0x4000–0x7fff). It also parses successful Allocate/Refresh responses and checks required XOR-RELAYED-ADDRESS/LIFETIME attributes. The module deliberately does not add credentials or MESSAGE-INTEGRITY: the caller must use the negotiated auth provider and verify response integrity before parsing or applying state changes.

The codec supports RFC 8489 `MESSAGE-INTEGRITY-SHA256` (full 32-byte HMAC) in addition to the legacy `MESSAGE-INTEGRITY` HMAC-SHA1. Both APIs accept an already-derived key and do not select a credential algorithm or derive TURN credentials. When both integrity attributes are present, SHA-1 precedes SHA-256 as shown in the TURN example; verification supports that layout and an optional final FINGERPRINT.


### TURN password-algorithm negotiation

The protocol crate now parses RFC 8489 `PASSWORD-ALGORITHMS` and `PASSWORD-ALGORITHM` values with strict length bounds, duplicate-ID rejection, and preservation of unknown algorithm identifiers. Selection prefers SHA-256 when offered and falls back to MD5 only when SHA-256 is absent. The module only models and encodes negotiation attributes: it does not derive long-term credential keys, infer the VK Calls authentication profile, or authorize use of an algorithm without explicit service-profile confirmation.


### TURN allocation lifecycle

The protocol crate exposes an event-driven allocation state machine with Idle, AwaitingAllocate, Active, and AwaitingRefresh states. It accepts only matching transaction IDs and typed Allocate/Refresh results, tracks the granted relayed address and expiry, schedules refresh at 80% of the granted lifetime, restores a still-valid lease after a failed refresh, and retires expired or explicitly deleted allocations. It performs no network I/O and assumes the caller has already matched the response source/method/transaction and verified MESSAGE-INTEGRITY.


TURN 401 challenge parsing also preserves a valid raw `PASSWORD-ALGORITHMS` offer and exposes it as an attribute for the authenticated retry. This is required by RFC 8489 downgrade protection: the client must echo the server's offer in the next authenticated request. The opaque NONCE is retained unchanged; its service-specific security bits are not interpreted by this layer.


### TURN ChannelData framing

The UDP ChannelData codec validates the current RFC 8656 channel range `0x4000–0x4FFF`, exact declared payload length, and the UDP payload bound. It accepts both unpadded datagrams and the optional 0–3 bytes of padding permitted for UDP. The codec does not decide whether a channel is bound or whether its peer permission is active; those checks belong to the allocation/session layer.


### Protected data frames

The protocol crate includes an AEAD frame codec using ChaCha20-Poly1305. A frame authenticates its magic/version marker, session identifier, direction, sequence number, and payload length as associated data. Nonces are formed from a caller-supplied 32-bit per-direction prefix and a 64-bit monotonic sequence. The receiver enforces a 128-packet replay window and commits sequence state only after successful authentication.

The codec requires independent directional keys and nonce prefixes from a future authenticated session key agreement. It does not derive keys from TURN credentials, does not implement the key agreement, and is not yet connected to the Android TUN, TURN socket, or server gateway.


### TURN peer permission and channel state

The allocation-scoped peer registry tracks permissions by peer IP and channel bindings by peer transport address/channel number. It models the RFC 8656 permission lifetime of 300 seconds, channel-binding lifetime of 600 seconds, uniqueness in both directions, and the 300-second cooldown before reusing an expired channel number or peer address. A successful ChannelBind is recorded as also installing/refreshing the corresponding IP permission. The registry is updated only after the caller has authenticated and accepted a successful response.


### TURN UDP socket adapter

The transport crate now provides a Tokio UDP socket adapter that sends STUN/TURN control datagrams and ChannelData messages to one configured TURN endpoint, preserves the source address of received datagrams, and can adopt a pre-bound standard UDP socket. Android integration is expected to create and protect that socket with `VpnService.protect(fd)` before handing it to the adapter. The adapter does not yet perform TURN authentication, transaction scheduling, allocation management, or relay session establishment.
