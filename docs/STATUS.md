# Текущий статус

Дата фиксации: 2026-11-10.

## Целевая функция

Единственный транспорт первой версии — защищённый IP-туннель через TURN-реле инфраструктуры звонков VK (VK Calls). QUIC не является целевым транспортом и пока остаётся действующим экспериментальным путём в Android и сервере. До полной замены QUIC целевым TURN-путём приложение нельзя считать реализующим основную функцию.

## Реализованные компоненты

- STUN codec: framing, method/class, TLV attributes, XOR address IPv4/IPv6, MESSAGE-INTEGRITY HMAC-SHA1/SHA-256, FINGERPRINT CRC-32.
- Parser TURN challenge 401/438, включая PASSWORD-ALGORITHMS.
- Parser TURN credentials и TURN/TURNS URI с ограничениями размеров и redaction секретов.
- TURN transaction manager: случайные transaction ID, matching по endpoint/method/id, ограниченные retransmissions и лимит незавершённых запросов.
- Конструкторы Allocate/Refresh/CreatePermission/ChannelBind и parser успешных Allocate/Refresh ответов.
- Allocation state machine с lease, expiry, refresh deadline и обработкой неудачного refresh.
- Peer registry для permissions и channel bindings с expiry/cooldown.
- UDP adapter, включая принятие заранее созданного Android socket после `VpnService.protect(fd)`.
- Единый bounded TURN socket actor: один reader/writer task, раздельные control/data queues, классификация STUN/ChannelData/Data indications, явная drop-newest политика для data overload, сохранение исходных wire bytes и счётчики malformed/drop.
- TURN control driver поверх socket actor: Allocate/Refresh/CreatePermission/ChannelBind, matching ответов, MESSAGE-INTEGRITY verification, retransmission/timeout и изменение allocation/peer state только после принятого успешного ответа.
- TURN session supervisor: обработка 401/438 с ограниченными повторами, внешний `TurnAuthProvider`, планирование Refresh allocation и обновления permission/channel binding.
- TURN auth context с раздельными профилями password derivation и MESSAGE-INTEGRITY HMAC. Добавлен изолированный legacy VK Calls provider: MD5(username:realm:password) → HMAC-SHA1, по совпадающему подходу в трёх актуальных Rust-реализациях исходных репозиториев. Он отклоняет PASSWORD-ALGORITHMS offers, которые пока не подтверждены профилем VK. Vendor attribute 0x8021 не добавлен: его необходимость требует проверки на реальном relay. Этот provider обрабатывает TURN 401/438, но получение самих временных VK Calls credentials через VK API ещё не реализовано и live-профиль не подтверждён.
- Protected frame codec: directional AEAD, session ID, sequence numbers и replay window.
- Noise XX session handshake: pinned server static key, client credential внутри encrypted handshake message, encrypted server acknowledgement, HKDF-SHA256 directional frame keys. Реализована протокольная state machine поверх TURN handshake envelope: ClientInit → ServerResponse → ClientFinish → ServerAck, проверка handshake ID/phase, выдача frame keys клиенту только после проверки encrypted acknowledgement и серверу только после проверки credential. Отдельно реализованы deterministic retry driver с exact-byte retransmission, response matching без завершения до явного подтверждения после Noise-аутентификации, bounded per-peer/global pending limits, bounded exact-response cache и TTL. Socket actor распознаёт handshake payload внутри TURN ChannelData на клиентской стороне и передаёт его через отдельную bounded queue с drop counter. На клиентской стороне добавлен `run_turn_client_handshake`: единый task владеет Noise state, bounded retry driver и входящей handshake queue; проверяет source endpoint TURN-сервера, выполняет точные retransmissions через socket actor и завершает retry transaction только после успешной Noise-проверки ServerResponse/ServerAck. Он возвращает directional frame keys и конфигурацию туннеля (виртуальный IPv4 и MTU), полученную внутри encrypted ServerAck. На серверной стороне реализован bounded `TurnHandshakeService`: replay-cache lookup выполняется до Noise state advancement; точные ServerResponse/ServerAck кэшируются до отправки; действуют per-relay-tuple rate limits, TTL и ограничения активных рукопожатий. После проверки credential сервер включает в encrypted ServerAck назначенный виртуальный IPv4 и MTU; после помещения ServerAck в replay cache gateway регистрирует сессию до отправки ответа, исключая гонку с первым uplink-пакетом.
- Client TURN dataplane: bounded uplink/downlink queues, проверка relay source, ChannelData/channel, AEAD, session/direction/replay и формата IP-пакета. Доступен через `TurnSessionSupervisor::take_data_plane_parts()`.
- Server TURN gateway: принимает raw UDP payloads от TURN relay (TURN удаляет ChannelData framing на peer-facing стороне), выполняет Noise handshake, отправляет raw handshake response обратно на relay и после отправки ServerAck регистрирует session ID, назначенный виртуальный IPv4 и directional frame codecs. Защищённый dataplane проверяет relay source tuple, session ID, AEAD/replay и внутренний IPv4 source; uplink поступает в bounded TUN queue, downlink маршрутизируется по destination IPv4 на зарегистрированный relay tuple. Gateway подключён к server TUN lifecycle при заданных `GHULAKH_TURN_GATEWAY_BIND`, `GHULAKH_NOISE_PRIVATE_KEY` и `GHULAKH_NOISE_PUBLIC_KEY`; ключи читаются из hex-файлов, credential verifier использует существующий список SHA-256 digest. Это интеграция серверной стороны, но ещё не сквозной клиентский VPN.
- Mock UDP tests для TURN socket actor, client dataplane и server gateway; gateway tests используют raw peer-facing UDP payloads, включая интегрированный Noise handshake → encrypted session config → session registration → protected uplink. Отдельный mock control-plane test покрывает Allocate/Permission/ChannelBind/Refresh и клиентскую сторону ChannelData forwarding. Протокольные tests покрывают полный Noise XX обмен через handshake envelopes, mismatch handshake ID, отказ credential и передачу конфигурации туннеля внутри encrypted ServerAck.
- Экспериментальный QUIC-клиент/сервер, серверный TUN и Android VpnService/JNI-интеграция.

## Что эти компоненты пока не означают

Наличие codec, driver, supervisor и gateway core не означает, что сквозной VPN уже работает. Client dataplane и server gateway протестированы на loopback/mock UDP, но не связаны между собой через реальную TURN allocation, production TUN и единый authenticated session manager.

## Оставшиеся критические задачи

- Проверить текущий VK Calls credential flow и реализовать получение/обновление временных TURN credentials.
- Подтвердить фактический VK TURN authentication profile на реальном relay: normalization, legacy MD5 key derivation, MESSAGE-INTEGRITY HMAC-SHA1, необходимость vendor attribute 0x8021, поведение при PASSWORD-ALGORITHMS и rotation. Исходные Rust-реализации сходятся на MD5(username:realm:password) и HMAC-SHA1, но этого недостаточно для заявления о live-совместимости.
- Довести Noise XX до production: реализовать серверный handshake task с cache-before-state-advance/cache-before-send и duplicate suppression; добавить сетевой rate limiting/admission; добавить сетевой rate limiting/admission, persistent server key integration, pinned key distribution, credential verifier/rate limiting и session registry integration. Snow security review обязательна.
- Создать единый session manager, который связывает authenticated identity, назначенный virtual IPv4, TURN relayed address, channel binding и frame keys.
- Подключить server gateway к production server TUN reader/writer и проверенному session manager.
- Подключить client dataplane к Android TUN worker/JNI и protected TURN UDP socket.
- Удалить QUIC из production runtime Android/server после завершения и тестирования TURN vertical slice; fallback с TURN на QUIC не добавлять.
- Завершить сквозные mock-тесты Allocate → Permission → ChannelBind → protected uplink → gateway → protected downlink → TUN.
- Проверить MTU/fragmentation, IPv4/IPv6 scope, queue saturation, packet loss, replay, source spoofing, reconnect и credential rotation.
- Провести fuzz/property tests, сетевую симуляцию, нагрузочные и энергопотребительские измерения. Физические Android/VPS испытания — ближе к завершению проекта.

## Архитектурные решения

- Первая реализация — одна TURN allocation на устройство.
- Control plane и dataplane разделены; один socket actor владеет UDP socket и выполняет единственный receive loop.
- Все межзадачные очереди ограничены. Data overload использует явный drop-newest; control queue применяет backpressure.
- Packet pool/SPSC/ring buffer не вводить до benchmark: сравнивать throughput, loss, queue drops, CPU wakeups и память.
- Все retry ограничены и классифицируются по TURN/STUN error code.
- Сервер отвечает на фактический relay source tuple, заранее закреплённый при authenticated session registration. Не использовать адрес, извлечённый из незашифрованного IP payload.
- Key agreement, TURN credentials и TURN long-term authentication — отдельные security boundaries.

## Проверенные mock-сценарии

- Socket actor маршрутизирует STUN control и ChannelData/Data indications через один reader.
- Client dataplane передаёт защищённый IP packet через actor и принимает ответ с независимыми directional keys.
- Server gateway проверяет relay source tuple, channel, AEAD, inner source IP и replay; downlink отправляется на зарегистрированный relay tuple.
- Mock control-plane test моделирует Allocate, CreatePermission, ChannelBind, Refresh и двусторонний ChannelData forwarding.

Mock-тесты не являются испытаниями VK Calls и не доказывают совместимость с реальными VK TURN relay credentials, allocation policy или network behavior.

## Производительность и сравнительный аудит

При выборе реализации сравниваются одинаковые функции, владение ресурсами, количество копирований, очереди, wakeups, retry policy и устойчивость к перегрузке. Для первого среза выбраны bounded Tokio queues и один socket actor: это упрощает ownership и backpressure. Более сложные packet pools и ring buffers остаются кандидатами на последующие измерения; заявлений о превосходстве по скорости или энергопотреблению без benchmark не делается.

## Лицензирование

До переноса исходного кода требуется завершить проверку лицензий каждого источника. Сравнение архитектурных решений не даёт автоматического права копировать исходную реализацию.
