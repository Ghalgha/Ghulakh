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
- TURN auth context с раздельными профилями password derivation и MESSAGE-INTEGRITY HMAC. Integrity key передаётся извне; автоматическое получение/выведение из VK credentials не реализовано.
- Protected frame codec: directional AEAD, session ID, sequence numbers и replay window.
- Noise XX session handshake primitive: pinned server static key, client credential внутри encrypted handshake message, encrypted server acknowledgement, HKDF-SHA256 directional frame keys. Не подключён к TURN datagram transport/session registry; UDP reliability envelope ещё не реализован.
- Client TURN dataplane: bounded uplink/downlink queues, проверка relay source, ChannelData/channel, AEAD, session/direction/replay и формата IP-пакета. Доступен через `TurnSessionSupervisor::take_data_plane_parts()`.
- Server TURN gateway core: lookup по session ID, проверка зарегистрированного relay source tuple и channel, AEAD/replay, проверка внутреннего IPv4 source, bounded TUN-ingress queue и downlink на зарегистрированный relay tuple. Реализован в `server/src/turn_gateway.rs`, но пока не включён в production server TUN/session lifecycle.
- Mock UDP tests для TURN socket actor, client dataplane и server gateway; отдельный mock control-plane test покрывает Allocate/Permission/ChannelBind/Refresh и ChannelData forwarding.
- Экспериментальный QUIC-клиент/сервер, серверный TUN и Android VpnService/JNI-интеграция.

## Что эти компоненты пока не означают

Наличие codec, driver, supervisor и gateway core не означает, что сквозной VPN уже работает. Client dataplane и server gateway протестированы на loopback/mock UDP, но не связаны между собой через реальную TURN allocation, production TUN и единый authenticated session manager.

## Оставшиеся критические задачи

- Проверить текущий VK Calls credential flow и реализовать получение/обновление временных TURN credentials.
- Подтвердить фактический VK TURN authentication profile: normalization, password derivation, MESSAGE-INTEGRITY key и поведение при rotation. Нельзя предполагать совместимость профиля только по RFC или fixture-тестам.
- Довести Noise XX до production: TURN datagram retransmission/duplicate suppression, persistent server key, pinned key distribution, credential verifier/rate limiting и session registry integration. Snow security review обязательна.
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
