# Текущий статус

Дата фиксации: 2026-11-10.

## Целевая функция

Единственный поддерживаемый транспорт — защищённый VPN-туннель для IP-трафика через TURN-реле инфраструктуры звонков VK (VK Calls). TURN-реле выступает транспортным посредником; сервер Ghulakh является peer/gateway, а не TURN-сервером. На клиентской стороне TURN ChannelData используется между приложением и TURN-сервером. На peer-facing стороне TURN-сервер снимает ChannelData framing и пересылает gateway исходную UDP-нагрузку.

QUIC не является целевым транспортом. Его runtime на сервере выключен по умолчанию и может быть включён только явным GHULAKH_QUIC_ENABLED=true для временной диагностики. Android VPN service использует TURN runtime.

## Реализованные компоненты

- STUN codec: framing, method/class, TLV attributes, XOR address IPv4/IPv6, MESSAGE-INTEGRITY HMAC-SHA1/SHA-256, FINGERPRINT CRC-32.
- Parser TURN challenge 401/438, включая PASSWORD-ALGORITHMS.
- Parser TURN credentials и TURN/TURNS URI с ограничениями размеров и redaction секретов.
- TURN transaction manager: случайные transaction ID, matching по endpoint/method/id, ограниченные retransmissions и лимит незавершённых запросов.
- Конструкторы Allocate/Refresh/CreatePermission/ChannelBind и parser успешных Allocate/Refresh ответов.
- Allocation state machine с lease, expiry, refresh deadline и обработкой неудачного refresh.
- Peer registry для permissions и channel bindings с expiry/cooldown.
- UDP adapter, включая принятие заранее созданного Android socket после VpnService.protect(fd).
- Единый bounded TURN socket actor: один reader/writer task, раздельные control/data/handshake queues, классификация STUN/ChannelData/Data indications, явная drop-newest политика для data overload, сохранение исходных wire bytes и счётчики malformed/drop.
- TURN control driver и session supervisor: Allocate/Refresh/CreatePermission/ChannelBind, matching ответов, MESSAGE-INTEGRITY verification, 401/438 retry, обновление allocation/permission/channel binding.
- Изолированный legacy VK Calls TURN auth provider: MD5(username:realm:password) → HMAC-SHA1, по совпадающему подходу в трёх актуальных Rust-реализациях исходных репозиториев. Он отклоняет PASSWORD-ALGORITHMS offers, пока не подтверждён профиль VK. Vendor attribute 0x8021 намеренно не добавлен: его необходимость требует live-проверки. Этот provider не доказывает live-совместимость с relay.
- Protected frame codec: directional AEAD, session ID, sequence numbers и replay window.
- Noise XX session handshake: pinned server static key, client credential внутри encrypted handshake message, encrypted server acknowledgement, HKDF-SHA256 directional frame keys. Конфигурация сессии (виртуальный IPv4 и MTU) передаётся внутри encrypted ServerAck.
- Клиентский run_turn_client_handshake: единый task владеет Noise state, bounded retry driver и отдельной incoming handshake queue; проверяет relay endpoint и завершает transaction только после проверки Noise authentication и encrypted ServerAck.
- Серверный TurnHandshakeService: bounded active handshakes, per-relay-tuple rate limits, TTL и exact-response replay cache. Cache lookup выполняется до Noise state advancement; ServerResponse/ServerAck кэшируются до отправки. Неверный credential удаляет использованное Noise state.
- Server TURN gateway интегрирован с UDP receive loop и TUN lifecycle. Он принимает raw UDP peer payloads, обрабатывает handshake, регистрирует session после cache ServerAck и до отправки ответа (чтобы исключить гонку с первым uplink), проверяет relay source tuple, session ID, AEAD/replay и внутренний IPv4 source. Uplink поступает в bounded TUN queue; downlink маршрутизируется по назначенному destination IPv4 на зарегистрированный relay tuple. Клиент отправляет authenticated keepalive каждые 5 минут; idle sessions удаляются после 10 минут без authenticated traffic, адреса возвращаются в bounded virtual-IP allocator.
- Сервер загружает постоянную Noise keypair из hex-файлов и проверяет совпадение публичной/приватной частей. Добавлена команда ghulakh-server --generate-noise-keypair <private-hex-file> <public-hex-file>; private key создаётся с правами 0600 без перезаписи существующих файлов.
- Высокоуровневый TurnClientRuntime: protected UDP socket → Allocate → Permission → ChannelBind → Noise handshake → authenticated tunnel config → bounded bidirectional dataplane; allocation/peer refresh работает отдельной задачей.
- JNI-интерфейс Android для подключения, передачи и приёма IP-пакетов, получения виртуального IPv4/MTU и закрытия TURN-сессии.
- Android VpnService использует TURN runtime, защищает UDP socket через VpnService.protect(fd), настраивает TUN из authenticated session config и передаёт IP-пакеты в native dataplane.
- Android VkCallsCredentialProvider получает временные credentials через messages.getCallToken, auth.anonymLogin, vchat.startConversation и vchat.getConversationParams; при завершении вызывает vchat.hangupConversation. HTTP использует обычный HTTPS без имитации браузерного TLS fingerprint. VK access token, tunnel credential и pinned Noise key хранятся зашифрованными Android Keystore. Временные TURN credentials заново запрашиваются при каждом подключении.
- Mock UDP tests покрывают socket actor, client dataplane, server gateway и интегрированный Noise handshake → encrypted session config → session registration → protected uplink. Отдельный mock control-plane test покрывает Allocate/Permission/ChannelBind/Refresh и клиентскую ChannelData forwarding.

## Ограничения текущего этапа

Наличие компонентов и успешных mock-тестов не доказывает совместимость с реальными VK Calls API, TURN allocation policy или relay network behavior. Физические Android/VPS испытания намеренно отложены до завершения программной вертикали.

Android пока требует вручную предоставить пользовательский VK access token; встроенный OAuth/login flow не реализован. VK Calls API flow и legacy TURN authentication profile не проверены на реальном аккаунте/relay. Не подтверждены необходимость vendor attribute 0x8021, поведение PASSWORD-ALGORITHMS и ротация TURN credentials.

Сквозной тест реального TURN allocation → handshake → protected uplink/downlink → Android TUN ещё не выполнен. На сервере и клиенте компоненты собраны, но их совместная работа пока подтверждена отдельными mock-сценариями, а не реальным VK relay.

Туннель первой версии передаёт IPv4. Android захватывает IPv6 для предотвращения утечки, но серверный gateway не маршрутизирует IPv6.

## Оставшиеся критические задачи

- Проверить VK API credential flow на тестовом аккаунте, не логируя access token, call token, session key или TURN credentials; проверить завершение call при штатном отключении и ошибках.
- Подтвердить реальный TURN auth profile: username/password normalization, MD5 long-term key, HMAC-SHA1, vendor attribute 0x8021, PASSWORD-ALGORITHMS и credential rotation. Не включать непроверенные атрибуты/алгоритмы на основании одного исходного варианта.
- Добавить надёжное получение/обновление VK access token (OAuth UI) без scraping cookies и обхода CAPTCHA.
- Проверить lifecycle server TUN, IP forwarding/NAT/firewall и session cleanup под нагрузкой.
- Завершить end-to-end mock test полного пути через mock TURN relay: Allocate → Permission → ChannelBind → Noise handshake → protected uplink → server TUN → protected downlink → client TUN.
- Добавить fuzz/property tests, network loss/reorder simulation, queue saturation, MTU/fragmentation, replay, source spoofing, reconnect и credential rotation.
- Провести security review Noise/session protocol; библиотека Snow не заявляется как формально аудированная.
- Удалить остаточный QUIC runtime и код после успешного TURN vertical slice и тестирования; TURN→QUIC fallback не добавлять.
- Провести физические Android/VPS испытания ближе к завершению проекта, затем измерить throughput, loss, CPU wakeups, энергопотребление и память.

## Архитектурные решения

- Первая реализация — одна TURN allocation на устройство.
- Control plane, handshake и dataplane разделены; один socket actor владеет UDP socket и выполняет единственный receive loop.
- Межзадачные очереди ограничены. Data overload использует явный drop-newest; control queue применяет backpressure.
- Packet pool/SPSC/ring buffer не вводить до benchmark: сравнивать throughput, loss, queue drops, CPU wakeups и память.
- Все retry ограничены и классифицируются по TURN/STUN error code.
- Сервер отвечает на фактический relay source tuple, закреплённый при authenticated session registration. Не использовать адрес, извлечённый из незашифрованного IP payload.
- Key agreement, VK access token, временные TURN credentials, TURN long-term authentication и tunnel credential — отдельные security boundaries.

## Сравнительный аудит и производительность

Одинаковые функции в исходных реализациях сравниваются по владению ресурсами, количеству копирований, очередям, wakeups, retry policy и устойчивости к перегрузке. В актуальных Rust-реализациях источников обнаружен общий legacy-профиль MD5(username:realm:password) + HMAC-SHA1; vendor attribute 0x8021 требует отдельного подтверждения. Для peer-facing datapath выбран raw UDP payload, поскольку TURN снимает ChannelData framing перед пересылкой пиру.

Для первого среза выбраны bounded Tokio queues и один socket actor: это упрощает ownership и backpressure. Более сложные packet pools и ring buffers остаются кандидатами на последующие измерения; заявлений о превосходстве по скорости или энергопотреблению без benchmark не делается.

## Лицензирование

До переноса исходного кода требуется завершить проверку лицензий каждого источника. Сравнение архитектурных решений не даёт автоматического права копировать исходную реализацию.
