# Текущий статус

Дата фиксации: 2026-11-10.

## Целевая функция

Единственный транспорт первой версии — защищённый IP-туннель через TURN-реле инфраструктуры звонков VK (VK Calls). QUIC не является целевым транспортом и пока остаётся действующим экспериментальным путём в Android и сервере; до завершения замены приложение нельзя считать реализующим целевую функцию.

## Реализованные строительные блоки

- STUN codec: framing, method/class, TLV attributes, XOR address IPv4/IPv6, MESSAGE-INTEGRITY HMAC-SHA1/SHA-256, FINGERPRINT CRC-32.
- Ограниченный parser TURN challenge 401/438, включая PASSWORD-ALGORITHMS.
- Парсер TURN credentials и URI: ограничение размеров, redaction Debug, Zeroizing для username/password.
- TURN transaction manager: случайные transaction ID, matching по endpoint/method/id, retransmission policy и лимит незавершённых запросов.
- Конструкторы Allocate/Refresh/CreatePermission/ChannelBind и parser успешных Allocate/Refresh ответов.
- Allocation state machine с lease, expiry, refresh deadline и обработкой неудачного refresh.
- Peer registry для permissions и channel bindings с expiry и cooldown; он обновляется только после подтверждённого вызывающим кодом успеха.
- UDP adapter для STUN/TURN datagrams и ChannelData; умеет принимать заранее созданный и защищённый Android socket.\n- Отдельный bounded TURN socket actor: единственный reader/writer task, классификация STUN control / ChannelData / Data indications, bounded control/data queues, drop-newest для перегруженной data queue и счётчики malformed/drop.
- Асинхронный TURN control driver: сериализованные Allocate/Refresh/CreatePermission/ChannelBind transactions, точное сопоставление endpoint/method/transaction ID, ограниченные retransmissions/timeouts, проверка MESSAGE-INTEGRITY для успешных ответов и authenticated 438, возврат начального 401 challenge вызывающему слою, обновление allocation/peer state только после успешной проверки.
- TURN session supervisor: автоматическая обработка первоначального 401 и проверенного 438 с ограничением до трёх повторов; отдельный TurnAuthProvider; автоматическое планирование Refresh allocation, CreatePermission и ChannelBind до их сроков истечения; единый владелец control driver. Peer registry предоставляет точные deadlines для permission/channel.
- TURN auth context для USERNAME/REALM/NONCE и MESSAGE-INTEGRITY HMAC-SHA1/SHA-256 с явно переданным integrity key; отдельные параметры password derivation и HMAC, сохранение и точное эхо PASSWORD-ALGORITHMS из challenge, выбор PASSWORD-ALGORITHM по RFC 8656: SHA-256 при совместном предложении MD5/SHA-256 и поддержке обоих клиентом; иначе — первый поддерживаемый алгоритм в порядке серверного списка и проверка согласованности выбранного алгоритма. Ключ не выводится из VK credentials автоматически.
- Codec защищённых кадров поверх TURN ChannelData с AEAD и защитой от replay.
- Экспериментальный QUIC-клиент/сервер, серверный TUN и Android VpnService/JNI-интеграция.

Эти компоненты являются библиотечными примитивами и моделями состояния. Их наличие не означает, что сетевой TURN driver или сквозной туннель уже собран.

## Зафиксированное проектирование

- `docs/TURN_DRIVER_DESIGN.md` описывает ownership единственной allocation, сериализацию control state, обработку 401/438, границу credential/auth providers, data path, bounded queues и критерии готовности вертикального среза.
- Выбран bounded Tokio queue + один control owner для первого среза. SPSC/ring buffer и packet pool остаются кандидатами для benchmark, а не преждевременной оптимизацией.

## Что ещё не реализовано в целевом пути

- Реальное получение и обновление VK Calls credentials.
- Подтверждённый профиль TURN-аутентификации VK: нормализация строк, derivation MESSAGE-INTEGRITY key и обработка credential rotation. Auth context пока требует явно предоставленный ключ; реальный обмен VK не подтверждён.
- Автоматическое получение/обновление VK Calls credentials и ограниченный reconnect. Supervisor уже обрабатывает TURN 401/438 и обслуживает сроки allocation/permission/channel, но credential rotation и восстановление после потери allocation ещё не реализованы. Socket actor уже добавлен и протестирован отдельно, однако пока не подключён к TurnClientDriver: driver всё ещё читает socket во время отдельной control-операции, поэтому ChannelData пока нельзя принимать непрерывно параллельно с control-транзакциями.
- Согласование и аутентифицированный обмен отдельными tunnel session keys. TURN credentials не являются ключами шифрования IP-трафика.
- Серверный UDP gateway, принимающий защищённые кадры от relay и отправляющий ответы на фактический relay source tuple.
- Привязка server-side tunnel session к назначенному IP и проверенной relay-сессии.
- Android TUN worker, работающий через TURN driver и socket, защищённый VpnService.protect().
- Полный mock-relay integration test: Allocate → Permission/ChannelBind → uplink → gateway → downlink → TUN.
- Проверки MTU/fragmentation, очередей, backpressure, reconnect, потерь и длительной стабильности.

## Архитектурные решения по производительности и устойчивости

- Начинать с одного allocation на устройство. Многоканальность добавлять только после корректного single-allocation пути и измерений.
- Использовать bounded queues с явной политикой backpressure; не допускать неограниченного роста памяти.
- Предпочитать event-driven wakeups вместо периодического polling там, где это не ухудшает latency.
- Не фиксировать крупные socket buffers без измерений: сравнивать throughput, packet loss, queue drops, CPU wakeups и память.
- Сохранять один выделенный receive loop на allocation и сериализовать критические TURN control transitions. Новый socket actor реализует single-reader основу, но до интеграции с driver это архитектурное свойство ещё не обеспечено всем клиентским путём.
- Любой retry должен быть ограниченным, классифицировать STUN-код/тип ошибки и не повторять бесконечно заведомо невалидные credentials.
- Не включать дополнительные allocations и дублирование пакетов до измерения энергопотребления и влияния на порядок TCP-потоков.

## Статус действующего приложения

- Android VpnService сейчас вызывает QUIC JNI API.
- JNI bridge создаёт QUIC client и отправляет IP packets через QUIC DATAGRAM.
- Серверный основной путь принимает QUIC connections и маршрутизирует IP-пакеты через серверный TUN.
- TURN UDP adapter и TURN data codec пока не подключены к Android TUN или серверному gateway.
- Автоматического fallback с TURN на QUIC в целевой архитектуре быть не должно.

Следовательно, текущая сборка не реализует основную функцию проекта и не должна позиционироваться как готовый TURN VPN.

## Mock TURN control-plane

Добавлен integration test `crates/transport/tests/mock_turn_relay.rs`: UDP mock relay обрабатывает Allocate (UDP), CreatePermission, ChannelBind и Refresh, затем пересылает ChannelData в gateway и инкапсулирует ответ gateway обратно в ChannelData клиенту. Проверяется порядок Permission перед ChannelBind, успешный uplink/downlink и Refresh с lifetime=0. Это тестовая модель control/data plane, а не production TURN server: в ней намеренно отсутствуют long-term authentication/MESSAGE-INTEGRITY, реальные relay allocations, permission expiry timers, TCP/TLS и взаимодействие с VK Calls.

## Текущий тестовый срез

Добавлен loopback UDP test в `crates/transport/src/turn_data.rs`: клиентский защищённый ChannelData проходит через relay forwarder к gateway, gateway проверяет ClientToServer AEAD frame и отвечает на наблюдаемый relay source tuple, relay возвращает ServerToClient frame клиенту. Проверяются оба направления и раздельные directional keys. Это тест data-plane forwarding; он не эмулирует TURN Allocate/Refresh/CreatePermission/ChannelBind и не доказывает совместимость с VK Calls.

## План ближайшего вертикального среза

1. Интегрировать bounded socket actor с TURN driver: один reader, транзакционный dispatcher и отдельный потребитель data queue.
2. Реализовать локальный mock TURN relay с Allocate/Refresh/Permission/ChannelBind и relay forwarding.
3. Реализовать клиентский driver поверх существующих STUN/TURN примитивов; каждое состояние менять только после matching и MESSAGE-INTEGRITY verification.
4. Реализовать серверный UDP gateway с аутентификацией кадров и обратной отправкой на relay source tuple.
5. Пройти mock end-to-end путь с тестовыми IP-пакетами и проверкой replay, source spoofing, malformed frames, queue saturation и reconnect.
6. Подключить Android VpnService/JNI к TURN driver; убрать QUIC из production path и оставить его только вне целевой сборки либо удалить.
7. Выполнить fuzz/property tests, сетевую симуляцию и нагрузочные/энергетические измерения.
8. Физические Android/VPS испытания провести ближе к завершению проекта.

## Лицензирование

До переноса исходного кода необходимо завершить проверку лицензий каждого источника. Технические решения могут быть сравнены, но наличие исходного кода в публичном репозитории само по себе не даёт права копировать его реализацию.
