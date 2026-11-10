# Проектирование TURN client driver

## Назначение

Документ фиксирует границы первого рабочего TURN-клиента. Поддерживается только UDP TURN endpoint, полученный из VK Calls `turn_server`. TCP/TLS endpoint не должен незаметно подменяться UDP и не входит в текущий вертикальный срез.

## Владение состоянием

Одна allocation на устройство. Один управляющий driver владеет:

- UDP socket и его единственным receive loop;
- transaction manager;
- allocation lifecycle;
- permission/channel registry;
- выбранным peer gateway и номером канала;
- ограниченными очередями ingress/egress;
- текущим auth context и состоянием nonce.

Другие задачи не изменяют TURN state напрямую. Они передают команды driver через bounded command channel и получают результат через oneshot/watch. Это исключает гонки между Allocate, Refresh, CreatePermission, ChannelBind и reconnect.

## Порядок запуска

1. Получить временные VK Calls credentials через отдельный `TurnCredentialProvider`.
2. Выбрать только поддерживаемый UDP endpoint; сохранить username/password в zeroizing контейнерах.
3. Создать UDP socket. На Android вызвать `VpnService.protect(fd)` до передачи сокета в Tokio.
4. Отправить Allocate с Requested-Transport=UDP.
5. Обработать первоначальный 401 challenge: проверить transaction ID, method и source endpoint; извлечь ровно один REALM и NONCE.
6. Выбрать только явно поддержанный сервисным профилем алгоритм и получить integrity key через отдельный `TurnAuthProvider`.
7. Повторить Allocate с USERNAME, REALM, NONCE и MESSAGE-INTEGRITY.
8. При 438 Stale Nonce проверять целостность ответа, обновлять nonce и повторять запрос с ограниченным числом попыток.
9. После integrity-verified Allocate success установить lease и XOR-RELAYED-ADDRESS.
10. Выполнить CreatePermission для IP gateway peer, затем ChannelBind для конкретного UDP peer tuple.
11. Только после подтверждённого ChannelBind открыть data path.
12. Обновлять allocation, permission и channel до истечения их сроков; при потере allocation полностью очистить peer state и выполнить ограниченный reconnect.

## Реализация первого control-driver среза

`crates/transport/src/turn_driver.rs` связывает UDP adapter, transaction manager, auth context, allocation manager и peer registry. Он предоставляет отдельные операции Allocate, CreatePermission, ChannelBind и Refresh; все операции выполняются через один mutable driver, поэтому control transactions не конкурируют за один socket receive loop. Начальный unauthenticated 401 возвращается как структурированный challenge для credential/auth слоя. 438 принимается только после проверки MESSAGE-INTEGRITY; authenticated 401 не используется для повторного согласования credentials. Состояние allocation/peer обновляется только после проверки ответа.

Это ещё не автоматический session supervisor: nonce rotation/credential renewal, повтор Allocate после challenge, reconnect, непрерывный ChannelData receive path и TUN data path остаются отдельными задачами. Driver намеренно не выводит integrity key из VK Calls username/password.

## Session supervisor

`crates/transport/src/turn_supervisor.rs` добавляет единственного владельца TURN driver и auth context. `TurnAuthProvider` получает конкретный 401/438 challenge и возвращает новый явно сконфигурированный `TurnAuthContext`; derivation credentials остаётся за пределами транспорта.

Supervisor ограничивает повторное согласование тремя challenge retries, обрабатывает первоначальный 401 при Allocate и проверенный 438 при Refresh/CreatePermission/ChannelBind, предоставляет сериализованные control operations и maintenance loop. Он планирует обновление allocation, permissions (с запасом 60 секунд до истечения) и channel bindings (с запасом 120 секунд), повторно устанавливая peer state до истечения срока. Ошибки других классов не запускают автоматические повторные попытки. Локальные permission/channel записи удаляются по истечении их сроков.

Supervisor остаётся единственным владельцем control driver. `TurnClientDriver` теперь запускает `TurnSocketActor`: единственный reader/writer task маршрутизирует STUN control и data datagrams в независимые bounded queues. Driver получает control events из своей очереди, а `take_data_receiver()` передаёт data queue отдельному dataplane consumer, который может работать одновременно с control operations. Actor сохраняет исходные wire bytes для последующей MESSAGE-INTEGRITY проверки; transaction matching и проверка целостности остаются у driver. Старый per-transaction receive loop удалён.

## Единый UDP socket actor

Добавлен `crates/transport/src/turn_socket_actor.rs`. Actor получает владение `TurnUdpSocket` и запускает единственный reader/writer task. Все отправки проходят через bounded command queue ёмкостью 32; STUN control events направляются в bounded queue ёмкостью 32 с backpressure, ChannelData и TURN Data indications — в bounded data queue ёмкостью 128 с политикой drop-newest. Некорректные datagrams отбрасываются и учитываются отдельным счётчиком; переполнение data queue также учитывается. Источник каждого входящего datagram сохраняется.

Actor классифицирует UDP ChannelData по корректному RFC framing и STUN сообщения по codec; STUN Data indications направляются в data queue. Он не подтверждает транзакции и не проверяет MESSAGE-INTEGRITY: эти действия остаются у control-plane owner. Отправка сериализована actor task, а Android-путь с заранее защищённым socket descriptor остаётся в UDP adapter.

Actor подключён к `TurnClientDriver`: control transactions отправляются через bounded actor command queue и получают ответы через единственный control receiver; data receiver может быть передан отдельному dataplane consumer. Это устраняет конкурирующие socket receive loops. Сам data receiver пока не подключён к `TurnDataReceiver`, Android TUN и серверному gateway, поэтому сквозной TURN data path ещё не готов.

## Защищённый TURN dataplane

Добавлен `crates/transport/src/turn_dataplane.rs`. Он соединяет bounded data queue socket actor с `TurnDataReceiver` и `TurnDataSender`: uplink принимает целые `DataDatagram` от TUN-facing consumer, защищает их directional AEAD frame и отправляет через ChannelData; downlink принимает только датаграммы от настроенного TURN endpoint, проверяет channel number, AEAD, session/direction/replay и формат IP-пакета, после чего передаёт пакет в bounded очередь TUN-facing consumer. Пакеты от неожиданного UDP source отбрасываются до AEAD decode. Ошибки аутентификации/формата учитываются как rejected frames, а не завершают весь dataplane.

`TurnClientDriver::take_data_plane_parts()` передаёт data receiver и clone actor send handle без передачи socket ownership. Control driver продолжает использовать тот же actor. Key agreement, TURN credentials, allocation, CreatePermission и ChannelBind по-прежнему должны быть завершены до запуска dataplane; сам dataplane не создаёт ключи и не считает наличие AEAD PSK достаточным доказательством установления сессии.

Добавлен mock-UDP тест, который проводит IP packet через actor, ChannelData и обе directional AEAD стороны. Это проверяет локальную композицию компонентов, но не является испытанием реального TURN relay или VK Calls.

## Проверка управляющих ответов

Каждый ответ сначала сопоставляется по transaction ID, method и точному source SocketAddr. До изменения состояния проверяется MESSAGE-INTEGRITY согласно согласованному auth profile. TransactionManager.complete вызывается только после успешной проверки целостности и принятия ожидаемого перехода состояния.

Исключение — первоначальный unauthenticated 401 challenge, для которого MESSAGE-INTEGRITY не ожидается. Он принимается только для текущего Allocate transaction и только с ожидаемого TURN endpoint. Challenge не считается подтверждением личности сервера; транспортная защита и доверие к endpoint должны рассматриваться отдельно.

Неизвестные, повторные, просроченные или неправильно подписанные ответы не меняют состояние и не завершают активную транзакцию. Ошибки 401/438 обрабатываются отдельно от остальных STUN error codes. Бесконечные повторные попытки запрещены.

## Граница аутентификации

`TurnCredentialProvider` получает и обновляет временные credentials VK Calls. `TurnAuthProvider` предоставляет явно сконфигурированный профиль: нормализацию строк, PASSWORD-ALGORITHM по RFC 8656: SHA-256 обязателен, если сервер предложил MD5 и SHA-256 и клиент поддерживает оба; в остальных случаях учитывается порядок серверного списка, точный список PASSWORD-ALGORITHMS из challenge и функцию получения MESSAGE-INTEGRITY key. Если сервер прислал PASSWORD-ALGORITHMS, клиент обязан вернуть тот же список без изменений; последующие запросы используют MESSAGE-INTEGRITY-SHA256. Алгоритм вывода ключа и алгоритм HMAC — разные параметры профиля.

Эти интерфейсы не взаимозаменяемы. VK Calls credential не является ключом шифрования IP-пакетов и не передаётся в AEAD frame codec. Парсер и auth context сохраняют и проверяют согласованный список алгоритмов, но не выполняют password-key derivation. Пока реальный профиль VK TURN не подтверждён тестовыми ответами или надёжной спецификацией, production driver обязан завершать запуск диагностируемой ошибкой конфигурации, а не угадывать нормализацию или MD5/SHA-256 derivation.

## Data path

Uplink: IP packet из TUN → проверка длины/версии → session frame AEAD → TURN ChannelData → TURN UDP endpoint.

Downlink: ChannelData от TURN endpoint → проверка номера канала → AEAD open и replay check → проверка IP packet → запись в TUN.

Gateway peer должен быть одним заранее выбранным UDP endpoint. Gateway принимает кадры от relay и отправляет ответы обратно на фактический source SocketAddr relay-пакета. Не использовать адрес назначения из непроверенного payload. Серверная сессия определяется аутентифицированным session ID и криптографическим контекстом, а не только source IP/port.

## Очереди и план производительности

Первый вариант использует bounded Tokio channels и один serialized control owner. Receive loop не блокируется на обработке IP-пакетов; при заполнении очереди применяется явная политика backpressure/drop с метриками. Нельзя создавать unbounded channels.

Ring buffer/SPSC и отдельный packet pool вводятся только после сравнимых тестов. Сравнение должно использовать одинаковые MTU, RTT, packet-size distribution, loss/reordering, bitrate и длительность. Измерять p50/p95/p99 latency, goodput, packet loss, queue drops, CPU time, wakeups, allocations/packet и RSS.

## Тестовая стратегия

До реального VK endpoint обязательны:

- unit tests для каждого перехода и некорректного ответа;
- mock relay с реальным UDP socket и поддержкой auth fixtures;
- проверка 401 → authenticated Allocate, 438 → nonce refresh, retransmit, timeout и cancellation;
- permission/channel expiry и refresh;
- uplink/downlink с разными directional AEAD keys;
- source spoofing, replay, malformed STUN/ChannelData, oversized datagrams;
- bounded queue saturation и graceful shutdown;
- property/fuzz tests для STUN, ChannelData и защищённого frame codec.

Текущий mock relay намеренно не реализует MESSAGE-INTEGRITY и не может служить доказательством работоспособности production auth driver. Следующий этап должен добавить тестовый auth profile и проверяемые fixtures, не подменяя ими реальный профиль VK.

## Выбор архитектурных решений

При сравнении исходных реализаций обнаружены два подхода: более простой асинхронный driver с ограниченными Tokio очередями и более сложный вариант с выделенным state core, SPSC packet queues, packet pool и отдельным writer. Для первого корректного вертикального среза выбран первый подход с единственным владельцем control state. Сложный packet path оставлен кандидатом для benchmark, поскольку сам по себе не доказывает меньшую задержку или энергопотребление на Android.

## Результаты сравнительного аудита реализаций

Сопоставление TURN control core в нескольких Rust-реализациях выявило следующие решения:

- Один владелец состояния, отдельные очереди control/events фиксированной ёмкости, ограниченное число pending-транзакций и таймерное обслуживание allocation/permission/channel. Эти свойства подтверждают выбранную модель единственного владельца состояния; mutex в нашем driver не требуется, поскольку операции сериализованы через `&mut self`.
- В одной реализации начальный RTO равен 200 мс, максимальный RTO — 1600 мс, число передач ограничено семью; также предусмотрены три nonce-retry и периодические keepalive. Для нашего UDP control path сохранён RFC-ориентированный начальный RTO 500 мс, экспоненциальная задержка и ограничение числа передач: более агрессивные 200 мс без измерений на сетях с высокой RTT повышают риск лишних повторов и расхода энергии. Ограниченные nonce-retry и планировщик обслуживания остаются обязательной следующей частью session supervisor.
- Более сложная dataplane реализация использует отдельный поток, current-thread runtime, пакетную обработку UDP/TUN, ограниченную очередь команд и restart backoff. Это полезные идеи для последующей оптимизации, но перенос усложнит владение Android TUN и жизненный цикл потоков. До benchmark на одинаковых MTU, RTT, потерях и packet-size distribution сохраняется более простой async путь.
- Android-реализации с передачей TUN file descriptor в native worker сокращают промежуточную обработку пакетов. Это направление следует учитывать при подключении JNI, но оно не заменяет обязательный вызов `VpnService.protect(fd)` для UDP-сокета TURN и не доказывает преимущество по энергопотреблению без измерений.
- В реализации получения VK Calls credentials обнаружен конкретный anonymous join-link flow, включающий несколько VK/OK CDN API-вызовов и извлечение `turn_server.username`, `credential`, `urls`. В ней также присутствуют фиксированные client/app параметры и имитация TLS/browser-профиля. Поэтому в Ghulakh сохраняется отдельный provider boundary; значения и профиль нельзя считать стабильным публичным API или переносить без проверки актуальности и правомерности использования.

Эти выводы основаны на чтении исходного кода, а не на сопоставимом performance benchmark. Они не дают оснований объявлять одну реализацию более быстрой или энергоэффективной. До измерений выбран минимальный корректный control path с RFC-совместимой политикой retransmission, одним владельцем состояния и ограниченными ресурсами.

## Условия готовности первого вертикального среза

Первый срез считается готовым только когда автоматический тест проходит всю последовательность: credentials fixture → authenticated Allocate → CreatePermission → ChannelBind → protected uplink → gateway receive/authenticate → reply to relay source tuple → protected downlink → TUN packet. До этого TURN primitives и mock forwarding нельзя называть готовым TURN VPN.
