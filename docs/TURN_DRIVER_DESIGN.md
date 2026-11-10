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

## Условия готовности первого вертикального среза

Первый срез считается готовым только когда автоматический тест проходит всю последовательность: credentials fixture → authenticated Allocate → CreatePermission → ChannelBind → protected uplink → gateway receive/authenticate → reply to relay source tuple → protected downlink → TUN packet. До этого TURN primitives и mock forwarding нельзя называть готовым TURN VPN.
