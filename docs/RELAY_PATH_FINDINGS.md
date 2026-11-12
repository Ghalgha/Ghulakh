# Исследование двустороннего TURN data path

Статус: архитектура реализована и проверяется mock integration tests; совместимость с текущей внешней relay инфраструктурой ещё не подтверждена физическими испытаниями.

## Модель передачи

TURN relay — внешний посредник, не сервер приложения. Клиент создаёт allocation на TURN endpoint, разрешает peer IP собственного gateway и устанавливает ChannelBind для выбранного канала. Данные идут через TURN allocation к UDP gateway. TURN server снимает ChannelData framing и пересылает peer payload gateway. Gateway отвечает на фактический relay source tuple; TURN relay доставляет UDP response клиенту в рамках allocation.

## Сквозной путь

1. Android получает временные TURN credentials и endpoint через credential provider.
2. Для каждого path Android создаёт отдельный UDP socket и защищает его через `VpnService.protect(fd)`.
3. Клиент выполняет Allocate, CreatePermission и ChannelBind.
4. Для каждого allocation выполняется независимый Noise XX handshake с pinned server key и device credential внутри зашифрованного сообщения.
5. Server gateway регистрирует session ID, relay tuple, virtual IPv4, path metadata и directional AEAD codecs.
6. Клиент передаёт encrypted IPv4 datagrams через ChannelData; gateway проверяет relay tuple, AEAD, replay и inner source IP до передачи в TUN.
7. Server TUN reader выбирает активный path group по destination IPv4 и отправляет downlink на один из недавно аутентифицированных relay tuples группы.
8. TURN relay доставляет ответ allocation, а клиент проверяет AEAD/replay и передаёт IPv4 packet в Android TUN.

## Multipath

Одна tunnel group состоит из 2–10 независимых TURN allocations. Каждый path имеет собственные socket, allocation, permission/channel state, Noise session, session ID, directional keys и bounded queues. Paths имеют общий group ID, path count, virtual IPv4 и MTU.

Uplink использует flow/flowlet scheduling: поток сохраняет path в пределах burst, а bulk flow может перейти на другой path на границе burst. Sequence numbers и bounded reorder buffer защищают порядок при переключении. Downlink распределяет flows по активным путям с учётом path availability и backpressure. Отказавший path заменяется после новой allocation и Noise handshake; замена ограничена жизненным циклом tunnel group.

## Обратный путь и session binding

Gateway не извлекает адрес клиента из незашифрованного IP payload. Для uplink проверяются session ID, зарегистрированный relay source tuple, AEAD/replay и назначенный inner source IPv4. Для downlink destination IPv4 выбирает клиентскую tunnel group; затем выбирается подходящий активный path и датаграмма отправляется на его relay tuple.

TURN relay source tuple подтверждает маршрут через allocation, но сам по себе не аутентифицирует устройство. Идентичность устанавливается Noise handshake, а data plane защищается directional AEAD.

## Ограничения и неподтверждённые предположения

- VK Calls API выдача credentials и текущий TURN auth profile не проверены на реальном аккаунте/relay.
- Не подтверждены актуальные quotas, allocation lifetime, endpoint rotation и vendor-specific attributes.
- Mock TURN relay моделирует отдельные client-facing и peer-facing sockets; это подтверждает внутреннюю логику адресации, но не реальную политику VK relay.
- Один UDP gateway listener обслуживает множество независимых relay paths; gateway receive loop пока обрабатывает datagrams последовательно. Параллелизация требует benchmark и отдельной проверки сохранности session/replay state.
- IPv4 и IPv6 проходят через Android TUN, защищённый TURN dataplane и dual-stack серверный gateway. Публичный IPv6 egress требует upstream route или NAT66 и не подтверждён на реальном сервере.
- Flow affinity распределяет разные flows, но не агрегирует пропускную способность нескольких paths внутри одного flow.

## Проверки

Mock tests проверяют TURN control flow, ChannelData forwarding, Noise handshake, registration-before-uplink, source tuple binding, protected uplink/downlink, replay rejection, multipath flow distribution, simultaneous relay loss, fresh allocation/handshake replacement и сохранение virtual IPv4. Эти проверки не являются доказательством live compatibility.

Следующие программные проверки: partial control-plane failures, stale nonce/refresh recovery, deterministic queue saturation, concurrent session churn, gateway load and bounded resource behavior. Физические Android/VPS испытания — только ближе к завершению проекта.
