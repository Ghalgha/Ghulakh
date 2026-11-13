# Текущий статус

Дата проверки: 2026-11-13.
Проверяемая базовая версия: `main` на commit `1e42f53c877e0e1517f5661a0c272e7807f022b1`. Этот документ описывает состояние кода и автоматических проверок, а не результаты физических испытаний.

## Назначение и границы

Поддерживаемый пользовательский транспорт — защищённый IP VPN-туннель через TURN-реле инфраструктуры звонков VK (VK Calls). Android-клиент устанавливает TURN allocations и передаёт через них защищённые кадры серверному UDP gateway. Сервер является peer/gateway, а не TURN-сервером. Альтернативные пользовательские транспорты не реализованы и не должны использоваться как fallback.

## Реализовано в коде

- STUN/TURN codecs, transaction matching, ограниченные retransmissions, allocation/permission/channel lifecycle, UDP socket actor и session supervisor.
- VK Calls credential provider на Android: получение call token, создание conversation и получение временных TURN credential sets. Для дополнительных allocations используется общий credential broker; повторные наборы credentials отвергаются. VK access token вводится пользователем вручную и хранится с защитой Android Keystore; встроенного OAuth/login UI нет.
- TURN client runtime: protected UDP sockets, независимые allocations, CreatePermission/ChannelBind, Noise XX handshake, защищённый двусторонний dataplane и обслуживание allocation.
- Защищённая сессия: pinned server identity, device credential внутри зашифрованного handshake, directional AEAD keys, session/direction/sequence validation и replay protection.
- Android JNI и VpnService: один TUN для tunnel group, отдельные protected UDP sockets на TURN paths, передача/приём IPv4 и IPv6 пакетов, lifecycle generation, отмена устаревших операций и остановка recovery workers перед завершением credential sessions.
- TURN multipath: несколько независимых allocations в одной tunnel group; flow/flowlet scheduling uplink, адаптивное распределение downlink flows по доступным путям, per-path backpressure, обнаружение отказов и замена path с новым socket/allocation/handshake.
- Упорядочивание пакетов: sequence envelopes и bounded reorder buffers в обоих направлениях, включая сериализацию конкурентной доставки uplink. Это ограничивает переупорядочивание при переключении paths, но не превращает UDP в надёжный транспорт и не восстанавливает безусловно потерянные пакеты.
- Dual-stack: Android TUN захватывает IPv4/IPv6; клиентский TURN dataplane и серверный TUN gateway обрабатывают оба семейства; виртуальные IPv4/IPv6 адреса назначаются и проверяются отдельно; flow identities учитывают IPv4/IPv6 и фрагменты.
- Серверный gateway интегрирован с UDP ingress, authenticated session registration, TUN reader/writer и downlink route lookup. Очереди и основные admission/resource limits ограничены.
- Mock UDP/integration tests покрывают TURN control/data composition, Noise handshake, регистрацию сессии, защищённые uplink/downlink, multipath, path loss/replacement, IPv4/IPv6 forwarding, packet ordering, lifecycle races и cleanup.
- CI на базовом commit завершился успешно: Rust checks/tests и Android debug build. CI не является доказательством совместимости с внешней сетью VK Calls.

## Что не подтверждено или не реализовано

1. Совместимость текущего VK Calls API, реальной выдачи credentials, TURN auth profile, relay allocation и ChannelData forwarding не подтверждена на реальном аккаунте/relay.
2. Реальные лимиты одновременных allocations, quota scope, lifetime, credential rotation и endpoint rotation неизвестны до контролируемых испытаний.
3. Сквозная проверка Android device → live VK TURN relay → VPS gateway → интернет и обратного пути ещё не проведена.
4. Публичный IPv6 egress не гарантируется самим dual-stack туннелем: серверу нужен upstream route для ULA prefix либо NAT66 и соответствующие firewall rules. На реальном VPS это не проверено.
5. VK access token вводится вручную; встроенного OAuth/login flow и автоматического обновления пользовательского access token нет.
6. Поддерживается UDP TURN endpoint. TCP/TLS/TURNS transport не реализован.
7. MTU, производительность, устойчивость длительной работы, энергопотребление и поведение на реальных Android устройствах не измерены.
8. Не завершены финальный security review и расширенная проверка fuzz/property/fault scenarios. Успешные unit/mock tests не заменяют эти проверки.

## Многопутевой scheduler

Uplink сохраняет flow affinity внутри burst и может переключать bulk flows на границах flowlet/burst; dispatch сериализован на уровне tunnel group. Downlink распределяет flows между пригодными paths, используя состояние path и ограничение отправки/backpressure. Sequence/reorder layer защищает порядок при смене paths. Это реализация алгоритма, но не доказательство оптимального throughput: сопоставимый benchmark на реальных relay paths ещё не проводился.

## Эксплуатационные ограничения

Проект остаётся исследовательской системой и не готов к production или повседневному использованию. Перед запуском сервера необходимо вручную настроить IP forwarding, WAN routing, NAT и firewall. Не открывать unrestricted forwarding к private, loopback, link-local или multicast destinations. Не считать включённый IPv6 forwarding достаточным для публичного IPv6 egress.

Физические испытания Android/VPS и live VK Calls следует проводить на заключительном этапе, после завершения программного аудита, локальных integration/fault tests и security review.

## Следующие этапы

- Завершить аудит реализации и тестов, включая сравнение одноимённых функций в исследуемых исходных реализациях.
- Закрыть оставшиеся детерминированные fault/property/fuzz cases и повторно проверить CI после изменений.
- Проверить серверные NAT/firewall/routing сценарии и IPv6 egress в контролируемой среде.
- Выполнить контролируемые live VK Calls credential/allocation/authentication tests, не публикуя секреты.
- Провести сквозные Android/VPS испытания, измерить throughput, latency, loss, CPU, wakeups, память и энергопотребление.
- Выполнить финальный security review и обновить эксплуатационные инструкции по фактическим результатам испытаний.

## Как трактовать статус

«Реализовано» означает, что соответствующая логика присутствует в текущем коде и имеет автоматические тесты там, где они указаны. «Не подтверждено» означает отсутствие доказательства на реальном VK Calls relay или Android/VPS окружении. Не выводить процент готовности из числа файлов, тестов или успешного CI: оценка должна учитывать оставшиеся интеграционные и эксплуатационные риски.
