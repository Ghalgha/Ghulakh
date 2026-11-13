# Текущий статус проекта

Дата сверки: 2026-11-13. Ветка: main. Текущий commit: 611b4788c9b40dba29a82ed3011e8d6f0f5ae4f3 (merge PR №3). Последний CI для вошедшего в merge head eb92fd6e1628508c22c5eabf0f8ae5b291ed13d6: все три проверки успешны.

Документ отделяет наличие реализации и автоматических тестов от подтверждения работы с внешней сетью. Успешный CI не доказывает совместимость с VK Calls relay или production readiness.

## Назначение и границы

Поддерживаемый пользовательский транспорт — защищённый IP VPN-туннель через TURN-реле VK Calls. Android-клиент создаёт TURN allocations и передаёт защищённые кадры серверному UDP gateway. Сервер — peer/gateway приложения, а не TURN-сервер. Альтернативные пользовательские транспорты и fallback не реализованы.

## Реализовано в коде

- STUN/TURN codecs, transaction matching, ограниченные retransmissions, allocation/permission/channel lifecycle, UDP socket actor и session supervisor.
- TURN auth context отделён от получения credentials. 401 challenge обрабатывается отдельно; 438 stale nonce допускает ограниченный повтор с новым auth context. После исчерпания retry для 438, а также при аутентифицированных 401/441 путь классифицируется как требующий замены credentials. Квотные и временные ошибки отделены от отказа credentials.
- Android VK Calls credential provider получает call token, создаёт conversation и получает временные TURN credential sets. Для дополнительных allocations действует credential broker; повторные наборы отвергаются, auxiliary sessions закрываются однократно. VK access token вводится вручную.
- TURN runtime: защищённые UDP sockets, независимые allocations, CreatePermission/ChannelBind, Noise XX handshake, защищённый двусторонний dataplane и обслуживание allocation.
- Защищённая сессия: pinned server identity, device credential внутри зашифрованного handshake, directional AEAD keys, session/direction/sequence validation и replay protection.
- Android JNI и VpnService: один TUN для tunnel group, отдельные защищённые UDP sockets на TURN paths, IPv4/IPv6 packet I/O, generation-bound lifecycle и остановка recovery workers перед завершением credential sessions.
- Multipath: независимые allocations в одной tunnel group; flow/flowlet uplink scheduling, распределение downlink flows, bounded reordering, path failure detection и замена path новой allocation/handshake.
- Серверный gateway интегрирован с UDP ingress, authenticated session registration, TUN reader/writer и downlink route lookup. Очереди, handshake admission и основные resource limits ограничены.
- IPv4/IPv6 packet processing и source-address validation присутствуют на клиенте и сервере. Host egress policy вынесена в отдельный nftables script и не включается автоматически.
- Android Keystore сохраняет полный connection profile единым AES-GCM payload. При отсутствии ключа расшифрования профиль не пересоздаётся молча.
- Rust TURN credentials используют zeroizing storage/redacted Debug. Android передаёт TURN JSON в native через one-shot handoff и очищает ссылки; JVM immutable String не гарантирует физическое затирание памяти.
- CI включает Rust tests/Clippy/audit, пять коротких fuzz targets, Android JVM unit tests/native build/debug APK и Linux network namespace test.

## Автоматически проверено

Для merge head eb92fd6e1628508c22c5eabf0f8ae5b291ed13d6 успешно завершились Rust checks, Android debug build и Linux network namespace integration. Namespace test изолированно проверяет IPv4 forwarding/NAT, IPv6 NAT66 и routed egress, established return traffic и firewall drop cases. Это не тест реального VPS или Android туннеля.

Mock UDP/integration tests покрывают TURN control/data composition, Noise handshake, session registration, protected uplink/downlink, multipath, path loss/replacement, IPv4/IPv6 forwarding, ordering, lifecycle races и cleanup. Mock relay не является реализацией VK TURN и не подтверждает внешний auth profile.

## Не подтверждено или не завершено

1. Live VK Calls: совместимость API методов, прав аккаунта, credential выдачи, TURN auth challenge/profile, vendor attributes и relay forwarding не проверена на реальном аккаунте/relay.
2. Внешние ограничения: реальные quotas, максимум allocations, allocation lifetime, credential rotation и endpoint rotation неизвестны до контролируемого теста.
3. End-to-end: не проведён реальный маршрут Android → VK TURN → VPS gateway → интернет и обратный путь.
4. IPv6 egress: dual-stack packet path реализован, но публичный IPv6 зависит от upstream route либо NAT66 и не проверен на VPS.
5. Android OAuth: встроенного OAuth/login UI и автоматического обновления VK access token нет; токен вводится вручную.
6. Server deployment: нет безопасного полного install/update/uninstall lifecycle. Администратор вручную создаёт ключи/credentials, включает sysctl, проверяет маршруты и устанавливает ограниченную nftables policy. Автоматическое изменение глобальных настроек сервера не выполняется.
7. Supply chain: нужно отдельно подтвердить Gradle dependency locking/verification, pinning GitHub Actions по SHA и воспроизводимость сборок; наличие lockfiles/Wrapper само по себе аудит не завершает.
8. Secrets: остаётся аудит срока жизни промежуточных Kotlin String/JSON объектов, native copies, crash/backup paths и полного удаления после teardown.
9. Security assurance: не завершены независимый review Noise/session framing, длительные fuzz/property/fault runs, нагрузочные и resource-exhaustion проверки.
10. Производительность: нет сопоставимых реальных измерений goodput, p50/p95/p99 latency, loss, CPU, wakeups, RSS и энергопотребления.
11. Release: CI собирает debug APK; подписанный release artifact и безопасная процедура распространения не подтверждены.

## Эксплуатационные ограничения

Не использовать проект как production VPN. Не включать forwarding на рабочем сервере до ручной проверки firewall, маршрутов, NAT и правил провайдера. Скрипт tools/configure-egress-nftables.sh управляет только собственными таблицами inet ghulakh_egress, ip ghulakh_nat4 и ip6 ghulakh_nat6; он не меняет глобальные sysctl, маршруты, default FORWARD policy, INPUT rules или чужие таблицы. Его accept verdict не отменяет drop в другой base chain.

## Порядок завершения

1. Закончить аудит IPv4/IPv6 egress edge cases и расширить изолированные тесты только при наличии пробелов.
2. Закончить аудит секретов и lifetime на Kotlin/JNI/Rust границах.
3. Закрыть dependency locking/verification и SHA pinning CI actions.
4. Завершить crypto composition review и длительные fuzz/property/fault/resource tests.
5. Завершить операционную модель deployment, не затрагивающую чужие настройки сервера.
6. Только затем провести контролируемые live VK Calls тесты и физические Android/VPS испытания.

## Как трактовать статус

«Реализовано» означает наличие логики в текущем коде; наличие теста указывается отдельно. «Автоматически проверено» не означает «проверено на внешнем relay». «Не подтверждено» нельзя трактовать как работающее. Процент готовности не выводится из числа файлов или успешных CI: он должен учитывать интеграционные, security и эксплуатационные риски.
