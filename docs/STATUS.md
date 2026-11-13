# Текущий статус проекта

Дата сверки: 2026-11-14. Базовый main: `c337b98243f95b15256b4fb56995ff1597684bc2` (PR №12 и PR №13 слиты). PR №12 добавил IPv4/IPv6 fwmark policy-routing regression test; его head `2289e4c8718ad5a4372a53c878126e2c76f845db` прошёл все три CI jobs до squash-слияния. PR №14 на HEAD `77e1cc428118dbe772328d5eb041433e8640e7cc` проверен CI run `43506358419`: все три job (Rust checks, Android debug build, Linux network namespace integration) и все их шаги завершились успешно. Проверены Rust locked resolution, audit, форматирование, тесты, Clippy, пять fuzz targets, Android JVM tests/native build/debug APK и сетевые namespace tests.

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
- Rust TURN credentials, TURN challenges, STUN attributes/messages, pending transactions и retransmission events используют redacted Debug; чувствительные поля не выводятся в форматированном представлении. PR №14 добавляет очистку TURN challenge strings, STUN attribute buffers (включая частичный decode), SHA-1/SHA-256 signing и verification staging buffers, transaction request/retransmission buffers, socket actor command/control/receive buffers и временных query-параметров URI. JNI оборачивает полученные TURN JSON и tunnel credential в `Zeroizing`; парсер Rust очищает строки промежуточного JSON дерева.
- Kotlin/JNI lifetime audit: после сериализации и при любом выходе из обработки удаляются ссылки из промежуточных `JSONObject`/`JSONArray`, включая ответы выдачи токена, запуска звонка и получения TURN credentials; service-local VK access token освобождается после передачи активному credential broker; `VkCallsSession`/broker очищают удерживаемые ссылки при finish. HTTP request/response byte arrays очищаются. JVM immutable `String` (включая access token, TURN JSON, session key и URL-encoded request body) нельзя физически обнулить; их копии в `org.json`, HTTP/JNI и runtime также не могут быть гарантированно стерты. Это остаточное ограничение, а не гарантия zeroization.
- CI включает Rust tests/Clippy/audit, пять коротких fuzz targets, Android JVM unit tests/native build/debug APK и Linux network namespace test.

## Автоматически проверено

Для PR №12 на head `2289e4c8718ad5a4372a53c878126e2c76f845db` успешно завершились Rust checks, Android debug build и Linux network namespace integration; затем изменения слиты в main коммитом `cf8218a11b56f5cba770f91281af231ef7a2bc7d`. Namespace test изолированно проверяет IPv4 forwarding/NAT, IPv6 NAT66 и routed egress, established return traffic, firewall drop cases и IPv4/IPv6 fwmark policy routing через посторонний интерфейс: пакеты не достигают rogue peer и попадают под TUN catch-all drop. Это не тест реального VPS или Android туннеля.

Mock UDP/integration tests покрывают TURN control/data composition, Noise handshake, session registration, protected uplink/downlink, multipath, path loss/replacement, IPv4/IPv6 forwarding, ordering, lifecycle races и cleanup. Mock relay не является реализацией VK TURN и не подтверждает внешний auth profile.

## Не подтверждено или не завершено

1. Live VK Calls: совместимость API методов, прав аккаунта, credential выдачи, TURN auth challenge/profile, vendor attributes и relay forwarding не проверена на реальном аккаунте/relay.
2. Внешние ограничения: реальные quotas, максимум allocations, allocation lifetime, credential rotation и endpoint rotation неизвестны до контролируемого теста.
3. End-to-end: не проведён реальный маршрут Android → VK TURN → VPS gateway → интернет и обратный путь.
4. IPv6 egress: dual-stack packet path реализован, но публичный IPv6 зависит от upstream route либо NAT66 и не проверен на VPS.
5. Android OAuth: встроенного OAuth/login UI и автоматического обновления VK access token нет; токен вводится вручную.
6. Server deployment: нет безопасного полного install/update/uninstall lifecycle. Администратор вручную создаёт ключи/credentials, включает sysctl, проверяет маршруты и устанавливает ограниченную nftables policy. Автоматическое изменение глобальных настроек сервера не выполняется.
7. Supply chain: Rust stable toolchain закреплён на `1.100.0`, fuzz использует `nightly-2026-11-12`; cargo-audit `0.23.0`, cargo-fuzz `0.13.2` и cargo-ndk `4.1.2` устанавливаются по точным версиям. Cargo check/test/clippy используют `--locked`; cargo-audit читает корневой `Cargo.lock`. Для отдельного fuzz workspace добавлен `fuzz/Cargo.lock`; CI проверяет его через `cargo check --locked` и контролирует отсутствие изменений после fuzz-запусков. GitHub Actions в workflow закреплены полными commit SHA. Android dependency locking включён через `lockAllConfigurations()` и `LockMode.STRICT`; `android/app/gradle.lockfile` и `android/gradle/verification-metadata.xml` добавлены в PR №14. Android CI выполняет unit tests и assembleDebug с `--dependency-verification=strict`, затем проверяет, что lockfile и verification metadata не изменились. Strict lock mode заставляет сборку завершаться ошибкой, если разрешаемая locked-конфигурация не имеет lock state; фактическое покрытие ограничено конфигурациями, которые разрешаются проверяемыми задачами. Полное покрытие всех возможных AGP/Android variant-only конфигураций отдельно не заявляется.
8. Secrets: аудит контролируемого Rust TURN/STUN и Kotlin/JNI control-plane lifetime выполнен в PR №14. Проверены one-shot handoff, broker/session finish, late credential fetch, JNI conversion, teardown и очистка JSON containers на штатных и exceptional exit paths. Добавлено освобождение SHA-256 verification staging buffer и сокращено время удержания service-local VK access token. Неустранимое ограничение — immutable JVM strings и копии в сторонних runtime/API; crash dump/backup paths и независимая проверка остаются отдельными задачами.
9. Security assurance: не завершены независимый review Noise/session framing, длительные fuzz/property/fault runs, нагрузочные и resource-exhaustion проверки.
10. Производительность: нет сопоставимых реальных измерений goodput, p50/p95/p99 latency, loss, CPU, wakeups, RSS и энергопотребления.
11. Release: CI собирает debug APK; подписанный release artifact и безопасная процедура распространения не подтверждены.

## Эксплуатационные ограничения

Не использовать проект как production VPN. Не включать forwarding на рабочем сервере до ручной проверки firewall, маршрутов, NAT и правил провайдера. Скрипт tools/configure-egress-nftables.sh устанавливает собственные таблицы `inet ghulakh_egress`, `ip ghulakh_nat4` и `ip6 ghulakh_nat6` одной nftables batch transaction. Таблицы помечены ownership marker `ghulakh-egress-v1`; `--remove` предварительно проверяет владельца всех существующих таблиц и отказывается удалять чужие. Установка не меняет глобальные sysctl, маршруты, default FORWARD policy, INPUT rules или чужие таблицы. Его accept verdict не отменяет drop в другой base chain.

## Порядок завершения

1. Аудит основных IPv4/IPv6 egress edge cases и изолированный тест обходного fwmark policy routing для обоих семейств включены в main коммитом `cf8218a11b56f5cba770f91281af231ef7a2bc7d`. Это закрывает тестирование описанной топологии, но не произвольных правил реального хоста.
2. Аудит контролируемого Kotlin/JNI/Rust TURN/STUN secret lifetime завершён в PR №14. CI run `43506358419` подтвердил все три jobs на PR head `77e1cc428118dbe772328d5eb041433e8640e7cc`; live VK relay и физические испытания остаются отдельными этапами. Остаточные JVM immutable-string/runtime-copy и внешние runtime limitations документированы.
3. Gradle supply-chain: dependency lockfile и SHA-256 verification metadata добавлены; временная генерация в CI заменена строгим read-only режимом. Остаётся проверить, что новые/вариантные Android конфигурации не обходят lock/verification. Fuzz workspace lockfile добавлен и проверяется в read-only режиме. Rust toolchain/tool versions и GitHub Actions SHA pinning выполнены в PR №14.
4. Завершить crypto composition review и длительные fuzz/property/fault/resource tests.
5. Завершить операционную модель deployment, не затрагивающую чужие настройки сервера.
6. Только затем провести контролируемые live VK Calls тесты и физические Android/VPS испытания.

## Как трактовать статус

«Реализовано» означает наличие логики в текущем коде; наличие теста указывается отдельно. «Автоматически проверено» не означает «проверено на внешнем relay». «Не подтверждено» нельзя трактовать как работающее. Процент готовности не выводится из числа файлов или успешных CI: он должен учитывать интеграционные, security и эксплуатационные риски.
