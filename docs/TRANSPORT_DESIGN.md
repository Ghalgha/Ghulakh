# Проектирование основного транспорта

Статус: программная реализация основного TURN-транспорта и Android/server vertical slice собраны; реальная совместимость с инфраструктурой VK Calls ещё не подтверждена.

## Назначение и границы

Единственный транспорт первой версии — защищённый IP-туннель через TURN relay инфраструктуры VK Calls. TURN relay — посредник доставки UDP-датаграмм, а не сервер приложения. Собственный сервер принимает peer-facing UDP payloads от relay и маршрутизирует аутентифицированные IPv4-пакеты в TUN.

QUIC runtime не является транспортом пользовательского VPN-трафика, не используется как fallback и выключен по умолчанию. Другие транспорты сейчас не реализуются.

## Реализованный поток

1. Android получает временные TURN credentials через VK Calls credential provider.
2. Для каждого транспортного пути Android создаёт отдельный UDP socket и вызывает `VpnService.protect(fd)` до запуска сетевого обмена.
3. Каждый путь независимо выполняет TURN Allocate, CreatePermission, ChannelBind, Noise XX handshake и получает собственные directional AEAD keys.
4. В зашифрованном Noise exchange сервер аутентифицирует device credential и передаёт tunnel IPv4/MTU в encrypted ServerAck.
5. Android объединяет 2–10 независимых путей в одну tunnel group с одним TUN и общим виртуальным IPv4.
6. Uplink IPv4 packets распределяются по путям с flow affinity. Пакеты одного flow остаются на одном пути, разные flows используют разные allocations.
7. Сервер проверяет relay source tuple, session ID, AEAD, replay window и внутренний source IPv4 до передачи пакета в серверный TUN.
8. Downlink маршрутизируется по virtual destination IPv4 и отправляется на relay tuple соответствующего активного пути.

На клиентской стороне TURN ChannelData framing используется для передачи peer payload. На peer-facing стороне TURN relay снимает ChannelData framing и доставляет gateway исходную UDP-нагрузку.

## Компоненты

- `android/`: VpnService, защищённые UDP sockets, получение credentials, TUN I/O и восстановление отказавших путей.
- `crates/protocol/`: STUN/TURN wire codecs, allocation/path metadata, Noise handshake, encrypted frame format и IP flow hashing.
- `crates/transport/`: TURN socket actor, control driver/supervisor, dataplane, independent path runtime и multipath group.
- `server/`: UDP relay ingress, bounded handshake admission, authenticated session registry, TUN gateway и downlink routing.

## Multipath и конкуренция

Путь означает независимый TURN allocation и отдельный socket/session/Noise context, а не только OS thread. Допустимо 2–10 путей; Android начально запрашивает 5. Это конфигурационное значение, не измеренный оптимум и не гарантия квот VK.

Один Tokio multi-thread runtime выполняет параллельную настройку путей. У каждого пути собственный socket actor и bounded queues. Один Android TUN reader и один writer обслуживают общую tunnel group. Flow affinity сохраняет порядок внутри потока; packet round-robin внутри одного flow не используется. Переполнение очереди выбранного пути приводит к drop-newest и счётчику, но не к миграции уже начатого flow на другой путь.

Отказ allocation обнаруживается по отсутствию authenticated keepalive acknowledgement. Восстановление создаёт новый protected socket, получает свежие credentials, выполняет новую allocation и Noise handshake, затем заменяет только соответствующий path slot. Отклонённые по TURN quota credentials учитываются общим bounded fingerprint set на время VPN-сессии, чтобы другой recovery worker не повторял ту же credential.

## TURN control plane

Реализованы Allocate, Refresh, CreatePermission и ChannelBind, transaction matching, bounded retransmissions, allocation lease/refresh, peer/channel expiry и authenticated 401/438 challenge handling. Shutdown и ошибки setup выполняют best-effort Refresh(0) с ограниченным timeout. При невозможности подтвердить deallocation локальные ресурсы всё равно закрываются.

TURN auth provider изолирован от протокольного слоя. Текущий legacy auth profile основан на MD5 long-term key и HMAC-SHA1; его совместимость с текущим VK relay не подтверждена. PASSWORD-ALGORITHMS и vendor-specific атрибуты не включаются без отдельного доказательства совместимости.

## Безопасность и ограничения

- Noise XX аутентифицирует закреплённый server static key; device credential передаётся только внутри зашифрованного handshake сообщения.
- Directional frame keys выводятся отдельно через HKDF-SHA256.
- AEAD frames включают session ID, direction и sequence; replay window обновляется только после успешной аутентификации.
- TURN credentials, device credential, access token и Noise key — отдельные секреты; секреты не должны попадать в логи.
- Все очереди, handshake admission, transaction retry и cache ограничены.
- IPv4 — единственный маршрутизируемый IP family. Android захватывает IPv6 для fail-closed поведения, серверный IPv6 dataplane не реализован.
- MTU по умолчанию 1100 и должен быть проверен на реальном relay path.
- Потери UDP возможны; надёжность и упорядочивание на уровне TURN не предполагаются.

## Проверки

CI покрывает Rust tests/Clippy/fuzz targets, Android JVM tests, native transport build и APK build. Mock tests покрывают control plane, Noise handshake, bidirectional dataplane, multipath, relay loss, path replacement и bounded queue behavior. Эти тесты не доказывают реальную совместимость с VK Calls.

До физических испытаний остаются: deterministic fault tests для частичных отказов, расширение fuzz/property coverage, аудит lifecycle и секретов, нагрузочные/ресурсные тесты в симуляции и security review. Android/VPS испытания проводить только ближе к завершению программной вертикали.
