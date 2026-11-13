# Ghulakh (ГӀулакх)

Ghulakh — исследовательская система защищённого IP VPN-туннеля с Android-клиентом и серверным шлюзом.

## Назначение

Единственный пользовательский транспорт первой версии — собственный защищённый туннель через TURN-реле инфраструктуры звонков VK (VK Calls). Android-клиент создаёт независимые TURN allocations и передаёт защищённые IP-кадры серверному UDP gateway. Сервер проверяет сессию и маршрутизирует пакеты через TUN; обратный трафик возвращается через проверенный relay path. Другие пользовательские транспорты не реализованы; архитектура допускает их добавление позднее.

## Состояние на 2026-11-14

Текущий main: `c337b98243f95b15256b4fb56995ff1597684bc2`; PR №12 и синхронизация документации PR №13 слиты. В main включена проверка устойчивости egress-политики к IPv4/IPv6 fwmark policy routing. Основной программный вертикальный срез реализован: TURN control plane, VK Calls credential provider, Noise XX handshake, двусторонний защищённый dataplane, multipath с восстановлением отказавших путей, Android VpnService/JNI и серверный TUN gateway. Android Keystore сохраняет полный профиль единым AES-GCM payload. IPv4/IPv6 обработка и изолированные Linux-тесты сетевой политики присутствуют.

Для PR №12 все три CI jobs успешно завершились на head `2289e4c8718ad5a4372a53c878126e2c76f845db`; изменения слиты в main коммитом `cf8218a11b56f5cba770f91281af231ef7a2bc7d`. В PR №14 завершён связанный аудит Rust STUN/TURN и Kotlin/JNI secret-buffer lifetime: очищаются контролируемые Rust staging/packet buffers и промежуточные Kotlin JSON containers, включая exceptional exit paths. Перед слиянием обязательны успешные CI jobs на окончательном HEAD. CI не проверяет живой VK relay и не заменяет испытания на реальном устройстве.

**Проект пока не готов к production или повседневному использованию.** Не подтверждены live VK Calls API/TURN auth profile, реальная relay allocation и сквозной маршрут Android → VK TURN → VPS → интернет → Android. Не проверены публичный IPv6 egress на VPS, внешние квоты и длительная стабильность. VK access token вводится вручную; in-app OAuth отсутствует. Подробности — [текущий статус](docs/STATUS.md).

## Компоненты

- android/ — Android UI, Keystore, VpnService, JNI bridge и lifecycle.
- server/ — UDP TURN gateway, аутентификация сессий, TUN и маршрутизация.
- crates/protocol/ — wire formats, STUN/TURN, handshake и защищённые кадры.
- crates/transport/ — TURN driver/supervisor, socket actor, Noise handshake и dataplane.
- tools/ — ограниченная nftables egress policy и изолированные network namespace tests, включая обходные policy-routing сценарии.
- docs/ — архитектура, протокол, безопасность и эксплуатация.

## Основные ограничения

- Поддерживается только UDP TURN endpoint; TCP/TLS/TURNS не реализованы.
- TURN credentials VK Calls, device credential и Noise keys — разные секреты.
- Серверный forwarding/NAT/firewall настраивается администратором отдельно. Полного автоматического server installer/update/uninstaller в репозитории нет.
- Автоматические тесты используют mock relay и не доказывают совместимость с внешней инфраструктурой VK Calls.
- Физические испытания выполняются ближе к завершению проекта, после программного аудита.

## Документация

- [Архитектура](docs/ARCHITECTURE.md)
- [Проектирование транспорта](docs/TRANSPORT_DESIGN.md)
- [Спецификация протокола](docs/PROTOCOL.md)
- [Текущий статус и оставшиеся работы](docs/STATUS.md)
- [Развёртывание](docs/DEPLOYMENT.md)
- [Эксплуатация сервера](docs/SERVER_OPERATIONS.md)
- [Модель угроз](docs/THREAT_MODEL.md)
- [Исследование relay path](docs/RELAY_PATH_FINDINGS.md)
