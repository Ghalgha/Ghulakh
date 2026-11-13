# Ghulakh (ГӀулакх)

Ghulakh — исследовательская система защищённого IP VPN-туннеля с Android-клиентом и серверным шлюзом.

## Назначение

Единственный пользовательский транспорт первой версии — собственный защищённый туннель через TURN-реле инфраструктуры звонков VK (VK Calls). Android-клиент создаёт независимые TURN allocations и передаёт защищённые IP-кадры серверному UDP gateway. Сервер проверяет сессию и маршрутизирует пакеты через TUN; обратный трафик возвращается через проверенный relay path. Другие пользовательские транспорты не реализованы; архитектура допускает их добавление позднее.

## Состояние на 2026-11-13

Текущий main: 611b4788c9b40dba29a82ed3011e8d6f0f5ae4f3. Основной программный вертикальный срез реализован: TURN control plane, VK Calls credential provider, Noise XX handshake, двусторонний защищённый dataplane, multipath с восстановлением отказавших путей, Android VpnService/JNI и серверный TUN gateway. Android Keystore сохраняет полный профиль единым AES-GCM payload. IPv4/IPv6 обработка и изолированные Linux-тесты сетевой политики присутствуют.

Последний CI для вошедшего в merge содержимого завершился успешно: Rust checks, Android debug build и Linux network namespace integration. CI не проверяет живой VK relay и не заменяет испытания на реальном устройстве.

**Проект пока не готов к production или повседневному использованию.** Не подтверждены live VK Calls API/TURN auth profile, реальная relay allocation и сквозной маршрут Android → VK TURN → VPS → интернет → Android. Не проверены публичный IPv6 egress на VPS, внешние квоты и длительная стабильность. VK access token вводится вручную; in-app OAuth отсутствует. Подробности — [текущий статус](docs/STATUS.md).

## Компоненты

- android/ — Android UI, Keystore, VpnService, JNI bridge и lifecycle.
- server/ — UDP TURN gateway, аутентификация сессий, TUN и маршрутизация.
- crates/protocol/ — wire formats, STUN/TURN, handshake и защищённые кадры.
- crates/transport/ — TURN driver/supervisor, socket actor, Noise handshake и dataplane.
- tools/ — ограниченная nftables egress policy и изолированный network namespace test.
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
