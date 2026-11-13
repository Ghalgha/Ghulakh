# Архитектура

**Сверено с main `c337b98243f95b15256b4fb56995ff1597684bc2` (2026-11-13).** Актуальный статус реализации и границы подтверждения — в [STATUS.md](STATUS.md).

## Цель

Ghulakh — Android VPN-клиент и серверный шлюз для защищённой передачи IP-пакетов через TURN-реле инфраструктуры звонков VK (VK Calls). Это основной и единственный транспорт первой версии. Архитектура допускает добавление других транспортов позднее, но сейчас альтернативные реализации не создаются.

## Сквозной поток данных

1. Android `VpnService` перехватывает IP-пакеты через локальный TUN.
2. Транспортное ядро формирует ограниченные кадры, защищает их AEAD и отправляет через TURN allocation инфраструктуры VK Calls на серверный gateway endpoint.
3. Серверный gateway проверяет кадры, криптографическую аутентичность, replay protection, сессию и IP-адрес источника.
4. Валидные IP-пакеты проходят egress ACL и передаются в серверный TUN.
5. Ответные пакеты маршрутизируются в соответствующую сессию, защищаются и возвращаются через TURN relay тем же транспортным путём.

Обратный путь реализован через проверенный relay source tuple, session mapping, защищённый downlink и ChannelData. Mock integration tests проверяют композицию, но не доказывают совместимость с реальной VK Calls relay-инфраструктурой.

## Компоненты

### Android

- Kotlin UI и управление профилями.
- Android `VpnService` и локальный TUN.
- Rust transport core через JNI.
- Отдельный credential provider для получения/обновления TURN credentials.
- TURN allocation manager: Allocate, Refresh, CreatePermission, ChannelBind, keepalive и cleanup.
- Secure frame codec, replay window, packet fragmentation/reassembly.
- Session supervisor для восстановления после смены сети и истечения allocation.

### Сервер

- Rust async runtime и UDP ingress для пакетов от TURN relay.
- Реестр устройств/сессий и аутентификация.
- Проверка защищённых кадров и replay window.
- Ограниченная сборка IP-пакетов и маршрутизация по сессии.
- Серверный TUN, source-IP validation и egress ACL.
- Возвратный путь через TURN relay с проверенной адресацией.

### Протокольный слой

- Версионированные control и data frames.
- Ограничения размеров и строгая валидация.
- Идентификатор сессии, направление, счётчик/nonce и защита от повторов.
- Фрагментация с ограничением количества фрагментов, времени жизни и общей памяти.
- Криптографическая защита стандартными AEAD-примитивами; RTP-подобное оформление само по себе не является защитой.

### Жизненный цикл TURN/STUN control buffers

Контрольный путь использует явную очистку временных копий:
- STUN attribute values очищаются при уничтожении `StunMessage`; частичный результат decode очищается при любой ошибке.
- TURN challenge realm/nonce и password-algorithm offer очищаются при завершении challenge lifetime.
- STUN SHA-1/SHA-256 signing/verification/fingerprint staging buffers очищаются через `Zeroizing`.
- Сохранённый transaction request, retransmission copy, socket actor outbound command, inbound control wire и UDP receive buffer очищаются после завершения своего использования.
- TURN URI query parameters очищаются при уничтожении `TurnEndpoint`, в том числе при ошибке разбора неполного списка параметров.

На Android credential provider снимает ссылки с промежуточных JSON containers после формирования результата и при ошибках валидации/разбора; service-local VK access token освобождается после передачи активному broker. JNI преобразует входные TURN JSON и tunnel credential в контролируемые Rust-копии под `Zeroizing`. Сетевые байты и порядок retransmission не меняются. Очистка ограничена памятью, контролируемой приложением; immutable JVM `String`, внутренние копии `org.json`/HTTP/JNI, память ядра и внутренние состояния криптографических библиотек не гарантированно стираются.
## Абстракция транспорта

Ввести интерфейс `TransportProvider`, отвечающий за создание сессии, отправку/приём кадров, состояние и закрытие. Первая и единственная реализация — VK Calls TURN. Получение credentials и TURN endpoint выделяется в отдельный интерфейс, чтобы не связывать TURN protocol engine с конкретным способом авторизации VK Calls.

## Роль текущего QUIC-кода

Существующая реализация QUIC — экспериментальный прототип и не соответствует основной цели. Она не должна использоваться для передачи пользовательских IP-пакетов в целевой конфигурации. Её можно оставить изолированной для локальной диагностики или удалить после переноса полезных независимых компонентов (например, тестовой инфраструктуры и общих проверок).

## Безопасность и эксплуатация

- Никаких общих встроенных секретов.
- Индивидуальные credentials и ключи на устройство/сессию.
- Fail-closed при ошибках аутентификации, криптографии, replay check и состояния allocation.
- Жёсткие лимиты на кадры, очереди, сессии, сборки и тайм-ауты.
- Не включать forwarding без проверенной серверной настройки TUN, NAT и firewall.
- IPv4 и IPv6 захватываются Android TUN и передаются через TURN dataplane; сервер проверяет виртуальные source addresses и маршрутизирует оба семейства. Публичный IPv6 egress зависит от маршрута upstream либо NAT66 на сервере и не подтверждён на реальном VPS.
- Физические испытания проводятся только на заключительном этапе.

Подробные открытые вопросы и порядок проверки перечислены в [TRANSPORT_DESIGN.md](TRANSPORT_DESIGN.md) и [STATUS.md](STATUS.md).

Текущая реализация включает dual-stack tunnel group, multipath recovery, Android Keystore profile persistence и authenticated TURN credential-rejection recovery. Серверные sysctl/routes/firewall остаются административной конфигурацией; приложение не выполняет автоматический глобальный deployment.
