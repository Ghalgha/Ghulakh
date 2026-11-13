# Решения по реализации TURN-транспорта

Дата: 2026-11-10.

## Область сравнения

Сравнивались реализации TURN allocation driver в доступных Rust-клиентах из исследуемого набора. Сравнение относится к архитектурным решениям и наблюдаемому коду, а не к доказанным результатам одинакового benchmark: сопоставимых измерений энергопотребления и latency для всех реализаций нет.

## Наблюдения

### Вариант с Tokio MPSC и крупными UDP buffers

- Один driver task обслуживает TURN control state и inbound datagrams.
- Для входящих пакетов используется bounded Tokio MPSC queue.
- UDP receive/send buffers настроены существенно крупнее.
- Очередь ограничена долей общего PacketPool, что не позволяет одному allocation бесконечно занимать память.
- Реализация проще для интеграции с async Tokio consumers, но queue handoff и более крупные socket buffers могут повышать память на allocation.

### Вариант с SPSC и отдельным outbound writer

- Для входящих пакетов используется SPSC ring, уменьшающий общую синхронизацию producer/consumer.
- Outbound UDP отправка вынесена в отдельный writer с bounded ArrayQueue.
- При WouldBlock writer ждёт writable event, вместо немедленного сброса пакета или постоянного polling.
- Notify/event-driven wakeups избегают периодического пробуждения простаивающего writer.
- Socket buffers и очереди компактнее, что потенциально снижает память и давление на cache; это не доказывает более высокий throughput на каждом устройстве.
- Архитектура сложнее: требуется аккуратная реализация rearm/notification, shutdown и владения буферами.

## Выбор для Ghulakh

Взять за основу следующие свойства:

1. Один владелец TURN control state и сериализованные control transitions.
2. Отдельный receive loop для relay datagrams.
3. Bounded ingress/egress queues и единый socket actor используются в текущем runtime. SPSC/ring-buffer замена остаётся только возможной оптимизацией после сопоставимого benchmark.
4. Outbound UDP operations выполняются через actor/runtime с ограниченными очередями и управляемым shutdown; отдельная SPSC writer-архитектура не заявляется как реализованная.
5. Event-driven notifications вместо периодического polling.
6. Буферы из PacketPool/reusable buffers, чтобы избежать лишних allocation/copy на каждый пакет.
7. Явные счётчики queue-full, pool-exhaustion, socket WouldBlock, packet loss, retransmission и reconnect.

Не копировать значения buffer sizes из одного источника. Начальная конфигурация должна быть консервативной и измеряться на одинаковых тестовых сценариях.

## Критерии сравнения

Для каждого изменения сравнивать на одинаковых MTU, packet sizes, bitrate, RTT, loss и длительности:

- p50/p95/p99 end-to-end packet latency;
- goodput и packets/sec;
- packet loss, queue drops и reorder;
- CPU time и wakeups/second;
- peak RSS и allocations/packet;
- время восстановления после смены сети и потери relay;
- стабильность на длительном soak test.

Решение о SPSC, размере очередей, количестве allocations и дублировании пакетов принимать по результатам benchmark, а не по субъективной оценке исходного кода.

## Безопасность и корректность важнее микрооптимизаций

- Никакой пакет не передаётся в TUN до успешной аутентификации AEAD.
- Входящие ответы маршрутизируются по серверной session mapping; незашифрованный payload не задаёт произвольный destination.
- Проверяются direction, session ID, sequence/replay window и лимиты размера.
- TURN transaction response применяется только после проверки transaction ID, method, source endpoint и MESSAGE-INTEGRITY.
- Все очереди ограничены; переполнение имеет явную политику и метрики.
- Закрытие allocation отменяет driver и writer, завершает pending transactions и освобождает буферы.
