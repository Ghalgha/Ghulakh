# Текущий статус

Дата фиксации: 2026-11-11.

## Целевая функция

Единственный поддерживаемый транспорт — защищённый VPN-туннель для IP-трафика через TURN-реле инфраструктуры звонков VK (VK Calls). TURN-реле выступает транспортным посредником; сервер Ghulakh является peer/gateway, а не TURN-сервером. На клиентской стороне TURN ChannelData используется между приложением и TURN-сервером. На peer-facing стороне TURN-сервер снимает ChannelData framing и пересылает gateway исходную UDP-нагрузку.

QUIC не является целевым транспортом. Его runtime на сервере выключен по умолчанию и может быть включён только явным GHULAKH_QUIC_ENABLED=true для временной диагностики. Android VPN service использует TURN runtime.

## Реализованные компоненты

- STUN codec: framing, method/class, TLV attributes, XOR address IPv4/IPv6, MESSAGE-INTEGRITY HMAC-SHA1/SHA-256, FINGERPRINT CRC-32.
- Parser TURN challenge 401/438, включая PASSWORD-ALGORITHMS.
- Parser TURN credentials и TURN/TURNS URI с ограничениями размеров и redaction секретов.
- TURN transaction manager: случайные transaction ID, matching по endpoint/method/id, ограниченные retransmissions и лимит незавершённых запросов.
- Конструкторы Allocate/Refresh/CreatePermission/ChannelBind и parser успешных Allocate/Refresh ответов.
- Allocation state machine с lease, expiry, refresh deadline и обработкой неудачного refresh.
- Peer registry для permissions и channel bindings с expiry/cooldown.
- UDP adapter, включая принятие заранее созданного Android socket после VpnService.protect(fd).
- Единый bounded TURN socket actor: один reader/writer task, раздельные control/data/handshake queues, классификация STUN/ChannelData/Data indications, явная drop-newest политика для data overload, сохранение исходных wire bytes и счётчики malformed/drop.
- TURN control driver и session supervisor: Allocate/Refresh/CreatePermission/ChannelBind, matching ответов, MESSAGE-INTEGRITY verification, 401/438 retry, обновление allocation/permission/channel binding.
- Изолированный legacy VK Calls TURN auth provider: MD5(username:realm:password) → HMAC-SHA1, по совпадающему подходу в трёх актуальных Rust-реализациях исходных репозиториев. Он отклоняет PASSWORD-ALGORITHMS offers, пока не подтверждён профиль VK. Vendor attribute 0x8021 намеренно не добавлен: его необходимость требует live-проверки. Этот provider не доказывает live-совместимость с relay.
- Protected frame codec: directional AEAD, session ID, sequence numbers и replay window; двусторонние authenticated keepalive probes с nonce и ответом сервера.
- Noise XX session handshake: pinned server static key, client credential внутри encrypted handshake message, encrypted server acknowledgement, HKDF-SHA256 directional frame keys. Конфигурация сессии (виртуальный IPv4 и MTU) передаётся внутри encrypted ServerAck.
- Клиентский run_turn_client_handshake: единый task владеет Noise state, bounded retry driver и отдельной incoming handshake queue; проверяет relay endpoint и завершает transaction только после проверки Noise authentication и encrypted ServerAck.
- TURN dataplane отправляет authenticated path-health probe каждые 15 секунд и ожидает соответствующий зашифрованный ACK; отсутствие ACK в течение 45 секунд завершает только соответствующую path runtime. Gateway отвечает на тот же TURN relay tuple после проверки source tuple, session ID, AEAD и replay protection. Это обнаруживает silent UDP blackhole; Android recovery worker пересоздаёт отказавший path с новым protected socket, credentials, TURN allocation и Noise handshake без пересоздания всей tunnel group.
- Серверный TurnHandshakeService: bounded active handshakes, per-relay-tuple rate limits, TTL и exact-response replay cache. Cache lookup выполняется до Noise state advancement; ServerResponse/ServerAck кэшируются до отправки. Неверный credential удаляет использованное Noise state.
- Server TURN gateway интегрирован с UDP receive loop и TUN lifecycle. Он принимает raw UDP peer payloads, обрабатывает handshake, регистрирует session после cache ServerAck и до отправки ответа (чтобы исключить гонку с первым uplink), проверяет relay source tuple, session ID, AEAD/replay и внутренний IPv4 source. Uplink поступает в bounded TUN queue; downlink маршрутизируется по назначенному destination IPv4 на зарегистрированный relay tuple. Клиент отправляет двусторонние authenticated path-health probes каждые 15 секунд и считает path недоступным после 45 секунд без корректного ACK; idle sessions удаляются после 10 минут без authenticated traffic, адреса возвращаются в bounded virtual-IP allocator.
- Сервер загружает постоянную Noise keypair из hex-файлов и проверяет совпадение публичной/приватной частей. Добавлена команда ghulakh-server --generate-noise-keypair <private-hex-file> <public-hex-file>; private key создаётся с правами 0600 без перезаписи существующих файлов.
- Высокоуровневый TurnClientRuntime: protected UDP socket → Allocate → Permission → ChannelBind → Noise handshake → authenticated tunnel config → bounded bidirectional dataplane; allocation/peer refresh работает отдельной задачей.
- JNI-интерфейс Android для подключения, передачи и приёма IP-пакетов, получения виртуального IPv4/MTU и закрытия TURN-сессии.
- Rust TurnClientPathGroup объединяет 2–10 независимых TurnClientRuntime, проверяет общий group ID/IPv4/MTU и уникальность path ID, объединяет downlink queues и отслеживает доступность путей. Uplink использует детерминированный IPv4 flow hash и flow affinity: разные flows распределяются по независимым paths, пакеты одного flow сохраняют порядок. При насыщении очереди выбранного uplink path пакет newest-drop учитывается отдельным счётчиком; он не переносится на другой path и не блокирует TUN reader.
- Android JNI создаёт отдельный VpnService.protect(fd)-защищённый UDP socket для каждого path, поднимает allocations параллельно в Tokio multi-thread runtime (число worker threads равно числу путей), выполняет отдельный Noise handshake для каждого path и передаёт собранную группу в один native handle. Android VpnService по умолчанию запрашивает пять paths, настраивает один TUN по общей authenticated session config и передаёт пакеты в native path group.
- Android VkCallsCredentialProvider получает временные credentials через messages.getCallToken, auth.anonymLogin, vchat.startConversation и vchat.getConversationParams; при завершении вызывает vchat.hangupConversation. HTTP использует обычный HTTPS без имитации браузерного TLS fingerprint. VK access token, tunnel credential и pinned Noise key хранятся зашифрованными Android Keystore. Временные TURN credentials заново запрашиваются при каждом подключении.
- Mock UDP tests покрывают socket actor, client dataplane, server gateway и интегрированный Noise handshake → encrypted session config → session registration → protected uplink. Full mock TURN tunnel test дополнительно проверяет Allocate/Permission/ChannelBind, authenticated Noise handshake, protected uplink через server TUN, protected downlink до client TUN и Refresh. Эмулятор TURN использует отдельные client-facing и peer-facing UDP sockets, поэтому gateway видит адрес allocation relay, а не адрес TURN control endpoint. Отдельный mock control-plane test покрывает Allocate/Permission/ChannelBind/Refresh и клиентскую ChannelData forwarding.
- Multipath gateway test регистрирует два независимо защищённых authenticated paths с общим virtual IPv4, передаёт uplink через оба пути в один server TUN queue и проверяет flow-affine downlink с расшифровкой на выбранном пути. Отдельный Rust path-group test использует две mock path runtime и проверяет flow-affine uplink dispatch, downlink fan-in, сохранение выбранного пути для flow, а также исключение пути после закрытия его downlink и продолжение передачи через оставшийся path. Этот тест изолирует group scheduler; он не заменяет полный multi-allocation TURN handshake test. Дополнительный тест одновременно закрывает обе mock path runtime, дожидается регистрации отказа обоих путей, заменяет каждый path на месте и проверяет передачу через обе восстановленные очереди без пересоздания tunnel group.

## Ограничения текущего этапа

Наличие компонентов и успешных mock-тестов не доказывает совместимость с реальными VK Calls API, TURN allocation policy или relay network behavior. Физические Android/VPS испытания намеренно отложены до завершения программной вертикали.

Android пока требует вручную предоставить пользовательский VK access token; встроенный OAuth/login flow не реализован. VK Calls API flow и legacy TURN authentication profile не проверены на реальном аккаунте/relay. Не подтверждены необходимость vendor attribute 0x8021, поведение PASSWORD-ALGORITHMS и ротация TURN credentials.

Сквозной тест реального TURN allocation → handshake → protected uplink/downlink → Android TUN ещё не выполнен. На сервере и клиенте компоненты собраны, но их совместная работа пока подтверждена отдельными mock-сценариями, а не реальным VK relay.

Туннель первой версии передаёт IPv4. Android захватывает IPv6 для предотвращения утечки, но серверный gateway не маршрутизирует IPv6.

## Оставшиеся критические задачи

- Проверить VK API credential flow на тестовом аккаунте, не логируя access token, call token, session key или TURN credentials; проверить завершение call при штатном отключении и ошибках.
- Подтвердить реальный TURN auth profile: username/password normalization, MD5 long-term key, HMAC-SHA1, vendor attribute 0x8021, PASSWORD-ALGORITHMS и credential rotation. Не включать непроверенные атрибуты/алгоритмы на основании одного исходного варианта.
- Добавить надёжное получение/обновление VK access token (OAuth UI) без scraping cookies и обхода CAPTCHA.
- Проверить lifecycle server TUN, IP forwarding/NAT/firewall и session cleanup под нагрузкой.
- Полный mock multipath TURN integration test проверяет две независимые allocations, отдельные Allocate/Permission/ChannelBind и Noise XX handshakes, общий authenticated virtual IPv4 и двусторонний protected datapath. В том же сценарии обе relay allocations одновременно отключаются; клиент обнаруживает потерю authenticated keepalive ACK, помечает оба path как отказавшие, получает новые mock credentials для каждого пути, создаёт новые protected UDP sockets и TURN allocations, проходит новые Noise handshakes и заменяет оба path без пересоздания tunnel group. После восстановления проверяются uplink через оба пути в общий server TUN, downlink через новые relay allocations и сохранение прежнего virtual IPv4. Это mock network-fault test; реальная VK Calls credential выдача и поведение relay остаются непроверенными.
- Отдельный path-group saturation test заполняет bounded uplink queue выбранного path, проверяет drop counter и подтверждает, что переполненный flow не переназначается на другой path. Отдельный group-level test проверяет замену двух отказавших runtime. Полный server-side mock TURN integration test теперь дополнительно проверяет отказ relay, обнаружение таймаута, новые credentials, повторные allocations и handshakes. Осталось добавить детерминированные fault cases для частичных отказов (потеря control response, отказ Allocate/Refresh, stale nonce), проверить cleanup путей при остановке Android service и расширить fuzz/property coverage.
- После стабилизации flow-affinity multipath решить по измерениям, нужен ли striping одного flow с общим group sequence и reorder buffers.
- Добавить fuzz/property tests, deterministic network fault simulation на полном multipath пути TURN, MTU/fragmentation, source spoofing, reconnect и credential rotation.
- Провести security review Noise/session protocol; библиотека Snow не заявляется как формально аудированная.
- Удалить остаточный QUIC runtime и код после успешного TURN vertical slice и тестирования; TURN→QUIC fallback не добавлять.
- Провести физические Android/VPS испытания ближе к завершению проекта, затем измерить throughput, loss, CPU wakeups, энергопотребление и память.

## Архитектурные решения

- Целевая многопутевая модель — одна tunnel group на устройство и несколько независимых TURN allocations (transport paths), каждая со своим protected UDP socket, TURN permission/ChannelBind, Noise handshake, ключами и bounded queues. Один Android TUN и один виртуальный IPv4 принадлежат tunnel group.
- Один socket actor владеет UDP socket каждого path и выполняет единственный receive loop. TUN reader/writer остаются единственными владельцами Android TUN I/O.
- Начальный режим распределяет flows по независимым paths с flow affinity; общий group sequence и bounded reorder buffer понадобятся только для будущего striping одного flow. Простой packet round-robin без восстановления порядка не допускается.
- Число TURN paths, число async tasks и число OS threads — разные параметры. Многопоточность обязательна; число paths ограничивается политиками клиента/сервера и уточняется после измерений.
- Межзадачные очереди ограничены. Data overload использует явный drop-newest; control queue применяет backpressure.
- Packet pool/SPSC/ring buffer не вводить до benchmark: сравнивать throughput, loss, queue drops, CPU wakeups и память.
- Все retry ограничены и классифицируются по TURN/STUN error code.
- Сервер отвечает на фактический relay source tuple, закреплённый при authenticated session registration. Не использовать адрес, извлечённый из незашифрованного IP payload.
- Key agreement, VK access token, временные TURN credentials, TURN long-term authentication и tunnel credential — отдельные security boundaries.

## Сравнительный аудит и производительность

Одинаковые задачи сравниваются на уровне решений, а не переноса исходного кода. В нескольких Android-реализациях повторяется полезная модель учёта доступных физических сетей как множества с переходами AVAILABLE/CHANGED/UNAVAILABLE; это позволяет не рвать туннель при появлении/исчезновении вторичного интерфейса, пока остаётся пригодная сеть. Политика повторного использования TUN требует одновременно живого дескриптора, неизменной конфигурации и отсутствия принудительной перестройки; восстановление через уже закрытый дескриптор не допускается. Эти принципы следует применить к lifecycle Android-клиента, но не копировать конкретные классы.

Варианты с большим числом worker-сессий и групп предназначены для параллельных TURN allocations, а не для создания такого же количества OS threads поверх одной allocation. Ghulakh использует несколько независимых allocations внутри одной tunnel group; каждая имеет отдельный защищённый UDP socket, TURN state, Noise keys и bounded queues. Один Tokio multi-thread runtime обслуживает группу, а число его worker threads сейчас равно числу paths. Это начальная инженерная настройка, а не измеренный оптимум. В Go-вариантах полезны изоляция worker sessions и ограничение очередей; в одной реализации применяются size-based chunks, отдельная приоритетная очередь для коротких пакетов и ограничение времени удержания одного relay. Это снижает head-of-line задержку, но переключение relay внутри одного IP flow требует осторожности из-за разного RTT. В Rust-вариантах встречаются два класса scheduler: фиксированное чередование worker paths короткими пакетными группами с разделением latency/priority/bulk traffic и более сложный adaptive deficit scheduler с token buckets, оценкой sendability/congestion, ограниченной flow table, TTL и burst-based миграцией bulk flows. Второй вариант функционально богаче, но его параметры зависят от измеренной скорости allocation и семантики очередей конкретного транспорта; переносить их в Ghulakh без end-to-end tests и измерений нельзя. Поэтому текущая реализация сохраняет статический flow hash как консервативную основу, не вводит packet striping и не заявляет, что adaptive scheduling уже реализован. Отдельно изучены lock-free bounded queues, epoch-based queue invalidation, разделение очередей по классам трафика и packet pool; это кандидаты на последующую оптимизацию после профилирования, а не автоматическая замена текущих Tokio bounded queues.

Тестовая стратегия также различается: синтетические throughput/soak тесты измеряют поведение очередей при заданной нагрузке, но не доказывают реальную пропускную способность TURN. Обнаруженный крупный chaos harness в одной ветке отключён условной компиляцией и потому не считается действующим покрытием CI. Ghulakh добавляет собственные тесты на уровне gateway: пропуск sequence, переупорядочивание и обязательное отклонение повторного кадра. Следующий этап — моделирование очередей и отказов allocation на полном mock TURN пути.

Для VK Calls auth profile в актуальных Rust-вариантах прослеживается общий подход MD5(username:realm:password) + HMAC-SHA1, однако vendor attribute 0x8021 и поведение PASSWORD-ALGORITHMS требуют подтверждения на реальном relay. Для peer-facing datapath выбран raw UDP payload, поскольку TURN снимает ChannelData framing перед пересылкой пиру.

Для каждого TURN path выбраны bounded Tokio queues и отдельный socket actor с единственным reader/writer owner. Android recovery выполняется одним последовательным worker: одновременный отказ нескольких allocations не вызывает конкурентный шторм запросов VK credentials; это согласуется с credential fetch gate и paced recovery подходами, обнаруженными в сравнительном аудите. На уровне tunnel group uplink использует flow-affinity и неблокирующую постановку в per-path queue: при заполнении очереди отбрасывается newest packet, учитываемый счётчиком; перегруженный flow не переводится на другой path. Эта политика предотвращает блокировку Android TUN reader и сохраняет порядок оставшихся пакетов. Более сложные packet pools, ring buffers и batched UDP I/O остаются кандидатами на последующие измерения; заявлений о превосходстве по скорости или энергопотреблению без benchmark не делается.

## Многопутевая архитектура

**Статус: протокол, серверная регистрация, Rust path group, Android JNI multipath wiring и восстановление TURN allocation на уровне Rust mock integration реализованы.** Реализованы защищённые group/path metadata, server-side shared IPv4 lease, несколько relay sessions на один адрес, flow-stable downlink, Rust TurnClientPathGroup с flow-affinity uplink и объединением downlink. Android JNI создаёт отдельный protected UDP socket на каждый path, параллельно поднимает независимые TURN allocations и Noise handshakes, затем объединяет их в один native handle. Android VpnService по умолчанию запрашивает пять paths и использует один TUN на общую tunnel group. Успешная Android debug build подтверждена CI, но физическая совместимость с VK TURN не проверена. Полный mock multipath test проверяет две независимые client allocations, одновременную потерю обеих relay allocations, обнаружение отказа по authenticated keepalive, получение новых mock credentials, создание новых allocations и Noise handshakes, замену path slots и двусторонний protected datapath после восстановления. Group sequence/reorder для striping одного flow также не реализованы.

Обязательное требование — несколько независимых TURN allocations в одной логической VPN-сессии. Дополнительные OS threads поверх одной allocation не устраняют ограничение скорости отдельного relay-потока. Каждая allocation становится отдельным transport path с собственным UDP socket, permission, ChannelBind, Noise keys и очередями; tunnel group использует один виртуальный IPv4 и один TUN.

Сравнение datapath решений показало два класса распределения. Ранние Go-варианты распределяют последовательные chunks пакетов между worker sessions, имеют per-worker queues и переключаются при перегрузке. Это агрегирует трафик, но простое пакетное чередование между relay paths способно переупорядочить TCP. Более поздние Rust-варианты используют независимые TURN allocations, flow-aware selection и deficit scheduling. Это лучше сохраняет порядок внутри flow, однако жёсткая привязка одного flow к одному path ограничивает скорость одного flow скоростью одного relay-потока. В более поздней версии добавлена временная pinning-политика для малых UDP и ограничение удержания bulk flow на одном path; это уменьшает длительное закрепление, но требует reorder handling и измерения.

Поэтому Ghulakh не будет копировать конкретный dispatcher. Выбрано самостоятельное решение в два этапа. Первый multipath режим использует flow-affinity: один IP flow закрепляется за одним path, разные flows распределяются по независимым allocations. Это сохраняет порядок без дополнительной reorder задержки, но один flow пока ограничен скоростью одного path. Второй этап, если испытания подтвердят необходимость ускорения одного flow, добавит общий защищённый sequence и bounded reorder buffers в обоих направлениях; потерянный кадр не должен блокировать очередь бесконечно, поэтому обязательны gap timeout, окно и лимит памяти.

В актуальных Go-реализациях обнаружены 9 worker sessions на группу, per-worker retry loop с jitter и общий mutex для обновления credentials; в Rust-реализациях — 10 workers на группу, pacing запуска, сериализованный credential fetch gate и ограниченная retry ladder. Это параметры конкретных реализаций, а не измеренные оптимумы и не основание жёстко выбирать 9 или 10. Ghulakh задаст минимальную многопутевую конфигурацию и безопасный верхний предел, а итоговое число paths будет определяться нагрузочными и физическими испытаниями с учётом TURN quota.

Профили энергопотребления и тест скорости — функции после завершения и стабилизации основного multipath-туннеля. Тест скорости должен отдельно показывать single-flow и aggregate multi-flow throughput; профили должны управлять числом активных paths, batching, keepalive и concurrency, не снижая уровень защиты.

## Лицензирование

Проверены лицензии всех шести исследуемых репозиториев: два распространяются по GNU GPL v3, четыре — по PolyForm Noncommercial 1.0.0 с обязательными уведомлениями об авторстве и отдельным письменным разрешением на коммерческое использование. Код из этих репозиториев в Ghulakh не переносился; используются только самостоятельно реализованные компоненты и архитектурные выводы. Наличие технически подходящей реализации не означает разрешения на копирование или создание производного кода.

В самом Ghulakh на текущий момент отсутствует файл LICENSE. До публикации распространяемых сборок необходимо отдельно выбрать и добавить лицензию проекта, проверив её совместимость с используемыми зависимостями. Если в дальнейшем будет принято решение переносить фрагменты исходного кода, до этого потребуется отдельная проверка условий соответствующей лицензии, сохранения уведомлений и получения необходимых разрешений.


## Серверная замена отказавшего TURN path

Каждый слот `path_id` привязан к generation token — 128-битному идентификатору аутентифицированного Noise handshake. Повторная регистрация слота заменяет его generation, сохраняя общий виртуальный IPv4. Очистка сессии освобождает слот только при совпадении generation token, поэтому запоздалое завершение старой сессии не удаляет новую регистрацию. Gateway при замене удаляет старую сессию из маршрутизации до добавления новой. Это серверная основа восстановления пути; создание новой Android TURN allocation и повторный handshake из JNI реализованы; остаются проверка реального VK Calls credential flow и физическая валидация.


## Android TURN path recovery

The Android service now monitors failed path slots while the VPN remains active. For each failed slot it obtains fresh temporary VK Calls TURN credentials, creates a new Android-protected UDP socket, establishes a new TURN allocation and authenticated Noise session, then replaces only that slot in the existing multipath group. The virtual IPv4 address, MTU, TUN descriptor, and surviving paths remain unchanged.

Recovery retries use bounded exponential delays (1, 2, 4, 8, 16, then at most 30 seconds). Successful VK Calls conversations are retained until the VPN service stops; failed attempts are explicitly finished. When all paths are unavailable, outbound packets are dropped and counted rather than terminating the TUN reader, allowing the recovery worker to restore service. Packet loss during a full outage is expected; continuity is not claimed.

CI and a full mock relay-loss/reallocation recovery test cover the Rust recovery path. Android recovery is integrated into the service; the live VK Calls credential flow and physical Android/VPS validation remain deferred until the software vertical slice is complete. Multiple simultaneous VK Calls TURN allocations and credential lifetime behavior still require physical validation.


### Recovery race hardening

A path-replacement race was found during review: an old downlink forwarder could finish after its path slot had been replaced and mark the new path unhealthy. Replacement now aborts the prior slot's forwarder before publishing the new slot as healthy, reuses the stable per-slot forwarder entry, and acquires registry locks before mutating state. The server's legacy virtual-address release path also refuses to release an address still owned by active generation-bound multipath leases. Regression coverage was added for both cases.

## Transactional server path replacement

Path-slot reservation now records the generation displaced by a replacement handshake. If Noise completion or gateway registration fails before the replacement is installed, rollback restores the previous generation instead of dropping the still-active lease. A regression test verifies that the previous generation remains releasable and the shared virtual IPv4 is not prematurely returned to the allocator. The handshake acknowledgement cache now commits only after successful gateway registration. Failed registration rolls back the path generation and does not leave a replayable successful acknowledgement.


## Handshake acknowledgement commit ordering

The server no longer exposes a cached successful ServerAck immediately after Noise authentication. The gateway first installs the authenticated session and its relay route; only then does the handshake service commit the exact response bytes to the replay cache. A duplicate ClientFinish arriving during registration is rejected and can be retried; after commit it receives the cached acknowledgement without advancing Noise state. Failed gateway registration rolls back the path generation and leaves no successful acknowledgement in the cache. UDP send failure after commit remains safely retryable.


## Serialized TURN path replacement commit

The gateway now retains the handshake-service mutex from authenticated ClientFinish processing through gateway session registration and ServerAck cache commit. This prevents two concurrent handshakes for the same path slot from reserving generations in one order but installing gateway routes in the opposite order. The lock is released before sending the UDP response; dataplane processing does not use this lock. Registration failure rolls back the reservation while the same transaction lock is held.


## TURN control-plane fault coverage

Added deterministic regression coverage for a lost Allocate response: the mock relay intentionally withholds every response, verifies that the client retransmits the exact same request bytes to the same endpoint, and confirms timeout cleanup removes both the pending transaction and provisional allocation state. The protocol transaction tests also assert byte-for-byte identity for each retransmission, preserving the authenticated request and transaction identifier.

Comparative review of the six reference codebases confirms two useful patterns: worker-level recovery should remain bounded and serialized around credential refresh, while maintenance operations should use explicit retry state rather than uncontrolled loops. The implementation keeps its existing bounded transaction policy and serialized supervisor/provider ownership; it does not adopt error-string-based stale-nonce detection. Тесты покрывают потерянный Allocate response с точной побайтной повторной передачей, а также полный authenticated сценарий 401 → Allocate success → подписанный старым ключом 438 Stale Nonce → повторный Refresh с новым nonce и ключом. Отдельные fault cases для Allocate server-error и Refresh failure, а также Android stop-during-recovery lifecycle coverage остаются следующими задачами.


Android recovery shutdown now checks the service-running flag immediately after VK credential acquisition and before entering JNI path replacement. If shutdown occurred while credential acquisition was in progress, the newly created Calls session is finished and no replacement is attempted. The existing post-replacement retention check remains in place for shutdown racing with an already-running native operation. Shutdown remains non-blocking; native session closure removes the registry handle while outstanding JNI work retains its own Arc lifetime.


## TURN server-error state regression coverage

Added authenticated mock-relay tests for non-challenge TURN server errors. An authenticated Allocate error verifies MESSAGE-INTEGRITY and confirms the provisional allocation is aborted. An authenticated Refresh error verifies integrity and confirms the existing allocation lease remains available after the failed refresh transition. Both tests assert that only the initial 401 causes credential-provider invocation; ordinary server errors are not misclassified as authentication challenges.


## Deterministic protocol property coverage

The STUN codec now has deterministic property-style regression tests covering XOR address round trips across IPv4/IPv6 and boundary ports, transaction-ID masks, aligned attribute payload lengths from 0 through 1024 bytes, and rejection of every strict prefix truncation of a valid message. These are reproducible corpus tests, not coverage-guided fuzzing; a dedicated fuzz target and sustained fuzz runs remain future validation work.


### Android startup/shutdown race hardening

The initial VK credential acquisition now checks the service-running flag before native connection setup. Native session handles are published to the service only under the same monitor used by shutdown. If shutdown wins while native connection setup is in progress, the newly returned handle is immediately closed through the local transport instance rather than being published after teardown. This closes the startup counterpart to the existing recovery credential-acquisition guard. The Android build validates compilation; deterministic Android lifecycle instrumentation remains outstanding.


## Bounded parser fuzzing

Added a separate cargo-fuzz package, excluded from the main Cargo workspace, with independent targets for the STUN message decoder and handshake datagram envelope decoder. CI runs each target for a bounded 15-second campaign with per-input timeout and RSS limits. Successful decodes are checked for encode/decode round-trip invariants. This is an initial smoke-fuzz gate, not a substitute for longer scheduled fuzz campaigns or corpus retention across releases.

Comparative implementation review: worker recovery variants use bounded retry delays and worker-start pacing; scheduler variants distribute packet classes across workers. Ghulakh retains per-path exponential recovery backoff and flow affinity. Worker-start pacing may be added if physical evidence shows TURN allocation bursts or credential throttling; packet striping is still deferred because packet ordering and reassembly requirements are not yet validated.


## Fuzz CI toolchain selection

CI run #635 confirmed that installing the Nightly toolchain did not change the default compiler selected by the `cargo` proxy for `cargo fuzz`; the fuzz build therefore invoked stable rustc and rejected the required sanitizer `-Z` option. The workflow now invokes both fuzz targets explicitly through `cargo +nightly`. Run #636 then exposed a separate Musl-target issue in the prebuilt cargo-fuzz installer; that issue was fixed by building cargo-fuzz from source for the native runner. Both fuzz targets subsequently passed in CI run #638.


The first explicit Nightly invocation exposed a second CI environment issue: the prebuilt cargo-fuzz binary installed through the fallback installer targets `x86_64-unknown-linux-musl`. Its fuzz build consequently selects the Musl target, where AddressSanitizer is incompatible with static libc. CI now builds cargo-fuzz from source using `cargo +nightly install cargo-fuzz --locked`, so the tool is compiled for the native GNU runner target. CI run #638 passed: the native-target cargo-fuzz installation completed, and both bounded fuzz targets (STUN decoder and handshake envelope decoder) ran successfully. Android debug build, Rust formatting, tests, Clippy, and dependency audit also passed in the same run.


## Android TURN recovery backoff policy

Сравнение Android worker-recovery реализации в актуальных исходных ветках показало одинаковую модель восстановления здоровой группы после полного обнуления числа активных workers: запоминание максимального размера группы, однократное вооружение восстановления и сброс после возврата целевого количества. Эта модель решает обнаружение потери группы, но не задаёт задержки повторных попыток отдельных TURN allocations. Ghulakh сохраняет собственную path-level exponential backoff (1, 2, 4, 8, 16, затем максимум 30 секунд), поскольку каждый TURN path восстанавливается независимо и не должен сбрасывать счётчик другого пути. Расчёт задержки вынесен в чистую Kotlin policy-функцию; добавлены JVM-тесты граничных значений, включая отрицательные и максимально большие счётчики. CI validation ожидается.

Android CI workflow дополнен отдельным `testDebugUnitTest` перед сборкой APK, чтобы новые JVM-тесты recovery policy исполнялись, а не только компилировались. Проверка этого изменения ожидается в следующем CI run.
