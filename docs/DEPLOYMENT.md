# Развёртывание сервера

Документ описывает установку, обновление и удаление серверного runtime. Установщик управляет только собственными каталогами, двумя systemd units и собственными nftables tables. Он не устанавливает пакеты, не меняет sysctl, маршруты, глобальную политику firewall, INPUT rules или чужие службы.

## Требования

- Linux с работающим systemd.
- Root для установки и управления службами.
- /dev/net/tun как character device.
- net.ipv4.ip_forward=1 и net.ipv6.conf.all.forwarding=1, настроенные администратором и сохранённые в конфигурации ОС.
- Команды ip, nft, runuser, useradd, python3, systemctl, systemd-analyze.
- Доступный WAN-интерфейс.
- Linux release binary ghulakh-server, собранный для архитектуры сервера.

Установщик не загружает бинарники из сети и не устанавливает системные пакеты. Перед передачей бинарника на сервер проверьте его происхождение и SHA-256 по доверенному каналу.

## Сборка

На Linux build host из корня репозитория:

~~~
cargo build --release --locked -p ghulakh-server
~~~

Ожидаемый бинарник: `target/release/ghulakh-server`.

## Первая установка

Если на сервере уже существуют /etc/ghulakh или /var/lib/ghulakh, установщик проверит владельца и права каталогов и остановится при несовпадении. Неполное состояние, в котором отсутствует активная ссылка current, но остался заполненный ownership marker или хотя бы один systemd unit, автоматически не исправляется: установщик откажется продолжать до ручной проверки. Единственное допустимое состояние повторной первой установки — пустой marker без unit-файлов и без active release. Требуются /etc/ghulakh root:ghulakh 0750 и /var/lib/ghulakh ghulakh:ghulakh 0700; мигрируйте права вручную после проверки содержимого.

Скопируйте бинарник и каталог tools/ на сервер, сохранив рядом файлы:
- deploy-server.sh
- deployment-preflight.sh
- configure-egress-nftables.sh
- create_credential.py

Укажите фактический WAN-интерфейс и подходящий режим IPv6:

~~~
sudo bash tools/deploy-server.sh install \
  --binary /absolute/path/to/ghulakh-server \
  --wan-interface eth0 \
  --ipv6-mode nat66
~~~

Используйте routed вместо nat66 только при наличии проверенного upstream-маршрута к клиентскому IPv6-префиксу.

При первой установке создаются системная учётная запись ghulakh, постоянные каталоги, Noise keypair, digest-файл device credentials, EnvironmentFile, release directory и systemd units. Пустой ownership marker резервирует созданный установщиком корневой каталог ещё до staging, чтобы повторная установка после сбоя могла безопасно распознать принадлежащие ей каталоги. При rollback первой установки marker остаётся пустым, созданные units и current удаляются, а постоянная конфигурация, ключи и credentials сохраняются. Секрет первого устройства и публичный Noise key выводятся в терминал. Сохраните credential и закрепите public key в Android profile. Credential показывается только при создании; digest хранится на сервере.

Перед выдачей каждого credential утилита открывает каталог и файл через file descriptors с запретом следования symlink, затем проверяет тип объекта, UID/GID, режим и отсутствие дополнительных hard links через fstat. Файл блокируется на время append. Если append, fsync или передача секрета в stdout завершается ошибкой, утилита пытается вернуть размер файла к исходному значению и завершает операцию с ошибкой. Секрет выводится только после успешного append и fsync. Несоответствие пути или прав приводит к отказу без изменения файла.

До создания учётной записи, каталогов, release, ключей или credentials выполняется read-only preflight. UDP/4434 проверяется через ss; занятый порт допускается только при совпадении всех PID слушателей с MainPID действующей ghulakh-server.service, её cgroup и исполняемым файлом текущего release. Сокет без видимого PID, чужой PID или невозможность проверить владельца приводят к отказу. Существующий ghulakh0 допускается только если это TUN-интерфейс, а MainPID текущей службы держит открытый /dev/net/tun. Иначе интерфейс не принимается во владение. Конфликты systemd units вне управляемых путей проверяются до staging. Установщик не останавливает и не изменяет чужие процессы, интерфейсы или службы.

Установщик включает и запускает:
- ghulakh-egress.service: устанавливает только принадлежащие приложению nftables tables через configure-egress-nftables.sh; при остановке удаляет только эти таблицы после проверки ownership marker;
- ghulakh-server.service: запускает сервер от непривилегированного пользователя ghulakh с CAP_NET_ADMIN и доступом к /dev/net/tun.

Каталог /etc/ghulakh принадлежит root:ghulakh (0750), EnvironmentFile и credential digest — root:ghulakh (0640), а Noise private key доступен service account только через отдельный файл. Сервер не может заменять конфигурацию или credential digest через права каталога. Сервис не может менять sysctl благодаря systemd hardening. Серверный EnvironmentFile находится в /etc/ghulakh/server.env. Для согласованности egress policy установщик проверяет фиксированные значения TUN name, gateway bind (0.0.0.0:4434), forwarding flags и путей к секретам; изменение этих параметров требует отдельного изменения deployment unit и firewall policy.

## Добавление устройства

~~~
sudo bash tools/deploy-server.sh credential
~~~

Команда генерирует отдельный 256-битный credential, добавляет только SHA-256 digest в серверный файл и выводит исходный секрет один раз. Передайте его устройству по защищённому каналу. Не копируйте секрет в логи, Git или тикеты.

## Обновление

Соберите и передайте новый бинарник, затем выполните ту же команду с действующими WAN/IPv6 параметрами:

~~~
sudo bash tools/deploy-server.sh update \
  --binary /absolute/path/to/new-ghulakh-server \
  --wan-interface eth0 \
  --ipv6-mode nat66
~~~

Новая версия размещается в отдельном release directory. Активная ссылка переключается атомарно. Если активация не проходит, установщик возвращает предыдущую ссылку, оба systemd unit-файла и ownership marker из снимков, затем восстанавливает прежние состояния enablement и активности служб. После этого он проверяет фактические LoadState, ActiveState и UnitFileState через systemd, сравнивает восстановленные unit-файлы и marker со снимками и проверяет цель current. Несовпадение считается неудачным rollback: снимки сохраняются, а установщик сообщает о необходимости ручного восстановления. Предыдущие release directories сохраняются для ручного восстановления. WAN interface и IPv6 mode нельзя менять через update: исходные значения читаются из проверенного checksum ownership marker systemd unit-файла, а запрошенные значения сравниваются с сохранённой ExecStart-строкой до создания/изменения service account, каталогов, release или credentials. Несовпадение приводит к отказу без изменения deployment state. Для изменения сетевой топологии требуется отдельная проверенная процедура.

Оба systemd unit-файла сначала формируются и проверяются во временном каталоге. До замены сохраняются предыдущие версии обоих файлов и ownership marker. Замена каждого файла выполняется через rename в пределах /etc/systemd/system; если установка второго unit или обновление marker завершается ошибкой, оба unit-файла и marker восстанавливаются. Обработчики HUP/INT/TERM также запускают rollback. При первой установке новые службы сначала останавливаются и отключаются, пока systemd ещё видит их unit-файлы; только после этого файлы удаляются и выполняется daemon-reload. После rollback проверяются фактические LoadState, ActiveState и UnitFileState, а также ссылка current и содержимое восстановленных unit-файлов/marker. Если сам rollback не удаётся или его результат нельзя подтвердить, резервные файлы сохраняются, а ошибка явно выводится; в таком случае не продолжайте обновление и восстановите файлы вручную по сообщению установщика. Если соответствующего управляемого unit-файла нет, установщик проверяет LoadState и отказывается перекрывать vendor, generated или transient unit с тем же именем. При ошибке создания snapshot его частичный каталог удаляется до любых переключений. Перед активацией обновления установщик проверяет, что прежние службы находятся в состояниях active/inactive и имеют поддерживаемое состояние enablement; неизвестное состояние приводит к отказу до переключения release. Состояния enabled-runtime и masked-runtime при rollback восстанавливаются именно как runtime-настройки. Persistent masked unit не принимается, поскольку он заменяет unit-файл символической ссылкой.

Обновление не перезаписывает server.env, Noise keys или credential digests.

## Проверка состояния

Команда status проверяет владельца и права каталогов и ownership marker, владельца, режим 0644 и отсутствие hard links у обоих systemd units, их checksum, структурную принадлежность nftables tables и расположение active release. Для каждой службы она также запрашивает у systemd LoadState, FragmentPath, ActiveState и UnitFileState: FragmentPath обязан указывать ровно на проверенный файл в /etc/systemd/system, служба должна быть active и persistently enabled. MainPID сервера должен принадлежать cgroup ghulakh-server.service, его executable должен соответствовать текущему release, а процесс должен удерживать открытый /dev/net/tun. Ошибка любого запроса или несовпадение приводит к ненулевому коду.

~~~
sudo bash tools/deploy-server.sh status
sudo systemctl status ghulakh-server.service ghulakh-egress.service
sudo journalctl -u ghulakh-server.service -u ghulakh-egress.service
~~~

## Удаление

~~~
sudo bash tools/deploy-server.sh uninstall
~~~

Если первая установка завершилась до создания unit-файлов и active-ссылки, пустой ownership marker позволяет удалить только staging reservation и release tree; постоянная конфигурация и учётная запись сохраняются. Непустой marker без active-ссылки не считается безопасной частичной установкой. До подтверждения удаление проверяет владельца и режим release root и releases directory, link count ownership marker; проверяет, что current указывает внутрь releases; запрещает symlink, hard link и объекты с чужим UID/GID внутри удаляемого release tree; повторно сверяет checksum systemd units и структурно проверяет ownership comment каждой существующей nftables table. Для status дополнительно требуется полный набор таблиц активного режима: общие IPv4/egress таблицы и NAT66 только при nat66; отсутствие любой ожидаемой таблицы считается ошибкой. Маркер должен находиться непосредственно в JSON-объекте нужной таблицы. При любой неоднозначности удаление прекращается. Ошибки остановки служб прекращают удаление до файловой очистки; ошибка daemon-reload запускает восстановление unit-файлов и active-ссылки из временной копии, а при неполном восстановлении путь к копии сообщается оператору. При неудаче удаления releases оставшиеся данные не маскируются успешным завершением: root-owned recovery journal создаётся перед удалением units и active-ссылки. Повторный uninstall проверяет журнал, отсутствие units/current, владельца и безопасную структуру оставшегося release tree, затем запрашивает точное подтверждение. Только после подтверждения выполняется systemd daemon-reload и продолжается очистка; при отмене системное состояние не меняется. Persistent configuration не затрагивается. Если журнал или состояние неоднозначны, автоматическое восстановление прекращается. Требуется точный ввод REMOVE GHULAKH. Удаляются только проверенные собственные systemd units, release directories, активная ссылка и принадлежащие приложению nftables tables. Сохраняются /etc/ghulakh (EnvironmentFile, Noise keys, credential digests), /var/lib/ghulakh и системная учётная запись. Они оставлены намеренно, чтобы удаление runtime не уничтожало ключи и учётные данные. Удалять их можно отдельно после резервного копирования и ручной проверки.

Если unit-файл изменён администратором, не является обычным файлом (включая битую символическую ссылку) или не содержит маркер установщика, установка и обновление останавливаются вместо замены неизвестного пути.

## Сетевые границы

Установщик не меняет:
- net.ipv4.ip_forward, IPv6 forwarding или другие sysctl;
- маршруты, policy routing и RA;
- host INPUT rules и UDP-доступ к gateway;
- чужие nftables tables/chains;
- настройки SSH, DNS, package manager, Docker или другие службы.

Egress unit использует только собственные таблицы inet ghulakh_egress, ip ghulakh_nat4 и, для nat66, ip6 ghulakh_nat6. Если такие таблицы уже установлены вручную, перед запуском unit удалите их только штатной командой sudo bash tools/configure-egress-nftables.sh --remove после проверки ownership marker. Не сохраняйте параллельную копию этих таблиц в другом firewall startup config.

Входящий UDP-порт gateway по умолчанию 4434. Разрешение входящего трафика в существующем INPUT firewall остаётся отдельным решением администратора. Установщик его не открывает.

## Проверки и ограничения

Автоматические deployment checks проверяют shell syntax, ключевые lifecycle invariants, отсутствие глобальных сетевых мутаций и отсутствие широкого удаления системных каталогов. Отдельные Python regression tests проверяют успешную выдачу digest и отказ для file symlink, symlink каталога, FIFO, hard link, неверного режима и неверной группы; при отказе проверяется неизменность целевого файла и отсутствие выдачи секрета. Изолированный поведенческий тест извлекает и запускает фактическую rollback-функцию с управляемым systemd shim: проверяет восстановление обоих unit-файлов, marker и current при update, остановку и удаление новых units при неудачной первой установке, а также сохранение снимков при неудачном восстановлении службы. Отдельные проверки rollback helper покрывают active/inactive, enabled/enabled-runtime/disabled/masked-runtime, отсутствие unit и отказ при несовпадении состояния или невозможности прочитать systemd. Статические проверки дополнительно подтверждают сравнение восстановленных unit-файлов, marker и current со снимками. Отдельные nftables ownership regression tests проверяют table-level marker, отклонение chain-level decoy, foreign marker, malformed/unexpected JSON и безопасное удаление принадлежащих таблиц. Release ownership/integrity regression tests проверяют root ownership, symlink/hardlink rejection, nested mount rejection, формат release ID, режимы файлов и пересчёт содержимого каждого релиза. Linux namespace tests отдельно проверяют egress policy.

Эти тесты не имитируют полноценную systemd VM и не проверяют отключение питания или SIGKILL в произвольной точке транзакции. Реальный install/update/reboot/rollback/uninstall на отдельной VM/VPS остаётся обязательным этапом.

Эти проверки не доказывают успешный запуск на конкретном VPS, доступность UDP-порта у провайдера, корректность host firewall, live VK TURN relay или сквозной Android → relay → VPS → Internet маршрут. До таких проверок проект остаётся исследовательской системой, а не production VPN.
