# Фазы одного запроса

[English](#english) · [Русский](#русский)

Заметка о том, от какого момента считаются DNS, TCP, TLS, ожидание и передача, что происходит с неудачным адресом и когда connect с TLS оцениваются, а не измеряются. Коротко те же числа описаны в [README](README.md).

## English

### One clock for the step

`perform` in [`src/client.rs`](src/client.rs) takes an `Instant` before DNS. `ttfb_ms` is the elapsed time from that instant until the HTTP response headers have arrived. `total_ms` is the elapsed time until the body has been collected, or until the error is known. DNS, connect, and TLS are nested inside that same interval. They are not a second clock that starts at zero after the previous phase.

`TimingMetrics::finalize` then fills the two derived fields:

```text
wait_ms = max(0, ttfb_ms − dns_ms − connect_ms − tls_ms)
xfer_ms = max(0, total_ms − ttfb_ms)
```

The `max` keeps a rounding edge from printing a negative bar. On a measured request the five phases sum to `total_ms`. A phase of zero is left out of the waterfall drawing.

`HEAD` stops before the body. `bytes` is 0 and `xfer_ms` is whatever remains between the header arrival and the end of the call.

### What each phase includes

| Phase | Starts | Stops |
|---|---|---|
| DNS | The resolver call | The address list is in hand |
| Connect | The first TCP attempt | The attempt that completed, including the failed ones before it |
| TLS | The handshake call | `TlsConnector::connect` returns |
| TTFB | The step's `Instant` | Response headers are available |
| Total | The step's `Instant` | The body is buffered, or the call has failed |

An IP literal and a `--resolve HOST:PORT:ADDR` pin set `dns_ms` to 0. The pin keeps the Host header and the TLS server name of the URL. The format splits on the first two colons, so an IPv6 address may contain further colons. Brackets around that address are stripped. The port is 1–65535. A second pin for the same host and port is an error. `-4` and `-6` reject a pin of the other family.

A proxy that resolves the target itself (`http`, `https`, `socks5h`) also leaves `dns_ms` at 0 and leaves `ip` empty. The time to resolve and reach the proxy sits in `connect_ms`. For an HTTPS origin behind an HTTP proxy, `connect_ms` covers TCP to the proxy, TLS to the proxy when the proxy URL is `https`, and the `CONNECT` exchange. `tls_ms` starts when the handshake with the origin begins. The proxy path is in [PROXY.md](PROXY.md).

### Addresses, one after another

The resolver returns every address of the requested family. The client dials them in that order. It does not race them.

The deadline is one `Instant` for the whole redirect chain, created in [`src/analyzer.rs`](src/analyzer.rs). The default is 20 seconds. Before each TCP attempt the remaining time is divided by the number of addresses still to try, so one blackholed address cannot consume the entire budget. A refused connection records `connect_ms` as the time since the first attempt and moves to the next address. When every address fails, that accumulated time is the hop's `connect_ms`, and `ttfb_ms` / `total_ms` still run from the step's original `Instant`.

A TLS error returns immediately. The next address is not tried. If verification was enabled, a second connection of at most 5 seconds (`TLS_PROBE_MAX`) performs the handshake with a verifier that accepts any certificate, and the parsed certificate is attached to the error. The probe's time is outside `tls_ms`. The hop still fails.

### The 30/70 estimate

Some failure paths know TTFB and DNS and do not have a measured connect or TLS. `finalize` treats that case as follows.

For `https://`, when connect was not measured and TLS was not measured either:

```text
gap          = max(0, ttfb_ms − dns_ms)
connect_ms   = gap × 0.30
tls_ms       = gap × 0.70
is_estimated = true
```

For `http://` the same gap becomes `connect_ms`, `tls_ms` stays 0, and `is_estimated` stays false. The ratios live in [`src/exit.rs`](src/exit.rs) as `CONNECT_PHASE_RATIO` and `TLS_PHASE_RATIO`.

A hop that really completed a TCP connect sets `connect_measured`, and an HTTPS hop that completed a handshake sets `tls_measured`. Those flags are not exported. `is_estimated` is. The waterfall appends `estimated` to the Connect and TLS labels when it is set. HAR copies it to `timings._estimated`.

### Redirect hops

Every hop calls `perform` again. DNS, TCP, and TLS are measured from scratch. The deadline is the same `Instant`, so a slow first hop shortens the budget of the next one. A hop that finds the deadline already passed becomes a network error, `Request timeout exhausted`, with empty timings.

### What the tests check

`models::tests::derived_wait_and_transfer` builds a timing with DNS 10, connect 20, TLS 50, TTFB 100, total 160 and expects wait 20 and transfer 60.

`models::tests::estimates_https_when_phases_were_not_measured` leaves connect and TLS unmeasured on an HTTPS timing whose TTFB is 100 and expects connect 30, TLS 70, and `is_estimated`.

`live_tests::http_get_reports_phases_and_status` checks that a local HTTP/1.1 response reports status 200, `total >= ttfb`, and a non-negative connect.

## Русский

### Одни часы на шаг

`perform` в [`src/client.rs`](src/client.rs) берёт `Instant` до DNS. `ttfb_ms` — это время от него до прихода заголовков ответа. `total_ms` — время до тех пор, пока тело собрано или пока известна ошибка. DNS, connect и TLS лежат внутри того же интервала. Это не вторые часы, которые стартуют с нуля после предыдущей фазы.

`TimingMetrics::finalize` заполняет два производных поля:

```text
wait_ms = max(0, ttfb_ms − dns_ms − connect_ms − tls_ms)
xfer_ms = max(0, total_ms − ttfb_ms)
```

`max` не даёт краю округления нарисовать отрицательный столбик. На измеренном запросе пять фаз в сумме дают `total_ms`. Фаза с нулём на рисунке waterfall не показывается.

`HEAD` останавливается до тела. `bytes` равен 0, а `xfer_ms` — это то, что осталось между приходом заголовков и концом вызова.

### Что входит в фазу

| Фаза | Начало | Конец |
|---|---|---|
| DNS | Вызов резолвера | Список адресов уже в руках |
| Connect | Первая попытка TCP | Попытка, которая удалась, вместе с неудачными до неё |
| TLS | Вызов рукопожатия | `TlsConnector::connect` вернулся |
| TTFB | `Instant` шага | Заголовки ответа доступны |
| Total | `Instant` шага | Тело буферизовано или вызов упал |

IP-литерал и привязка `--resolve HOST:PORT:ADDR` ставят `dns_ms` в 0. Привязка сохраняет заголовок Host и имя сервера TLS из URL. Формат режется по первым двум двоеточиям, поэтому в IPv6-адресе двоеточия могут остаться. Скобки вокруг адреса снимаются. Порт — от 1 до 65535. Вторая привязка на тот же хост и порт — ошибка. `-4` и `-6` отвергают привязку чужого семейства.

Прокси, который резолвит цель сам (`http`, `https`, `socks5h`), тоже оставляет `dns_ms` равным 0 и оставляет `ip` пустым. Время резолва и пути до прокси сидит в `connect_ms`. Для HTTPS-origin за HTTP-прокси `connect_ms` покрывает TCP до прокси, TLS до прокси, если URL прокси — `https`, и обмен `CONNECT`. `tls_ms` начинается, когда стартует рукопожатие с origin. Путь через прокси описан в [PROXY.md](PROXY.md).

### Адреса по очереди

Резолвер возвращает все адреса запрошенного семейства. Клиент звонит им в этом порядке. Гонки нет.

Дедлайн — один `Instant` на всю цепочку редиректов, его создаёт [`src/analyzer.rs`](src/analyzer.rs). По умолчанию это 20 секунд. Перед каждой попыткой TCP остаток времени делится на число адресов, которые ещё предстоит попробовать, поэтому один «чёрный» адрес не съедает весь бюджет. Отказ в соединении записывает `connect_ms` как время с первой попытки и переходит к следующему адресу. Когда не ответил ни один, накопленное время и есть `connect_ms` хопа, а `ttfb_ms` и `total_ms` по-прежнему считаются от исходного `Instant` шага.

Ошибка TLS возвращается сразу. Следующий адрес не пробуется. Если проверка была включена, второе соединение длительностью не больше 5 секунд (`TLS_PROBE_MAX`) проходит рукопожатие с верификатором, который принимает любой сертификат, и разобранный сертификат прикладывается к ошибке. Время зонда в `tls_ms` не входит. Хоп всё равно считается неудачным.

### Оценка 30/70

На некоторых путях ошибки известны TTFB и DNS, а измеренных connect и TLS нет. `finalize` обрабатывает это так.

Для `https://`, когда connect не измерен и TLS тоже не измерен:

```text
gap          = max(0, ttfb_ms − dns_ms)
connect_ms   = gap × 0.30
tls_ms       = gap × 0.70
is_estimated = true
```

Для `http://` тот же промежуток становится `connect_ms`, `tls_ms` остаётся 0, а `is_estimated` остаётся false. Доли лежат в [`src/exit.rs`](src/exit.rs): `CONNECT_PHASE_RATIO` и `TLS_PHASE_RATIO`.

Хоп, который действительно завершил TCP, ставит `connect_measured`, а HTTPS-хоп с завершённым рукопожатием ставит `tls_measured`. Эти флаги наружу не отдаются. `is_estimated` отдаётся. Waterfall дописывает `estimated` к подписям Connect и TLS, когда флаг установлен. HAR копирует его в `timings._estimated`.

### Хопы редиректа

Каждый хоп снова вызывает `perform`. DNS, TCP и TLS измеряются заново. Дедлайн — тот же `Instant`, поэтому медленный первый хоп укорачивает бюджет следующего. Хоп, который застаёт дедлайн уже прошедшим, становится сетевой ошибкой `Request timeout exhausted` с пустыми таймингами.

### Что проверяют тесты

`models::tests::derived_wait_and_transfer` собирает тайминг с DNS 10, connect 20, TLS 50, TTFB 100, total 160 и ждёт wait 20 и transfer 60.

`models::tests::estimates_https_when_phases_were_not_measured` оставляет connect и TLS неизмеренными на HTTPS-тайминге с TTFB 100 и ждёт connect 30, TLS 70 и `is_estimated`.

`live_tests::http_get_reports_phases_and_status` проверяет, что локальный ответ HTTP/1.1 даёт статус 200, `total >= ttfb` и неотрицательный connect.
