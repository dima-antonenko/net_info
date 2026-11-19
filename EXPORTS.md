# Отчёты

[English](#english) · [Русский](#русский)

Заметка о четырёх представлениях одного и того же прогона: JSON, HAR 1.2, textfile Prometheus и трейс OTLP/HTTP. Секреты в каждом из них уже замаскированы, см. [README](README.md). Числа фаз — те, что описаны в [TIMING.md](TIMING.md).

## English

Exports run after the report has been printed. A failure to write one of them sets the exit code to 73, which outranks `--fail` (22) and a missed SLO (4). A path of `-` for JSON and HAR writes the document to stdout. The same writer accepts `-` for Prometheus. A successful write to a real path prints `Exported ...` on stderr. The file is written to a temporary sibling and renamed into place, and parent directories are created.

### JSON

`--json PATH` writes one document:

```json
{
  "schema_version": 1,
  "net_info_version": "0.1.0",
  "timestamp": "2026-11-19T17:00:00+00:00",
  "initial_url": "https://example.com/",
  "total_steps": 1,
  "steps": [],
  "summary": {
    "total_time_ms": 0,
    "final_status": 200,
    "final_url": "https://example.com/",
    "final_bytes": 0,
    "errors": 0
  }
}
```

`summary.total_time_ms` sums `total_ms` of the hops that have no error. `final_status` and `final_bytes` come from the last hop when that hop succeeded. `final_url` is the URL of the last hop. `errors` counts hops that failed or that hit the redirect limit. `timestamp` is UTC, `YYYY-MM-DDTHH:MM:SS+00:00`.

When `--slo` or `--slo-file` was set and a hop could be evaluated, `summary.slo` is:

```json
{
  "pass": false,
  "thresholds_ms": {"total": 500, "ttfb": 200},
  "violations": [
    {"key": "total", "threshold_ms": 500, "actual_ms": 800, "delta_ms": 300}
  ]
}
```

`delta_ms` is `actual_ms − threshold_ms`. Keys in `violations` follow the key order of the threshold map.

Each step carries `url`, `step_number`, `request` (`method`, masked `headers`, `body_bytes`), `timing`, `network`, `response`, `error`, `note`, `redirect_limit_reached`, and `proxy`. Timing fields are the seven millisecond values plus `is_estimated`. `connect_measured` and `tls_measured` stay inside the process.

`network` includes `ip`, `ip_family` (`IPv4` or `IPv6`), `http_version` (`HTTP/1.1` or `HTTP/2.0`), `tls_version`, `tls_cipher`, the certificate fields, `tls_verified`, `tls_custom_ca`, `proxy_url`, and `proxy_source`. For plain HTTP, `tls_verified` and `tls_custom_ca` are null. For a verified HTTPS hop, `tls_verified` is true. For `--insecure`, it is false. `tls_custom_ca` is true only when `--cacert` was used.

Response headers are lower-cased, and repeated values are joined with `, `. `Date` is parsed with `httpdate` and stored as the same ISO form as the report timestamp. `response.bytes` is the raw body length. `HEAD` reports 0.

### HAR 1.2

`--har PATH` writes a log whose `creator` is `net-info`. There is one page, `page_1`, titled with the initial URL. Entries are laid back to back and end at the time of the export. Their wall clock is reconstructed from the phase sums, so the timestamps are a timeline of the measured durations, not the original start time of the process.

HAR timings, in milliseconds:

| HAR field | Source |
|---|---|
| `blocked` | `-1` |
| `dns` | `dns_ms` |
| `connect` | `connect_ms + tls_ms`. HAR's connect includes the handshake |
| `ssl` | `tls_ms` for an `https:` URL, otherwise `-1` |
| `send` | `0` |
| `wait` | `wait_ms` |
| `receive` | `xfer_ms` |

`time` on the entry sums the non-negative values of `blocked`, `dns`, `connect`, `send`, `wait`, and `receive`. `ssl` is not added again. A failed hop uses `-1` for `blocked`, `dns`, `connect`, and `ssl`, and `0` for `send`, `wait`, and `receive`. An estimated timing sets `timings._estimated` to true.

The request records the method, the redacted URL, the HTTP version, masked headers, the query string split on `&` and `=`, `headersSize: -1`, and `bodySize` from the request body length. The response records status, a short reason for the common codes, headers, `mimeType` (or `x-unknown`), `redirectURL`, and the body size. `serverIPAddress` is set when the hop has an address.

Custom fields: `_tls` (version, cipher, certificate CN, issuer, days left, verified), `_proxy` (url and source), `_redirectLimitReached`, and on the response `_error` plus `_errorKind`.

### Prometheus

`--prometheus PATH` writes a textfile. The prefix is `net_info_`, so a scraper can tell this exporter from httptap's `httptap_request_*` metrics. Durations are seconds.

| Metric | Type | Meaning |
|---|---|---|
| `net_info_request_success` | gauge | `1` when the hop has no error, `0` when it does |
| `net_info_request_duration_seconds` | gauge | One sample per phase: `dns`, `connect`, `tls`, `ttfb`, `wait`, `xfer`, `total` |
| `net_info_response_status_code` | gauge | The HTTP status |
| `net_info_response_body_size_bytes` | gauge | Raw body length |
| `net_info_last_run_timestamp_seconds` | gauge | When the file was written |

Labels on the request metrics are `host` (the hostname only) and `step`. The duration metric adds `phase`. The timestamp metric is labeled with the host of the first hop. A failed hop emits `net_info_request_success 0` and skips the duration, status, and size samples.

### OTLP

`--otlp ENDPOINT` POSTs one OTLP/HTTP JSON document. A trailing slash is stripped. `/v1/traces` is appended when the URL does not already end with it. The call uses the same `perform` client, forced to HTTP/1.1, with `Content-Type: application/json`. `Settings::default()` leaves the proxy disabled, so this POST does not follow the proxy of the measured request. The deadline is the same timeout the CLI was given. A transport error or a status outside 2xx is an export failure.

The trace has one resource, `service.name=net-info`. The root span is `net-info.analysis`. Each hop is a child `http.request`. Under it, in order, are `http.dns`, `http.connect`, `http.tls`, `http.wait`, and `http.xfer`. Phase spans share the hop's interval and are placed end to end from the phase durations. TTFB is an attribute of the measurement, not its own span: it is the sum of the phases before transfer. Trace and span ids are hex from `/dev/urandom`.

Hop attributes include `net_info.step_number`, `http.request.method`, `http.response.status_code`, `http.response.body.size`, `server.address`, `network.peer.address`, `network.protocol.version`, and `tls.protocol.version`, whichever of those the hop actually has. Each phase span carries `net_info.phase` and `net_info.duration_ms`.

The Cargo feature `otel` is empty. The JSON encoder above is always compiled.

### What the tests check

`export::tests::prometheus_skips_timings_for_failures` builds a failed hop and expects the success gauge to be 0 with no phase samples.

`live_tests::http_get_reports_phases_and_status` writes `--json` and checks status 200, `HTTP/1.1`, and the ordering `total >= ttfb`.

`live_tests::tls_insecure_and_custom_ca` writes a HAR after a custom CA and expects exit 0, which means the archive was written.

`live_tests::follows_redirects_and_masks_secrets` checks that the JSON file does not contain the raw secret.

## Русский

Экспорт идёт после того, как отчёт уже напечатан. Неудача записи любого из них ставит код выхода 73. Он важнее `--fail` (22) и сорванного SLO (4). Путь `-` у JSON и HAR пишет документ в stdout. Тот же писатель принимает `-` и для Prometheus. Успешная запись в настоящий путь печатает `Exported ...` в stderr. Файл пишется во временного соседа и переименовывается на место, родительские каталоги создаются.

### JSON

`--json PATH` пишет один документ:

```json
{
  "schema_version": 1,
  "net_info_version": "0.1.0",
  "timestamp": "2026-11-19T17:00:00+00:00",
  "initial_url": "https://example.com/",
  "total_steps": 1,
  "steps": [],
  "summary": {
    "total_time_ms": 0,
    "final_status": 200,
    "final_url": "https://example.com/",
    "final_bytes": 0,
    "errors": 0
  }
}
```

`summary.total_time_ms` суммирует `total_ms` хопов без ошибки. `final_status` и `final_bytes` берутся с последнего хопа, если он успешен. `final_url` — URL последнего хопа. `errors` считает хопы, которые упали или упёрлись в предел редиректов. `timestamp` — это UTC в виде `YYYY-MM-DDTHH:MM:SS+00:00`.

Когда заданы `--slo` или `--slo-file` и хоп удалось проверить, `summary.slo` выглядит так:

```json
{
  "pass": false,
  "thresholds_ms": {"total": 500, "ttfb": 200},
  "violations": [
    {"key": "total", "threshold_ms": 500, "actual_ms": 800, "delta_ms": 300}
  ]
}
```

`delta_ms` — это `actual_ms − threshold_ms`. Ключи в `violations` идут в порядке карты порогов.

Каждый шаг несёт `url`, `step_number`, `request` (`method`, замаскированные `headers`, `body_bytes`), `timing`, `network`, `response`, `error`, `note`, `redirect_limit_reached` и `proxy`. Поля тайминга — семь значений в миллисекундах плюс `is_estimated`. `connect_measured` и `tls_measured` остаются внутри процесса.

`network` включает `ip`, `ip_family` (`IPv4` или `IPv6`), `http_version` (`HTTP/1.1` или `HTTP/2.0`), `tls_version`, `tls_cipher`, поля сертификата, `tls_verified`, `tls_custom_ca`, `proxy_url` и `proxy_source`. У обычного HTTP `tls_verified` и `tls_custom_ca` равны null. У проверенного HTTPS-хопа `tls_verified` равен true. У `--insecure` он false. `tls_custom_ca` равен true только когда использован `--cacert`.

Заголовки ответа приводятся к нижнему регистру, повторы склеиваются через `, `. `Date` разбирается через `httpdate` и хранится в том же виде ISO, что и время отчёта. `response.bytes` — длина сырого тела. `HEAD` сообщает 0.

### HAR 1.2

`--har PATH` пишет лог, у которого `creator` — `net-info`. Страница одна, `page_1`, заголовок — исходный URL. Записи уложены встык и заканчиваются в момент экспорта. Их настенное время восстанавливается из сумм фаз, поэтому метки — это шкала измеренных длительностей, а не исходный старт процесса.

Тайминги HAR, в миллисекундах:

| Поле HAR | Откуда |
|---|---|
| `blocked` | `-1` |
| `dns` | `dns_ms` |
| `connect` | `connect_ms + tls_ms`. В HAR connect включает рукопожатие |
| `ssl` | `tls_ms` для URL `https:`, иначе `-1` |
| `send` | `0` |
| `wait` | `wait_ms` |
| `receive` | `xfer_ms` |

`time` записи суммирует неотрицательные `blocked`, `dns`, `connect`, `send`, `wait` и `receive`. `ssl` второй раз не прибавляется. У упавшего хопа `blocked`, `dns`, `connect` и `ssl` равны `-1`, а `send`, `wait` и `receive` равны `0`. У оценённого тайминга `timings._estimated` равен true.

Запрос записывает метод, замаскированный URL, версию HTTP, замаскированные заголовки, query string, разрезанный по `&` и `=`, `headersSize: -1` и `bodySize` по длине тела запроса. Ответ записывает статус, короткую причину для частых кодов, заголовки, `mimeType` (или `x-unknown`), `redirectURL` и размер тела. `serverIPAddress` ставится, когда у хопа есть адрес.

Дополнительные поля: `_tls` (версия, шифр, CN сертификата, издатель, дни до истечения, проверен ли), `_proxy` (url и source), `_redirectLimitReached`, а у ответа ещё `_error` и `_errorKind`.

### Prometheus

`--prometheus PATH` пишет textfile. Префикс — `net_info_`, поэтому сборщик отличает этот экспортёр от метрик httptap `httptap_request_*`. Длительности — в секундах.

| Метрика | Тип | Смысл |
|---|---|---|
| `net_info_request_success` | gauge | `1`, если у хопа нет ошибки, и `0`, если есть |
| `net_info_request_duration_seconds` | gauge | По сэмплу на фазу: `dns`, `connect`, `tls`, `ttfb`, `wait`, `xfer`, `total` |
| `net_info_response_status_code` | gauge | HTTP-статус |
| `net_info_response_body_size_bytes` | gauge | Длина сырого тела |
| `net_info_last_run_timestamp_seconds` | gauge | Когда файл записан |

Метки метрик запроса — `host` (только имя хоста) и `step`. У длительности добавляется `phase`. Метрика времени помечена хостом первого хопа. Упавший хоп пишет `net_info_request_success 0` и пропускает сэмплы длительности, статуса и размера.

### OTLP

`--otlp ENDPOINT` отправляет POST с одним JSON-документом OTLP/HTTP. Хвостовой слэш снимается. `/v1/traces` дописывается, если URL ещё на него не кончается. Вызов идёт через тот же клиент `perform`, принудительно по HTTP/1.1, с `Content-Type: application/json`. `Settings::default()` оставляет прокси выключенным, поэтому этот POST не идёт через прокси измеренного запроса. Дедлайн — тот же timeout, который дали CLI. Ошибка транспорта или статус вне 2xx — ошибка экспорта.

У трейса один resource, `service.name=net-info`. Корневой спан — `net-info.analysis`. Каждый хоп — дочерний `http.request`. Под ним по порядку идут `http.dns`, `http.connect`, `http.tls`, `http.wait` и `http.xfer`. Спаны фаз делят интервал хопа и стоят встык по длительностям фаз. TTFB — атрибут измерения, а не отдельный спан: это сумма фаз до передачи. Идентификаторы трейса и спанов — hex из `/dev/urandom`.

Атрибуты хопа включают `net_info.step_number`, `http.request.method`, `http.response.status_code`, `http.response.body.size`, `server.address`, `network.peer.address`, `network.protocol.version` и `tls.protocol.version` — те из них, которые у хопа есть. У спана фазы есть `net_info.phase` и `net_info.duration_ms`.

Cargo-feature `otel` пустая. Кодировщик JSON выше собирается всегда.

### Что проверяют тесты

`export::tests::prometheus_skips_timings_for_failures` собирает упавший хоп и ждёт gauge успеха 0 без сэмплов фаз.

`live_tests::http_get_reports_phases_and_status` пишет `--json` и проверяет статус 200, `HTTP/1.1` и порядок `total >= ttfb`.

`live_tests::tls_insecure_and_custom_ca` пишет HAR после своего CA и ждёт код 0, а это значит, что архив записан.

`live_tests::follows_redirects_and_masks_secrets` проверяет, что в JSON-файле нет сырого секрета.
