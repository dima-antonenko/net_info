# net_info

[English](#english) · [Русский](#русский)

## English

`net_info` is a diagnostic CLI for a single HTTP request. The binary is `net-info`. It splits that request into DNS, TCP connect, TLS, server wait, and body transfer, then prints a waterfall. A redirect chain is a sequence of such requests, each on a fresh connection. The tool follows the behaviour of [httptap](https://github.com/ozeranskii/httptap) 0.8.2 closely enough that an existing command can be moved by renaming the binary. The license is Apache-2.0.

It measures one request. A load generator, a session with cookies, a full-screen interface, gRPC, WebSocket, and HTTP/3 are outside this crate.

The sections below cover, in order: what the phases mean, how they are measured, how to run the CLI, and where the reports go. The mechanics that are easy to get wrong have their own notes: [TIMING.md](TIMING.md), [REDIRECTS.md](REDIRECTS.md), [PROXY.md](PROXY.md), and [EXPORTS.md](EXPORTS.md).

### In short

```text
net-info https://example.com
net-info --metrics-only --json - https://example.com/health
net-info -L --fail --slo total=500,ttfb=200 https://example.com
```

One successful HTTPS request produces seven numbers, all in milliseconds:

| Field | What the clock measured |
|---|---|
| `dns_ms` | Name lookup |
| `connect_ms` | TCP to the address that answered. Time spent on earlier failed addresses is included |
| `tls_ms` | Handshake with the origin. Zero for `http://` |
| `ttfb_ms` | From the start of the step until the first byte of the response |
| `wait_ms` | `max(0, ttfb − dns − connect − tls)` |
| `xfer_ms` | `max(0, total − ttfb)`, the body after the first byte |
| `total_ms` | From the start of the step until the body has been read |

`cargo test` passes: 20 library tests and 1 integration test. They talk to local listeners. A live trip to the public internet is not required.

### What one request is made of

A URL hides several round trips.

**DNS** turns the host into one or more addresses. An IP literal and a `--resolve` pin skip this, so `dns_ms` stays 0. Internationalized names are converted to ASCII (IDNA) before the query.

**TCP** opens a connection to one of those addresses. Addresses are tried one after another. The time of a refused or timed-out attempt stays inside `connect_ms`, the same way `curl`'s `time_connect` keeps it. The budget left until the deadline is split across the addresses that have not been tried yet.

**TLS** runs only for `https://`. The clock starts after TCP is up and stops when the handshake finishes. The peer certificate is parsed for the common name, DNS subject alternative names, issuer, serial, validity window, and days remaining. The cipher name is the IANA name from rustls (`TLS_AES_128_GCM_SHA256`), which differs from the OpenSSL spelling httptap prints.

**Wait** is the remainder of the time-to-first-byte after DNS, TCP, and TLS have been subtracted. It is the server thinking, plus any queueing the earlier phases did not cover.

**Transfer** is everything after the first response byte: headers that arrived with it are already inside TTFB, and the rest of the body is `xfer_ms`. `HEAD` does not read a body, so the byte count stays 0.

`ttfb_ms` and `total_ms` both include DNS. They are taken from one `Instant` that starts before lookup, so the phases add up to the wall clock of the step.

### How net-info measures it

`reqwest` hides these phases. The client in [`src/client.rs`](src/client.rs) times them itself: `hickory-resolver` for DNS, `TcpStream` for connect, `tokio-rustls` for the handshake, and `hyper` for HTTP/1.1 and HTTP/2. ALPN offers `h2` and then `http/1.1` when HTTP/2 is enabled. A plain `http://` URL stays on HTTP/1.1. `--no-http2` (alias `--http1.1`) offers only `http/1.1`.

When connect and TLS were not measured on an HTTPS step, the gap between DNS and TTFB is split 30/70 into `connect_ms` and `tls_ms`, and `is_estimated` becomes true. The waterfall marks those two bars with `estimated`. The formulas, the shared deadline, and the address fallback are written up in [TIMING.md](TIMING.md).

Each redirect hop resolves and connects again. The default deadline for the whole chain is 20 seconds (`-m` / `--max-time` / `--timeout`).

### Using the CLI

```bash
# Waterfall on a terminal. Colors follow NO_COLOR, FORCE_COLOR, and TERM=dumb.
net-info https://example.com/health

# One machine-readable line per hop.
net-info --metrics-only https://example.com/health

# POST a JSON body. The method becomes POST because --data is set and -X is not.
net-info https://example.com/api -d '{"ok":true}'

# Read the body from a file. A .json file also sets Content-Type.
net-info https://example.com/api -d @payload.json

# Follow up to 10 redirects. 4xx/5xx still prints the report, then exits 22.
net-info -L -f https://example.com

# Pin the name to an address. The Host header and the TLS name stay as written.
net-info --resolve example.com:443:203.0.113.10 https://example.com

# Trust an extra CA, or skip verification. The two flags cannot be combined.
net-info --cacert corp.pem https://intranet.example
net-info -k https://localhost:8443

# Fail the process when the last successful hop is slower than the budget.
net-info --slo dns=20,connect=50,tls=80,ttfb=200,total=500 https://example.com
```

`--data` without an explicit method sends `POST`. An explicit `GET` or `HEAD` with a body is sent as requested, and a warning is printed on stderr. A user-supplied `Content-Type` wins over the guess. Inline text that parses as JSON becomes `application/json`. A file gets a type from its extension: `.json`, `.xml`, `.txt`, `.text`.

The default `User-Agent` is `net-info/<version>` and the default `Accept` is `*/*`. Credentials in the URL become an `Authorization: Basic` header when the caller did not already pass one. The user and password are percent-decoded first.

### Flags

| Request | |
|---|---|
| `URL` | `http://` or `https://`, with a host. Whitespace and port 0 are rejected |
| `-X`, `--request`, `--method` | `GET` `POST` `PUT` `PATCH` `DELETE` `HEAD` `OPTIONS` |
| `-d`, `--data` | Body, or `@file` |
| `-H`, `--header` | Repeatable `Name: value` |
| `-L`, `--location`, `--follow` | Follow redirects, at most 10 |
| `-m`, `--max-time`, `--timeout` | Deadline for the whole chain, seconds. Default 20 |
| `--no-http2`, `--http1.1` | Stay on HTTP/1.1 |
| `-f`, `--fail` | Exit 22 when any hop returned 4xx or 5xx |
| `-4`, `--ipv4` / `-6`, `--ipv6` | One address family. The two flags exclude each other |
| `--resolve HOST:PORT:ADDR` | Dial `ADDR` for that host and port. Repeatable. Brackets around an IPv6 address are optional |

| TLS and proxy | |
|---|---|
| `-k`, `--insecure`, `--ignore-ssl` | Skip certificate verification |
| `--cacert`, `--ca-bundle` | Extra PEM certificates, added to the webpki root set |
| `-x`, `--proxy` | `http`, `https`, `socks5`, `socks5h`. An empty string ignores proxy environment variables |

| Output | |
|---|---|
| `--compact` | One line per hop, plus a redirect table when there is more than one hop |
| `--metrics-only` | `key=value` lines. Wins over `--compact` |
| `--json PATH` | JSON report. `-` writes it to stdout |
| `--har PATH` | HAR 1.2. `-` writes it to stdout |
| `--prometheus PATH` | Prometheus textfile. The metric prefix is `net_info_` |
| `--otlp ENDPOINT` | One OTLP/HTTP JSON trace. `/v1/traces` is appended when it is missing |
| `--slo KEY=MS[,...]` | Budgets in milliseconds |
| `--slo-file PATH` | Same keys, one per line. Blank lines and `#` comments are skipped. `--slo` overrides a key from the file |

`--help` and `--version` exit 0. A bad flag or a rejected URL exits 64. Messages about validation and export go to stderr. The report goes to stdout.

### What you see

The default view is a panel per hop: the URL, a network line (address, HTTP version, proxy, TLS version, cipher, certificate, days left), a response line (status, size, server, redacted `Location`), and a waterfall. Bars are `█`, drawn in proportion to DNS, Connect, TLS, Wait, and Transfer, each starting where the previous bar ended. The width follows the terminal and stays between 10 and 60 columns. A chain of more than one hop adds a redirect summary. An SLO result adds its own panel.

`--compact` is a single uncolored line: status, method, URL, the five raw timings, and a human size. `--metrics-only` never uses color. A passing SLO on the evaluated hop appends `slo=pass`. A failing one appends `slo=fail` and `slo_violations=` with the keys.

Color is on when stdout is a terminal. `NO_COLOR` or `TERM=dumb` turns it off. `FORCE_COLOR` turns it on, including over `TERM=dumb`.

Certificate expiry is colored in the rich view: under 30 days is critical, under 90 is a warning.

### Redirects, proxies, TLS, SLO

Redirects, including which headers survive a cross-origin hop, are in [REDIRECTS.md](REDIRECTS.md). Proxy selection, `NO_PROXY`, CONNECT, and the difference between `socks5` and `socks5h` are in [PROXY.md](PROXY.md).

TLS verification has three modes. The default builds a root store from `webpki-roots`. `--cacert` adds the PEM file to that store. `--insecure` accepts any certificate. A failed verification opens a second connection, at most 5 seconds, with verification disabled, so the report can still show the certificate that was rejected. That probe is not a retry of the request. A TLS failure does not move on to the next address.

`--slo` and `--slo-file` accept `dns`, `connect`, `tls`, `ttfb`, `wait`, `xfer`, and `total`. Values are positive finite milliseconds. A duplicate key inside one specification is an error. The check uses the last hop that has no network error. A hop is over budget when its actual value is strictly greater than the threshold. `delta_ms` in the JSON report is `actual − threshold`. Violations are ordered by key. The process exits 4 when the check fails and nothing more severe happened.

### Reports

JSON, HAR 1.2, Prometheus, and OTLP are described field by field in [EXPORTS.md](EXPORTS.md). The JSON document carries `schema_version`, `net_info_version`, a timestamp, `initial_url`, `steps`, and `summary`. `summary.slo` appears when a budget was set. HAR timings follow the HAR rule that `connect` includes TLS and `ssl` repeats the TLS time for HTTPS. Prometheus gauges use the prefix `net_info_`. OTLP is a JSON `POST` built in this crate. The empty Cargo feature `otel` does not pull in the OpenTelemetry SDK.

### Secrets

`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `Api-Key`, and `X-Api-Key` are masked before they reach the screen or a report. A value of 8 characters or fewer becomes `****`. A longer value keeps the first four and the last four characters: `Bearer supersecret` is stored as `Bear****cret`. Userinfo in a URL becomes `user:****` when a password is present, and `****` when it is only a token. The same masking is applied to `Location` and `Content-Location`.

### Exit codes

The first matching row wins.

| Code | When |
|---|---|
| 0 | The chain finished, exports were written, and no later rule matched. Also `--help` and `--version` |
| 4 | An SLO budget was missed |
| 22 | `--fail`, and some hop returned HTTP 4xx or 5xx |
| 47 | The redirect limit (10) was reached |
| 64 | Bad arguments, a rejected URL, a bad proxy, or an unreadable CA / SLO file |
| 70 | The analyzer produced no steps, or a step was tagged `internal` |
| 73 | JSON, HAR, Prometheus, or OTLP could not be written or accepted |
| 75 | DNS, TCP, TLS, timeout, or a refused connection |
| 130 | Ctrl-C during the request (`128 + SIGINT`) |

A network failure outranks a missed SLO and `--fail`. A redirect limit outranks a later network error. An export failure outranks HTTP 22 and SLO 4. Ctrl-C during the request returns 130 and skips the report.

### From Rust

The library entry point is `net_info::analyze`. `Settings::default()` follows no redirects, allows HTTP/2, trusts the webpki roots, and does not consult proxy environment variables. Pass `ProxyChoice::Environment` and a populated `env` map when the caller wants the CLI's proxy rules.

```rust
use std::time::Duration;

use net_info::options::{ProxyChoice, Settings};
use net_info::{analyze, Method};

#[tokio::main]
async fn main() {
    let settings = Settings {
        timeout: Duration::from_secs(20),
        proxy: ProxyChoice::Environment,
        env: std::env::vars().collect(),
        ..Settings::default()
    };
    let steps = analyze(
        "https://example.com/",
        Method::Get,
        None,
        &[],
        &settings,
    )
    .await;
    let step = &steps[0];
    println!(
        "status={:?} dns={:.1} connect={:.1} tls={:.1} total={:.1}",
        step.response.status,
        step.timing.dns_ms,
        step.timing.connect_ms,
        step.timing.tls_ms,
        step.timing.total_ms,
    );
}
```

The closure-free call is async and needs a Tokio runtime. Headers and the URL stored on a step are already redacted.

### Project layout

| File | Contents |
|---|---|
| `src/main.rs` | Starts the runtime and exits with the CLI status |
| `src/cli.rs` | Arguments, validation, colors, export, exit code |
| `src/analyzer.rs` | Redirect loop, header filtering, `determine_exit_code` |
| `src/client.rs` | DNS, TCP, TLS, HTTP/1.1, HTTP/2, proxy dialing, body |
| `src/dns.rs` | Hickory lookup, address family, IDNA |
| `src/tls.rs` | rustls config, handshake, certificate fields |
| `src/proxy.rs` | `--proxy`, environment, `NO_PROXY` |
| `src/models.rs` | `TimingMetrics`, `NetworkInfo`, `ResponseInfo`, `StepMetrics` |
| `src/render.rs` | Waterfall, compact, metrics-only |
| `src/export.rs` | JSON, HAR 1.2, Prometheus textfile |
| `src/otlp.rs` | OTLP/HTTP JSON trace |
| `src/slo.rs` | Threshold parse and evaluation |
| `src/redact.rs` | Header and URL masking |
| `src/options.rs` | `Settings`, `Verify`, `ProxyChoice` |
| `src/exit.rs` | Status codes and the 30/70 estimate ratios |
| `tests/smoke.rs` | The `net-info` binary against a local TCP server |
| `TIMING.md` | Clocks, formulas, fallback, deadline |
| `REDIRECTS.md` | Method changes and which headers are dropped |
| `PROXY.md` | How a proxy is chosen and how the tunnel is built |
| `EXPORTS.md` | JSON, HAR, Prometheus, OTLP |

### What the tests check

Unit tests cover the wait/transfer formulas, the 30/70 estimate, SLO parse and evaluation, redirect method changes (`301`/`302` POST becomes GET and drops `Content-Type`; `303` on HEAD stays HEAD; `307` POST stays POST), exit-code precedence, secret masking, `NO_PROXY` suffix and wildcard matching, and the Prometheus rule that a failed hop emits only `net_info_request_success 0`.

The local-server tests cover a plain HTTP GET, a redirect that masks URL userinfo and `Authorization`, `--fail` (22), a missed SLO (4), a redirect loop (47), a rejected URL and a bad SLO key (64), an HTTP proxy and a SOCKS5 proxy, `--insecure`, and `--cacert` with a generated CA. The integration test runs the `net-info` binary and expects `status=200` on stdout.

### Limitations

The DNS client is Hickory with its system-config feature. It reads the resolver configuration. It does not call `getaddrinfo`, so NSS modules and `/etc/hosts` are not consulted. A name that exists only in `/etc/hosts`, including some setups of `localhost`, needs `--resolve` or an IP literal.

Addresses are tried in resolver order. There is no Happy Eyeballs race.

Cipher names are IANA names. A dashboard that matches OpenSSL's `ECDHE-RSA-AES128-GCM-SHA256` will not find that string.

The certificate probe after a verification failure spends up to five extra seconds and shows the certificate. The original error still fails the hop.

`--cacert` adds certificates to the webpki roots. It does not replace them.

HTTP/2 is used when ALPN selects `h2`. There is no cleartext h2c. HTTP/3, cookies, connection reuse across hops, and a full curl feature set are out of scope.

OTLP export uses a fresh direct HTTP/1.1 connection and ignores the proxy chosen for the measured request. A non-2xx response or a transport error is exit 73.

The `otel` feature is empty. It reserves the name and does not change the build.

## Русский

`net_info` — диагностическая утилита для одного HTTP-запроса. Бинарник называется `net-info`. Она раскладывает запрос на DNS, TCP, TLS, ожидание сервера и передачу тела, а затем рисует waterfall. Цепочка редиректов — это несколько таких запросов, каждый по новому соединению. Поведение близко к [httptap](https://github.com/ozeranskii/httptap) 0.8.2, поэтому готовую команду можно перенести, заменив имя программы. Лицензия Apache-2.0.

Измеряется один запрос. Нагрузочное тестирование, сессии с cookies, полноэкранный интерфейс, gRPC, WebSocket и HTTP/3 в этот крейт не входят.

Ниже по порядку: из чего состоит запрос, как снимаются фазы, как запускать CLI и куда пишутся отчёты. Места, в которых легко ошибиться, вынесены в заметки: [TIMING.md](TIMING.md), [REDIRECTS.md](REDIRECTS.md), [PROXY.md](PROXY.md) и [EXPORTS.md](EXPORTS.md).

### Коротко

```text
net-info https://example.com
net-info --metrics-only --json - https://example.com/health
net-info -L --fail --slo total=500,ttfb=200 https://example.com
```

Успешный HTTPS-запрос даёт семь чисел, все в миллисекундах:

| Поле | Что измерили часы |
|---|---|
| `dns_ms` | Поиск имени |
| `connect_ms` | TCP до адреса, который ответил. Время неудачных предыдущих адресов входит сюда же |
| `tls_ms` | Рукопожатие с origin. Для `http://` это ноль |
| `ttfb_ms` | От старта шага до первого байта ответа |
| `wait_ms` | `max(0, ttfb − dns − connect − tls)` |
| `xfer_ms` | `max(0, total − ttfb)`, тело после первого байта |
| `total_ms` | От старта шага до конца чтения тела |

`cargo test` проходит: 20 тестов библиотеки и 1 интеграционный. Они ходят на локальные слушатели. Выход в интернет для тестов не нужен.

### Из чего состоит один запрос

За URL прячется несколько обменов.

**DNS** превращает имя в один или несколько адресов. IP-литерал и привязка `--resolve` этот шаг пропускают, поэтому `dns_ms` остаётся 0. Интернациональные имена перед запросом переводятся в ASCII (IDNA).

**TCP** открывает соединение с одним из адресов. Адреса пробуются по очереди. Время отказа или таймаута остаётся внутри `connect_ms`, так же как `time_connect` у `curl`. Остаток времени до дедлайна делится между адресами, которые ещё не пробовали.

**TLS** есть только у `https://`. Часы стартуют после TCP и останавливаются, когда рукопожатие закончилось. Из сертификата берутся CN, DNS-имена SAN, издатель, серийный номер, окно действия и дни до истечения. Имя шифра — имя IANA из rustls (`TLS_AES_128_GCM_SHA256`). Оно отличается от написания OpenSSL, которое печатает httptap.

**Ожидание** — остаток времени до первого байта после вычитания DNS, TCP и TLS. Это работа сервера и всё, что предыдущие фазы не забрали себе.

**Передача** — всё после первого байта ответа. Заголовки, пришедшие вместе с ним, уже сидят в TTFB, а остальное тело — это `xfer_ms`. `HEAD` тело не читает, поэтому счётчик байт остаётся 0.

`ttfb_ms` и `total_ms` включают DNS. Оба считаются от одного `Instant`, который стартует до поиска имени, поэтому фазы складываются в настенное время шага.

### Как net-info это измеряет

`reqwest` эти фазы прячет. Клиент в [`src/client.rs`](src/client.rs) снимает их сам: `hickory-resolver` для DNS, `TcpStream` для connect, `tokio-rustls` для рукопожатия и `hyper` для HTTP/1.1 и HTTP/2. ALPN предлагает `h2`, затем `http/1.1`, если HTTP/2 включён. Обычный `http://` остаётся на HTTP/1.1. `--no-http2` (псевдоним `--http1.1`) предлагает только `http/1.1`.

Если на HTTPS-шаге connect и TLS измерить не удалось, промежуток между DNS и TTFB делится 30/70 на `connect_ms` и `tls_ms`, а `is_estimated` становится true. Waterfall помечает эти два столбца словом `estimated`. Формулы, общий дедлайн и перебор адресов разобраны в [TIMING.md](TIMING.md).

Каждый хоп редиректа заново резолвит имя и открывает соединение. Дедлайн на всю цепочку по умолчанию — 20 секунд (`-m` / `--max-time` / `--timeout`).

### Как пользоваться CLI

```bash
# Waterfall в терминале. Цвет зависит от NO_COLOR, FORCE_COLOR и TERM=dumb.
net-info https://example.com/health

# Одна машинная строка на хоп.
net-info --metrics-only https://example.com/health

# POST с JSON. Метод становится POST, потому что задан --data и не задан -X.
net-info https://example.com/api -d '{"ok":true}'

# Тело из файла. Файл .json ещё и ставит Content-Type.
net-info https://example.com/api -d @payload.json

# До 10 редиректов. Ответ 4xx/5xx всё равно печатает отчёт и выходит с кодом 22.
net-info -L -f https://example.com

# Имя привязано к адресу. Заголовок Host и имя в TLS остаются как в URL.
net-info --resolve example.com:443:203.0.113.10 https://example.com

# Добавить свой CA или отключить проверку. Вместе эти флаги стоять не могут.
net-info --cacert corp.pem https://intranet.example
net-info -k https://localhost:8443

# Ненулевой код, если последний успешный хоп не уложился в бюджет.
net-info --slo dns=20,connect=50,tls=80,ttfb=200,total=500 https://example.com
```

`--data` без явного метода отправляет `POST`. Явные `GET` и `HEAD` с телом уходят как есть, а на stderr печатается предупреждение. Заданный пользователем `Content-Type` важнее угаданного. Строка, которая парсится как JSON, получает `application/json`. Тип файла берётся из расширения: `.json`, `.xml`, `.txt`, `.text`.

`User-Agent` по умолчанию — `net-info/<версия>`, `Accept` — `*/*`. Учётные данные из URL становятся заголовком `Authorization: Basic`, если вызывающий ещё не передал свой. Имя и пароль сначала percent-decode.

### Флаги

| Запрос | |
|---|---|
| `URL` | `http://` или `https://` с хостом. Пробелы и порт 0 отвергаются |
| `-X`, `--request`, `--method` | `GET` `POST` `PUT` `PATCH` `DELETE` `HEAD` `OPTIONS` |
| `-d`, `--data` | Тело или `@файл` |
| `-H`, `--header` | Повторяемый `Name: value` |
| `-L`, `--location`, `--follow` | Идти по редиректам, не больше 10 |
| `-m`, `--max-time`, `--timeout` | Дедлайн на всю цепочку, в секундах. По умолчанию 20 |
| `--no-http2`, `--http1.1` | Остаться на HTTP/1.1 |
| `-f`, `--fail` | Код 22, если какой-то хоп вернул 4xx или 5xx |
| `-4`, `--ipv4` / `-6`, `--ipv6` | Одно семейство адресов. Флаги взаимоисключающие |
| `--resolve HOST:PORT:ADDR` | Звонить на `ADDR` для этой пары хост и порт. Можно повторять. Скобки вокруг IPv6 необязательны |

| TLS и прокси | |
|---|---|
| `-k`, `--insecure`, `--ignore-ssl` | Не проверять сертификат |
| `--cacert`, `--ca-bundle` | Дополнительные PEM-сертификаты поверх набора webpki |
| `-x`, `--proxy` | `http`, `https`, `socks5`, `socks5h`. Пустая строка игнорирует переменные прокси |

| Вывод | |
|---|---|
| `--compact` | Одна строка на хоп и таблица редиректов, если хопов больше одного |
| `--metrics-only` | Строки `key=value`. Важнее `--compact` |
| `--json PATH` | JSON-отчёт. `-` пишет его в stdout |
| `--har PATH` | HAR 1.2. `-` пишет его в stdout |
| `--prometheus PATH` | Textfile для Prometheus. Префикс метрик — `net_info_` |
| `--otlp ENDPOINT` | Один трейс OTLP/HTTP JSON. `/v1/traces` дописывается, если его нет |
| `--slo KEY=MS[,...]` | Бюджеты в миллисекундах |
| `--slo-file PATH` | Те же ключи, по одному в строке. Пустые строки и комментарии `#` пропускаются. `--slo` перекрывает ключ из файла |

`--help` и `--version` выходят с кодом 0. Плохой флаг или отвергнутый URL дают 64. Сообщения о проверке аргументов и об экспорте идут в stderr. Отчёт идёт в stdout.

### Что видно на экране

Вид по умолчанию — панель на каждый хоп: URL, строка сети (адрес, версия HTTP, прокси, версия TLS, шифр, сертификат, дни до истечения), строка ответа (статус, размер, сервер, замаскированный `Location`) и waterfall. Столбики — это `█`, пропорциональные DNS, Connect, TLS, Wait и Transfer. Каждый начинается там, где кончился предыдущий. Ширина берётся из терминала и остаётся между 10 и 60 колонками. Цепочка длиннее одного хопа добавляет сводку редиректов. Результат SLO добавляет свою панель.

`--compact` — одна строка без цвета: статус, метод, URL, пять сырых таймингов и размер в человеческом виде. `--metrics-only` цвет не использует. Уложившийся SLO на проверяемом хопе дописывает `slo=pass`. Неуложившийся — `slo=fail` и `slo_violations=` со списком ключей.

Цвет включён, когда stdout — терминал. `NO_COLOR` или `TERM=dumb` его выключают. `FORCE_COLOR` включает, в том числе поверх `TERM=dumb`.

Срок сертификата в подробном виде раскрашен: меньше 30 дней — критично, меньше 90 — предупреждение.

### Редиректы, прокси, TLS, SLO

Редиректы, включая то, какие заголовки переживают переход на другой origin, описаны в [REDIRECTS.md](REDIRECTS.md). Выбор прокси, `NO_PROXY`, CONNECT и разница между `socks5` и `socks5h` — в [PROXY.md](PROXY.md).

У проверки TLS три режима. По умолчанию корень берётся из `webpki-roots`. `--cacert` добавляет PEM-файл в этот набор. `--insecure` принимает любой сертификат. После неудачной проверки открывается второе соединение, не дольше 5 секунд, уже без проверки, чтобы отчёт всё же показал отвергнутый сертификат. Это зонд, а не повтор запроса. Ошибка TLS не переходит к следующему адресу.

`--slo` и `--slo-file` принимают `dns`, `connect`, `tls`, `ttfb`, `wait`, `xfer` и `total`. Значения — положительные конечные миллисекунды. Повтор ключа внутри одной спецификации — ошибка. Проверяется последний хоп без сетевой ошибки. Хоп не уложился, когда фактическое значение строго больше порога. `delta_ms` в JSON — это `actual − threshold`. Нарушения упорядочены по ключу. Процесс выходит с кодом 4, если проверка не прошла и не случилось ничего более серьёзного.

### Отчёты

JSON, HAR 1.2, Prometheus и OTLP разобраны по полям в [EXPORTS.md](EXPORTS.md). JSON несёт `schema_version`, `net_info_version`, время, `initial_url`, `steps` и `summary`. `summary.slo` появляется, когда бюджет задан. В HAR `connect` включает TLS, а `ssl` повторяет время TLS для HTTPS. У Prometheus префикс `net_info_`. OTLP — это JSON `POST`, собранный в этом крейте. Пустая Cargo-feature `otel` не подключает SDK OpenTelemetry.

### Секреты

`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `Api-Key` и `X-Api-Key` маскируются до экрана и до отчёта. Значение из 8 символов и короче становится `****`. Более длинное оставляет первые четыре и последние четыре символа: `Bearer supersecret` хранится как `Bear****cret`. Userinfo в URL становится `user:****`, если есть пароль, и `****`, если это только токен. Та же маскировка применяется к `Location` и `Content-Location`.

### Коды выхода

Берётся первая подходящая строка.

| Код | Когда |
|---|---|
| 0 | Цепочка закончилась, экспорт записан, и более поздние правила не сработали. Также `--help` и `--version` |
| 4 | Бюджет SLO не выполнен |
| 22 | Задан `--fail`, и какой-то хоп вернул HTTP 4xx или 5xx |
| 47 | Достигнут предел редиректов (10) |
| 64 | Плохие аргументы, отвергнутый URL, плохой прокси или нечитаемый файл CA / SLO |
| 70 | Анализатор не дал ни одного шага, или шаг помечен `internal` |
| 73 | JSON, HAR, Prometheus или OTLP не удалось записать или сервер их не принял |
| 75 | DNS, TCP, TLS, таймаут или отказ в соединении |
| 130 | Ctrl-C во время запроса (`128 + SIGINT`) |

Сетевая ошибка важнее сорванного SLO и `--fail`. Предел редиректов важнее более поздней сетевой ошибки. Ошибка экспорта важнее HTTP 22 и SLO 4. Ctrl-C во время запроса возвращает 130 и отчёт не печатает.

### Из Rust

Точка входа библиотеки — `net_info::analyze`. `Settings::default()` не идёт по редиректам, разрешает HTTP/2, доверяет корням webpki и не смотрит на переменные прокси. `ProxyChoice::Environment` и заполненная карта `env` включают те же правила прокси, что у CLI.

```rust
use std::time::Duration;

use net_info::options::{ProxyChoice, Settings};
use net_info::{analyze, Method};

#[tokio::main]
async fn main() {
    let settings = Settings {
        timeout: Duration::from_secs(20),
        proxy: ProxyChoice::Environment,
        env: std::env::vars().collect(),
        ..Settings::default()
    };
    let steps = analyze(
        "https://example.com/",
        Method::Get,
        None,
        &[],
        &settings,
    )
    .await;
    let step = &steps[0];
    println!(
        "status={:?} dns={:.1} connect={:.1} tls={:.1} total={:.1}",
        step.response.status,
        step.timing.dns_ms,
        step.timing.connect_ms,
        step.timing.tls_ms,
        step.timing.total_ms,
    );
}
```

Вызов асинхронный и требует runtime Tokio. Заголовки и URL, которые лежат на шаге, уже замаскированы.

### Состав проекта

| Файл | Что внутри |
|---|---|
| `src/main.rs` | Поднимает runtime и выходит с кодом CLI |
| `src/cli.rs` | Аргументы, проверка, цвет, экспорт, код выхода |
| `src/analyzer.rs` | Цикл редиректов, фильтр заголовков, `determine_exit_code` |
| `src/client.rs` | DNS, TCP, TLS, HTTP/1.1, HTTP/2, набор прокси, тело |
| `src/dns.rs` | Поиск через Hickory, семейство адресов, IDNA |
| `src/tls.rs` | Конфиг rustls, рукопожатие, поля сертификата |
| `src/proxy.rs` | `--proxy`, окружение, `NO_PROXY` |
| `src/models.rs` | `TimingMetrics`, `NetworkInfo`, `ResponseInfo`, `StepMetrics` |
| `src/render.rs` | Waterfall, compact, metrics-only |
| `src/export.rs` | JSON, HAR 1.2, textfile Prometheus |
| `src/otlp.rs` | Трейс OTLP/HTTP JSON |
| `src/slo.rs` | Разбор порогов и проверка |
| `src/redact.rs` | Маскировка заголовков и URL |
| `src/options.rs` | `Settings`, `Verify`, `ProxyChoice` |
| `src/exit.rs` | Коды статуса и доли оценки 30/70 |
| `tests/smoke.rs` | Бинарник `net-info` против локального TCP-сервера |
| `TIMING.md` | Часы, формулы, перебор адресов, дедлайн |
| `REDIRECTS.md` | Смена метода и какие заголовки снимаются |
| `PROXY.md` | Как выбирается прокси и как строится туннель |
| `EXPORTS.md` | JSON, HAR, Prometheus, OTLP |

### Что проверяют тесты

Юнит-тесты покрывают формулы ожидания и передачи, оценку 30/70, разбор и проверку SLO, смену метода на редиректе (`301`/`302` у POST становится GET и снимает `Content-Type`; `303` у HEAD остаётся HEAD; `307` у POST остаётся POST), приоритет кодов выхода, маскировку секретов, суффикс и `*` в `NO_PROXY`, а также правило Prometheus: упавший хоп пишет только `net_info_request_success 0`.

Тесты на локальном сервере покрывают обычный HTTP GET, редирект с маскировкой userinfo и `Authorization`, `--fail` (22), сорванный SLO (4), цикл редиректов (47), отвергнутый URL и плохой ключ SLO (64), HTTP-прокси и SOCKS5, `--insecure` и `--cacert` с выпущенным CA. Интеграционный тест запускает бинарник `net-info` и ждёт `status=200` в stdout.

### Ограничения

DNS-клиент — Hickory с feature `system-config`. Он читает конфигурацию резолвера. `getaddrinfo` он не вызывает, поэтому модули NSS и `/etc/hosts` не участвуют. Имя, которое живёт только в `/etc/hosts`, в том числе некоторые настройки `localhost`, требует `--resolve` или IP-литерала.

Адреса пробуются в порядке резолвера. Гонки Happy Eyeballs нет.

Имена шифров — имена IANA. Дашборд, который ищет openssl-строку `ECDHE-RSA-AES128-GCM-SHA256`, эту строку не найдёт.

Зонд сертификата после ошибки проверки тратит до пяти дополнительных секунд и показывает сертификат. Исходная ошибка хоп всё равно проваливает.

`--cacert` добавляет сертификаты к корням webpki. Он их не подменяет.

HTTP/2 используется, когда ALPN выбрал `h2`. Открытого h2c нет. HTTP/3, cookies, повторное использование соединения между хопами и полный набор возможностей curl остаются за рамками.

Экспорт OTLP идёт новым прямым соединением HTTP/1.1 и игнорирует прокси, выбранный для измеряемого запроса. Ответ вне 2xx или ошибка транспорта — это код 73.

Feature `otel` пустая. Она резервирует имя и сборку не меняет.
