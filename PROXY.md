# Прокси

[English](#english) · [Русский](#русский)

Заметка о том, откуда берётся прокси, когда имя резолвится локально, и что именно попадает в `connect_ms`. Коротко те же правила описаны в [README](README.md). Как часы относятся к туннелю — в [TIMING.md](TIMING.md).

## English

### Which value wins

`resolve_effective_proxy` in [`src/proxy.rs`](src/proxy.rs) walks this list and stops at the first hit.

1. `--proxy ""` disables every environment variable. The report says `proxy=disabled` and `proxy_source` is `noproxy`.
2. `--proxy URL` wins over the environment. A value without `://` is read as `http://` that value. `proxy_source` is `--proxy`.
3. Otherwise the environment is consulted. `no_proxy`, when the variable exists, is used even if it is empty. `NO_PROXY` is used only when `no_proxy` is absent.
4. A host that matches the bypass list is a direct connection. `proxy_source` is `NO_PROXY`.
5. The first non-empty variable among `{scheme}_proxy`, `{SCHEME}_PROXY`, `all_proxy`, and `ALL_PROXY` is the proxy. For an `https://` URL the lowercase `https_proxy` therefore beats `HTTPS_PROXY`.
6. If some proxy variable is set and none of those four names match this scheme, the connection is direct and `proxy_source` is `no_proxy_env`.
7. If no proxy variable is set, the connection is direct and `proxy_source` is empty.

The library default, `Settings::default()`, is `ProxyChoice::Disable`. It does not read the environment. The CLI default is `ProxyChoice::Environment`.

Accepted schemes are `http`, `https`, `socks5`, and `socks5h`. The URL needs a host. Port 0 is rejected. Userinfo is kept for authentication and masked in every report.

### NO_PROXY

Entries are comma-separated, trimmed, and compared in lower case.

| Pattern | Matches |
|---|---|
| `*` | every host |
| `example.com` | that host, and any host that ends with `.example.com` |
| `.example.com` | a host that ends with `.example.com` |

`example.org` does not match `example.com`.

### Where the name is resolved

| Proxy | DNS of the target | `dns_ms` | `ip` of the origin |
|---|---|---|---|
| none | local | measured | the address that connected |
| `socks5` | local, then the address is sent to the proxy | measured | the address sent to the proxy |
| `http`, `https`, `socks5h` | on the proxy | 0 | empty |

`-4`, `-6`, and `--resolve` describe a local choice of address. They are rejected when the selected proxy resolves the name itself (`http`, `https`, `socks5h`). `socks5` still honors them, because the client looks the name up before the handshake.

The time spent resolving the proxy host and connecting to it is part of `connect_ms`. It is not `dns_ms` of the target.

### What is sent

**HTTP proxy, `http://` origin.** The request uses the absolute form (`http://host/path`). `Proxy-Authorization` is added when the proxy URL has userinfo. The origin is not contacted directly.

**HTTP or HTTPS proxy, `https://` origin.** The client sends `CONNECT host:port HTTP/1.1` and reads a `200`. Proxy credentials go on that `CONNECT`, and they are not repeated on the tunneled request. After `200`, TLS runs against the origin, and the HTTP request uses origin form plus a normal `Host`. `connect_ms` stops when `CONNECT` has succeeded. `tls_ms` is the origin handshake. An `https://` proxy wraps the connection to the proxy itself in TLS before `CONNECT`.

**`socks5`.** The target is resolved locally. Each address is offered to the proxy until one connects. Authentication is username and password when the proxy URL has userinfo, otherwise no authentication. The implementation is `tokio-socks`.

**`socks5h`.** One SOCKS request carries the host name. The proxy resolves it. `dns_ms` stays 0.

HTTP/2 is negotiated only with the origin, after the tunnel exists. An `http://` origin through an HTTP proxy stays on HTTP/1.1, because that path uses absolute-form HTTP/1.1.

### What the tests check

`proxy::tests::no_proxy_matches_suffix_and_wildcard` matches `api.example.com` against `example.com` and against `.example.com`, matches `localhost` against `*`, and leaves `example.org` alone.

`proxy::tests::explicit_proxy_beats_environment` keeps `socks5://proxy:1080` even when `https_proxy` is set, and reports that this proxy does not resolve remotely.

`proxy::tests::lowercase_scheme_proxy_is_preferred` picks `https_proxy` over `HTTPS_PROXY`.

`live_tests::http_proxy_and_socks_reach_origin` serves a tiny absolute-form HTTP proxy and a tiny SOCKS5 server with no authentication. Both reach a local origin and exit 0.

## Русский

### Какое значение побеждает

`resolve_effective_proxy` в [`src/proxy.rs`](src/proxy.rs) идёт по этому списку и останавливается на первом попадании.

1. `--proxy ""` отключает все переменные окружения. В отчёте будет `proxy=disabled`, а `proxy_source` — `noproxy`.
2. `--proxy URL` важнее окружения. Значение без `://` читается как `http://` плюс это значение. `proxy_source` — `--proxy`.
3. Дальше смотрит окружение. `no_proxy`, если переменная существует, используется даже пустой. `NO_PROXY` используется только когда `no_proxy` нет.
4. Хост, который попал в список обхода, идёт напрямую. `proxy_source` — `NO_PROXY`.
5. Первая непустая переменная из `{scheme}_proxy`, `{SCHEME}_PROXY`, `all_proxy` и `ALL_PROXY` и есть прокси. Для URL `https://` строчная `https_proxy` поэтому побеждает `HTTPS_PROXY`.
6. Если какая-то переменная прокси задана, а ни одно из этих четырёх имён к этой схеме не подходит, соединение прямое и `proxy_source` равен `no_proxy_env`.
7. Если переменных прокси нет, соединение прямое и `proxy_source` пустой.

Умолчание библиотеки, `Settings::default()`, — это `ProxyChoice::Disable`. Окружение оно не читает. Умолчание CLI — `ProxyChoice::Environment`.

Допустимые схемы: `http`, `https`, `socks5` и `socks5h`. В URL нужен хост. Порт 0 отвергается. Userinfo сохраняется для аутентификации и маскируется в каждом отчёте.

### NO_PROXY

Элементы разделены запятыми, обрезаются и сравниваются в нижнем регистре.

| Шаблон | Что совпадает |
|---|---|
| `*` | любой хост |
| `example.com` | этот хост и любой хост, который кончается на `.example.com` |
| `.example.com` | хост, который кончается на `.example.com` |

`example.org` с `example.com` не совпадает.

### Где резолвится имя

| Прокси | DNS цели | `dns_ms` | `ip` origin |
|---|---|---|---|
| нет | локально | измерен | адрес, с которым соединились |
| `socks5` | локально, затем адрес уходит прокси | измерен | адрес, отправленный прокси |
| `http`, `https`, `socks5h` | на прокси | 0 | пусто |

`-4`, `-6` и `--resolve` описывают локальный выбор адреса. Они отвергаются, когда выбранный прокси резолвит имя сам (`http`, `https`, `socks5h`). `socks5` их соблюдает, потому что клиент ищет имя до рукопожатия.

Время резолва хоста прокси и соединения с ним входит в `connect_ms`. Это не `dns_ms` цели.

### Что отправляется

**HTTP-прокси, origin `http://`.** Запрос идёт в абсолютной форме (`http://host/path`). `Proxy-Authorization` добавляется, когда в URL прокси есть userinfo. До origin напрямую клиент не ходит.

**HTTP- или HTTPS-прокси, origin `https://`.** Клиент шлёт `CONNECT host:port HTTP/1.1` и читает `200`. Учётные данные прокси стоят на этом `CONNECT` и на туннелированном запросе не повторяются. После `200` TLS идёт с origin, а HTTP-запрос использует origin-form и обычный `Host`. `connect_ms` заканчивается, когда `CONNECT` успешен. `tls_ms` — рукопожатие с origin. Прокси со схемой `https://` сначала оборачивает соединение до самого прокси в TLS, и только потом идёт `CONNECT`.

**`socks5`.** Цель резолвится локально. Каждый адрес предлагается прокси, пока один не соединится. Аутентификация — имя и пароль, если в URL прокси есть userinfo, иначе без аутентификации. Реализация — `tokio-socks`.

**`socks5h`.** Один запрос SOCKS несёт имя хоста. Резолвит его прокси. `dns_ms` остаётся 0.

HTTP/2 согласуется только с origin, после того как туннель есть. Origin `http://` через HTTP-прокси остаётся на HTTP/1.1, потому что этот путь использует absolute-form HTTP/1.1.

### Что проверяют тесты

`proxy::tests::no_proxy_matches_suffix_and_wildcard` сопоставляет `api.example.com` с `example.com` и с `.example.com`, сопоставляет `localhost` с `*` и оставляет `example.org` в стороне.

`proxy::tests::explicit_proxy_beats_environment` сохраняет `socks5://proxy:1080`, даже когда задан `https_proxy`, и сообщает, что этот прокси не резолвит имя удалённо.

`proxy::tests::lowercase_scheme_proxy_is_preferred` выбирает `https_proxy`, а не `HTTPS_PROXY`.

`live_tests::http_proxy_and_socks_reach_origin` поднимает маленький HTTP-прокси с absolute-form и маленький SOCKS5 без аутентификации. Оба доходят до локального origin и выходят с кодом 0.
