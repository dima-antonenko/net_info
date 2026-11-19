# Редиректы

[English](#english) · [Русский](#русский)

Заметка о том, какой метод уходит на следующий хоп, какие заголовки снимаются и когда цепочка останавливается с кодом 47. Кратко это же описано в [README](README.md). Тайминги каждого хопа — в [TIMING.md](TIMING.md).

## English

### The loop

`--follow` (`-L`, `--location`) walks 3xx responses that carry a `Location`. The default is to stop on the first response. The limit is 10 followed redirects, which means 11 steps: the first request plus ten hops. The eleventh 3xx still returns, the step is marked `redirect_limit_reached`, stderr gets a warning, and the process exits 47 unless a more severe rule already matched. See the exit table in the [README](README.md#exit-codes).

Each hop is a new `perform` call. Nothing is reused: no connection pool, no cookies, no TLS session.

`Location` is joined to the current URL with `Url::join`. A relative location stays on the same origin. An absolute one replaces it. A missing host, a scheme other than `http` or `https`, or a location that does not parse becomes an extra failed step with kind `network`. The raw location is followed. The value stored on the step, and the value printed, is the redacted one.

A 3xx without `Location` is a finished response. The loop stops.

### Which method leaves

| Status | Method that arrived | Method that leaves |
|---|---|---|
| 303 | anything except `HEAD` | `GET` |
| 303 | `HEAD` | `HEAD` |
| 301 or 302 | `POST` | `GET` |
| 301 or 302 | anything else | the same method |
| 307, 308, other 3xx | any | the same method |

When the method changes, the body is dropped, and so are `Content-Type`, `Content-Length`, `Content-Encoding`, and `Transfer-Encoding`. When the method stays, the body and those headers stay.

### Which headers leave

Four headers are bound to the origin: `Authorization`, `Cookie`, `Host`, and `Proxy-Authorization`. They are removed when the next URL is a different origin.

They are kept in two cases. The next URL has the same scheme, the same host, and the same port (default 80 or 443 counts). Or the hop is an upgrade from `http` on port 80 to `https` on port 443 of the same host. A change of port, a change of host, or an upgrade that is not exactly 80 → 443 drops them.

`Host` is in that list because the next request builds a fresh Host header from the URL it is about to call.

### Credentials in the URL

Userinfo on the request URL becomes `Authorization: Basic` when the caller did not pass `Authorization`. That header then follows the origin rule above. On a cross-origin redirect it is removed. On a same-origin redirect it stays, still masked in the report as `user:****` in the URL and as a masked header value.

### What the tests check

`analyzer::tests::post_becomes_get_on_301_and_drops_body_headers` expects `GET` after a 301 of a POST, keeps `HEAD` on a 303, keeps `POST` on a 307, and drops `Authorization` together with `Content-Type` when the next hop does not keep credentials or the body.

`live_tests::follows_redirects_and_masks_secrets` follows a local 302 and writes JSON. The report contains `****` and does not contain the password or the bearer token.

`live_tests::fail_slo_and_redirect_limit_have_distinct_codes` follows a self-redirect until the limit and expects exit 47.

## Русский

### Цикл

`--follow` (`-L`, `--location`) идёт по ответам 3xx, у которых есть `Location`. По умолчанию программа останавливается на первом ответе. Предел — 10 пройденных редиректов, то есть 11 шагов: первый запрос и десять хопов. Одиннадцатый 3xx всё же возвращается, шаг помечается `redirect_limit_reached`, в stderr уходит предупреждение, и процесс выходит с кодом 47, если более строгое правило уже не сработало. Таблица кодов — в [README](README.md#коды-выхода).

Каждый хоп — новый вызов `perform`. Ничего не переиспользуется: ни пул соединений, ни cookies, ни сессия TLS.

`Location` присоединяется к текущему URL через `Url::join`. Относительный адрес остаётся на том же origin. Абсолютный его заменяет. Хост отсутствует, схема не `http` и не `https`, или location не парсится — появляется ещё один неудачный шаг с видом `network`. Идём по сырому location. Значение, которое лежит на шаге и которое печатается, уже замаскировано.

3xx без `Location` — законченный ответ. Цикл останавливается.

### Какой метод уходит

| Статус | Метод, который пришёл | Метод, который уходит |
|---|---|---|
| 303 | любой, кроме `HEAD` | `GET` |
| 303 | `HEAD` | `HEAD` |
| 301 или 302 | `POST` | `GET` |
| 301 или 302 | любой другой | тот же метод |
| 307, 308, прочие 3xx | любой | тот же метод |

Когда метод меняется, тело снимается, и вместе с ним `Content-Type`, `Content-Length`, `Content-Encoding` и `Transfer-Encoding`. Когда метод остаётся, тело и эти заголовки остаются.

### Какие заголовки уходят

Четыре заголовка привязаны к origin: `Authorization`, `Cookie`, `Host` и `Proxy-Authorization`. Они снимаются, когда следующий URL — другой origin.

Они сохраняются в двух случаях. У следующего URL те же схема, хост и порт (порты по умолчанию 80 и 443 считаются). Или хоп — это переход с `http` на порту 80 на `https` на порту 443 того же хоста. Смена порта, смена хоста или переход, который не равен ровно 80 → 443, их снимает.

`Host` в этом списке потому, что следующий запрос собирает свежий Host из URL, на который он идёт.

### Учётные данные в URL

Userinfo в URL запроса становится `Authorization: Basic`, если вызывающий не передал `Authorization`. Дальше этот заголовок подчиняется правилу origin выше. На редиректе между разными origin он снимается. На том же origin остаётся. В отчёте URL всё равно показан как `user:****`, а значение заголовка замаскировано.

### Что проверяют тесты

`analyzer::tests::post_becomes_get_on_301_and_drops_body_headers` ждёт `GET` после 301 у POST, сохраняет `HEAD` на 303, сохраняет `POST` на 307 и снимает `Authorization` вместе с `Content-Type`, когда следующий хоп не сохраняет ни учётные данные, ни тело.

`live_tests::follows_redirects_and_masks_secrets` проходит локальный 302 и пишет JSON. В отчёте есть `****`, а пароля и bearer-токена нет.

`live_tests::fail_slo_and_redirect_limit_have_distinct_codes` ходит по редиректу на себя до предела и ждёт код 47.
