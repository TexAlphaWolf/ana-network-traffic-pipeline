# Security

## Reporting a problem

Open a private security advisory on GitHub (Security tab → Report a vulnerability) or contact
the maintainer through the profile. Please do not file public issues for vulnerabilities.

## Design notes

- Capture files and NetFlow datagrams are treated as hostile input: bounds-checked decoders,
  size limits, fuzz tests. The collector only accepts datagrams from listed exporters and refuses
  to start on a network address without a list.
- The database uses two users: a writer scoped to the `flowpipe` database and a read-only
  Grafana user. The open `default` user is removed. Ports are published on `127.0.0.1` only,
  except the NetFlow UDP port.
- Secrets live in `.env` (ignored by Git). Credentials are sent in HTTP headers, never in URLs,
  and are not included in error messages. TLS certificate verification is never disabled.
- Flow data can identify people and habits. Use `FLOWPIPE_ANONYMISE_KEY` before sharing data,
  and set a retention that matches your needs.
- Containers run as a non-root user with a read-only filesystem and all capabilities dropped.

## Not covered

- Spoofed UDP exporters on a network where untrusted hosts can reach the collector.
- Grafana exposure: it listens on localhost. If you publish it, put a TLS reverse proxy with
  authentication in front.
