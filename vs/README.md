# Visa Service (v2)

ZPR Visa Service binary written in rust.

## To build

- `make`
- `make test` run the unit tests


## To run

The `vs` has sensible defaults but you can override with your own configuration
file. See `vs.toml` for an example.

**Requires a compiled policy.**

To run with defaults:

```
vs /path/to/policy.bin2
```

- To use a custom configuration file:  `-c my-config.toml`.
- For verbose log output: `-v`.


By default, `vs` will look for TLS credentials in `admin-tls-cert.pem` and
`admin-tls-key.pem`. You can generate these:

```bash
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out admin-tls-cert.pem -keyout admin-tls-key.pem
```


