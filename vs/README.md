# Visa Service (v2)

To create TLS cert for the admin service:

```bash
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out admin-tls-cert.pem -keyout admin-tls-key.pem
```

