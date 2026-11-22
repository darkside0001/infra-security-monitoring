# Web security check

| Site | Grade | Score | Fails | Warnings |
|---|---|---|---|---|
| crm.lab.test | **A** | 92 | 0 | 1 |

## crm.lab.test

| Status | Check | Detail | Fix |
|---|---|---|---|
| WARN | Certificate expires soon | expires 2026-11-22 (0 days) | Renew it. Check that automatic renewal works. |
| PASS | TLS 1.0 and 1.1 refused |  |  |
| PASS | TLS 1.3 supported |  |  |
| PASS | Strong cipher negotiated | TLS_AES_128_GCM_SHA256 (TLSv1.3, 128 bit) |  |
| PASS | Certificate chain and hostname valid |  |  |
| PASS | HSTS enabled | max-age=31536000; includeSubDomains |  |
| PASS | Content-Security-Policy set | default-src 'none'; frame-ancestors 'none'; base-uri 'none' |  |
| PASS | X-Content-Type-Options: nosniff |  |  |
| PASS | Clickjacking protection (CSP frame-ancestors) |  |  |
| PASS | Referrer-Policy set | no-referrer |  |
| PASS | Permissions-Policy set | camera=(), microphone=(), geolocation=(), payment=() |  |
| PASS | No software versions disclosed |  |  |
| PASS | HTTP redirects to HTTPS | 308 -> https://crm.lab.test/health |  |
| INFO | Certificate details | subject CN=-, issuer=ISM Lab CA - ECC Intermediate, SAN=crm.lab.test |  |
