## Backend
- encryption - rustls https://www.slingacademy.com/article/implementing-tls-ssl-in-rust-with-native-tls-or-rustls/, https://github.com/rustls/tokio-rustls
  - config
  - data
- env vars and uuid path
## Web
- access control (modules - allow loading auth function - traits)
  - 3 nullable fields any of them should suffice
    - ip network client comes from
    - password client should send
    - regex over AP hostname - get from radius active sessions
- OIDC