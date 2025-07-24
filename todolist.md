## Backend
- probe config - just a file with uuid?
- config probe - server
  - say hello
  - check if adopted
  - if yes, start sending and accepting packets
  - if no, display for adoption and ignore packets on the server side
  - store configuration on server
  - pull configuration
  - allow stopping the probe and pulling config again
  
- encryption - rustls https://www.slingacademy.com/article/implementing-tls-ssl-in-rust-with-native-tls-or-rustls/, https://github.com/rustls/tokio-rustls
  - config
  - data
- transmit cancellation
- packet storage
  - how to avoid hashmap and hashset
  - should it be in the db?
## Web
- access control
- web UI
- OIDC