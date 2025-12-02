# edumdns_proxy

eBPF-based proxy for the EduMDNS system that enhances security by relaying all client–device traffic when enabled for a device.

## Overview

The `edumdns_proxy` binary is a privileged application that loads an eBPF (extended Berkeley Packet Filter) program into the Linux kernel. The eBPF program intercepts network packets and rewrites their headers to route traffic through the proxy, increasing the security of transmission between clients and devices.

**Important**: This binary requires elevated privileges (root or `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN` capabilities) to load eBPF programs into the kernel.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. eBPF programs can:

- Intercept and modify network packets at the kernel level
- Provide high-performance packet processing
- Execute safely in a sandboxed environment

In the context of EduMDNS, the eBPF program intercepts packets destined for proxied devices and rewrites their source and destination addresses (and MAC addresses) to route traffic through the proxy, ensuring all communication is relayed and can be monitored/controlled.

## How It Works

1. The eBPF program is attached to a network interface using XDP (eXpress Data Path)
2. When a packet matches a proxied device's IP address, the eBPF program:
   - Rewrites the source IP address to the proxy IP
   - Rewrites the destination MAC address
   - Updates packet checksums
3. The modified packets are forwarded, ensuring all traffic is routed through the proxy
4. The server maintains mappings in eBPF maps that define which IP addresses should be proxied

---
## Environment Variables

### Interface Configuration

- **`EDUMDNS_PROXY_INTERFACE`** (required)
  - Network interface name to attach the eBPF program to
  - The eBPF XDP program will be attached to this interface
  - Example: `EDUMDNS_PROXY_INTERFACE=eth0`
  - Example: `EDUMDNS_PROXY_INTERFACE=enp3s0`

### eBPF Map Configuration

- **`EDUMDNS_PROXY_PIN_PATH`** (optional, default: `"/sys/fs/bpf/edumdns"`)
  - Directory path where eBPF maps are pinned
  - Must be a BPF filesystem (BPFFS) mount point
  - The maps are pinned so they can be accessed by the server process
  - Example: `EDUMDNS_PROXY_PIN_PATH=/sys/fs/bpf/edumdns`

### Proxy IP Configuration

- **`EDUMDNS_PROXY_IP`** (required)
  - IPv4 address that will replace the original source address in proxied packets
  - This is the IP address that will appear as the source for all proxied IPv4 traffic
  - Example: `EDUMDNS_PROXY_IP=192.168.0.10`

- **`EDUMDNS_PROXY_IP6`** (required)
  - IPv6 address that will replace the original source address in proxied packets
  - This is the IP address that will appear as the source for all proxied IPv6 traffic
  - Example: `EDUMDNS_PROXY_IP6=::1`
  - Example: `EDUMDNS_PROXY_IP6=2001:db8::10`

### MAC Address Configuration

- **`EDUMDNS_PROXY_SRC_MAC`** (required)
  - Ethernet source MAC address for proxied packets
  - Format: Colon-separated hexadecimal (e.g., `e4:1d:82:72:43:c6`)
  - This MAC address will appear as the source in proxied packets
  - Example: `EDUMDNS_PROXY_SRC_MAC=e4:1d:82:72:43:c6`

- **`EDUMDNS_PROXY_DST_MAC`** (required)
  - Ethernet destination MAC address for proxied packets
  - Format: Colon-separated hexadecimal (e.g., `18:7a:3b:5e:c6:4c`)
  - This MAC address will appear as the destination in proxied packets
  - Example: `EDUMDNS_PROXY_DST_MAC=18:7a:3b:5e:c6:4c`

### Logging

- **`EDUMDNS_PROXY_LOG_LEVEL`** (optional, default: `"info"`)
  - Logging level for the proxy application
  - Valid values: `trace`, `debug`, `info`, `warn`, `error`
  - Example: `EDUMDNS_PROXY_LOG_LEVEL=debug`

## Command Line Arguments

All environment variables can also be provided as command-line arguments. Command-line arguments take precedence over environment variables.

### Common Usage

```bash
# Using environment variables (requires root)
sudo edumdns_proxy

# Using command-line arguments
sudo edumdns_proxy --interface eth0 --ip 192.168.0.10 --ip6 ::1 \
  --src-mac e4:1d:82:72:43:c6 --dst-mac 18:7a:3b:5e:c6:4c

# Using a custom .env file
sudo edumdns_proxy --env-file /path/to/.env
```
---
## Prerequisites

### Toolchain Requirements
1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### Kernel Requirements

- Linux kernel 5.8 or later (for XDP support)
- BPF filesystem (BPFFS) mounted, typically at `/sys/fs/bpf`

### Mount BPF Filesystem

Before running the proxy, ensure BPFFS is mounted:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

To make this permanent, add to `/etc/fstab`:

```
bpf /sys/fs/bpf bpf defaults 0 0
```

### Required Capabilities

The proxy requires the following capabilities:

- **CAP_BPF**: Load and attach eBPF programs
- **CAP_NET_ADMIN**: Configure network interfaces
- **CAP_SYS_ADMIN**: Access BPF filesystem

Or simply run as root.

---

## eBPF Maps

The proxy creates and pins two eBPF maps:

1. **`EDUMDNS_PROXY_REWRITE_MAP_V4`**: IPv4 address mapping (pinned as `edumdns_proxy_rewrite_v4`)
2. **`EDUMDNS_PROXY_REWRITE_MAP_V6`**: IPv6 address mapping (pinned as `edumdns_proxy_rewrite_v6`)

These maps are used by the server to update which IP addresses should be proxied. The maps store bidirectional mappings (client IP ↔ device IP) to handle both directions of traffic.

## Integration with Server

The server component (`edumdns_server`) reads the pinned eBPF maps and updates them when devices are enabled for proxy functionality. The server uses the `EDUMDNS_SERVER_EBPF_PIN_LOCATION` environment variable to locate the maps.

---

## Building

The proxy consists of multiple crates:

- **edumdns_proxy**: Main binary that loads the eBPF program
- **edumdns_proxy-ebpf**: eBPF program compiled for the kernel
- **edumdns_proxy-common**: Shared types and utilities

Build with:

```bash
cargo build --release
```

The eBPF program is compiled separately and embedded in the main binary.

--- 

## Shutdown

The proxy handles SIGTERM and SIGINT signals gracefully:

- On shutdown, it removes the pinned eBPF maps
- The XDP program is automatically detached when the process exits
- Clean shutdown ensures the interface returns to normal operation

---

## Security Considerations

- The proxy runs with elevated privileges and has access to network traffic
- Ensure the proxy binary is from a trusted source
- The eBPF program is sandboxed by the kernel, but the loader has significant privileges
- Monitor the proxy's behavior in production environments
- Use appropriate firewall rules to control access to the proxy IP addresses

--- 

## Example Configuration File

Create a `.env` file with the following content:

```env
EDUMDNS_PROXY_INTERFACE=eth0
EDUMDNS_PROXY_PIN_PATH=/sys/fs/bpf/edumdns
EDUMDNS_PROXY_IP=192.168.0.10
EDUMDNS_PROXY_IP6=::1
EDUMDNS_PROXY_SRC_MAC=e4:1d:82:72:43:c6
EDUMDNS_PROXY_DST_MAC=18:7a:3b:5e:c6:4c
EDUMDNS_PROXY_LOG_LEVEL=info
```


## License

With the exception of eBPF code, edumdns_proxy is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
