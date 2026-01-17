# edumdns_proxy

eBPF-based proxy for the edumDNS system that enhances security by relaying all client–device traffic when enabled for a device.

## Overview

The `edumdns_proxy` binary is a privileged application that loads an eBPF (extended Berkeley Packet Filter) program into the Linux kernel. The eBPF program intercepts network packets and rewrites their headers to route traffic through the proxy, increasing the security of transmission between clients and devices.

**Important**: This binary requires elevated privileges (root or `CAP_BPF`) to load eBPF programs into the kernel.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. eBPF programs can:

- Intercept and modify network packets at the kernel level
- Provide high-performance packet processing
- Execute safely in a sandboxed environment

In the context of edumDNS, the eBPF program intercepts packets destined for proxied devices and rewrites their source and destination addresses (and MAC addresses) to route traffic through the proxy, ensuring all communication is relayed and can be monitored/controlled.

## How It Works

1. The eBPF program is attached to a network interface using XDP (eXpress Data Path)
2. When a packet matches a proxied device's IP address, the eBPF program:
    - Rewrites the source IP address to the proxy IP
    - Rewrites the destination MAC address
    - Updates packet checksums
3. The modified packets are forwarded, ensuring all traffic is routed through the proxy
4. The server maintains mappings in eBPF maps that define which IP addresses should be proxied

---

## Configuration Model

`edumdns_proxy` supports two equivalent configuration mechanisms:

1. Command-line arguments
2. Environment variables (optionally loaded from a `.env` file)

Both mechanisms configure the same internal parameters.  
**Command-line arguments take precedence over environment variables.**

---

## Command-Line Arguments

This section documents all supported command-line arguments.  
For each argument, the corresponding environment variable is listed as an alternative means of configuration.

---

### `--env-file <ENV_FILE>`

**Description**  
Path to a `.env` file containing environment variable definitions. This allows configuring the proxy without passing sensitive or verbose configuration directly on the command line.

**Behavior**
- The file is read before argument parsing
- Variables defined in the file behave exactly like regular environment variables
- Command-line arguments still take precedence

**Environment Variable**  
None

**Example**

```bash
sudo edumdns_proxy --env-file /etc/edumdns/proxy.env
```

---

### `-i, --interface <INTERFACE>`

**Description**  
Network interface to which the eBPF XDP program will be attached. All packet interception and rewriting occurs on this interface.

**Environment Variable**  
`EDUMDNS_PROXY_INTERFACE` 

**Examples**

```bash
sudo edumdns_proxy --interface eth0
```

```bash
export EDUMDNS_PROXY_INTERFACE=enp3s0
sudo edumdns_proxy
```

---

### `-p, --pin-path <PIN_PATH>`

**Description**  
Filesystem path where eBPF maps are pinned. This directory must be a BPFFS mount point.

**Default**  
`/sys/fs/bpf/edumdns`

**Environment Variable**  
`EDUMDNS_PROXY_PIN_PATH` 

**Examples**

```bash
sudo edumdns_proxy --pin-path /sys/fs/bpf/edumdns
```

```bash
export EDUMDNS_PROXY_PIN_PATH=/sys/fs/bpf/edumdns
sudo edumdns_proxy
```

---

### `--ip <PROXY_IP>`

**Description**  
IPv4 address that replaces the original source IPv4 address in proxied packets.

**Environment Variable**  
`EDUMDNS_PROXY_IP` 

**Examples**

```bash
sudo edumdns_proxy --ip 192.168.0.10
```

```bash
export EDUMDNS_PROXY_IP=192.168.0.10
sudo edumdns_proxy
```

---

### `--ip6 <PROXY_IP6>`

**Description**  
IPv6 address that replaces the original source IPv6 address in proxied packets.

**Environment Variable**  
`EDUMDNS_PROXY_IP6` 

**Examples**

```bash
sudo edumdns_proxy --ip6 ::1
```

```bash
export EDUMDNS_PROXY_IP6=2001:db8::10
sudo edumdns_proxy
```

---

### `--src-mac <NEW_SRC_MAC>`

**Description**  
Ethernet source MAC address to use for proxied packets.

**Format**  
Colon-separated hexadecimal (e.g. `e4:1d:82:72:43:c6`)

**Environment Variable**  
`EDUMDNS_PROXY_SRC_MAC` 

**Examples**

```bash
sudo edumdns_proxy --src-mac e4:1d:82:72:43:c6
```

```bash
export EDUMDNS_PROXY_SRC_MAC=e4:1d:82:72:43:c6
sudo edumdns_proxy
```

---

### `--dst-mac <NEW_DST_MAC>`

**Description**  
Ethernet destination MAC address to use for proxied packets.

**Format**  
Colon-separated hexadecimal (e.g. `18:7a:3b:5e:c6:4c`)

**Environment Variable**  
`EDUMDNS_PROXY_DST_MAC` 

**Examples**

```bash
sudo edumdns_proxy --dst-mac 18:7a:3b:5e:c6:4c
```

```bash
export EDUMDNS_PROXY_DST_MAC=18:7a:3b:5e:c6:4c
sudo edumdns_proxy
```

---

### `-l, --log-level <LOG_LEVEL>`

**Description**  
Controls the verbosity of application logging.

**Valid Values**  
`trace`, `debug`, `info`, `warn`, `error`

**Default**  
`info`

**Environment Variable**  
`EDUMDNS_PROXY_LOG_LEVEL` 

**Examples**

```bash
sudo edumdns_proxy --log-level debug
```

```bash
export EDUMDNS_PROXY_LOG_LEVEL=debug
sudo edumdns_proxy
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

Or simply run as root.

---

## eBPF Maps

The proxy creates and pins two eBPF maps:

1. IPv4 address mapping (pinned as `edumdns_proxy_rewrite_v4`)
2. IPv6 address mapping (pinned as `edumdns_proxy_rewrite_v6`)

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

## Usage Examples

### Environment-Only Configuration

```bash
export EDUMDNS_PROXY_INTERFACE=eth0
export EDUMDNS_PROXY_IP=192.168.0.10
export EDUMDNS_PROXY_IP6=::1
export EDUMDNS_PROXY_SRC_MAC=e4:1d:82:72:43:c6
export EDUMDNS_PROXY_DST_MAC=18:7a:3b:5e:c6:4c

sudo edumdns_proxy
```

### Command-Line–Only Configuration

```bash
sudo edumdns_proxy \\
--interface eth0 \\
--ip 192.168.0.10 \\
--ip6 ::1 \\
--src-mac e4:1d:82:72:43:c6 \\
--dst-mac 18:7a:3b:5e:c6:4c
```

### Mixed Configuration (CLI Overrides Env)

```bash
export EDUMDNS_PROXY_INTERFACE=eth0
export EDUMDNS_PROXY_LOG_LEVEL=info

sudo edumdns_proxy --log-level debug
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
