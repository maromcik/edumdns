# 📡 **edumDNS**
### _Secure, access-controlled device discovery across enterprise networks_

edumDNS is a Rust-based system designed to make mDNS-based discovery (e.g., Chromecast, Apple TV, Playercast) work reliably and securely across multi-subnet, enterprise, and campus networks.  
It provides **on-demand, access-controlled discovery**, backed by remote probes, a central server, and an optional eBPF traffic-proxying layer.

This repository contains **three binaries** and multiple **nested crates**, each with their own focused README files.  

---

## 🌐 How edumDNS Works

### 1. 🛰️ Remote probes
Probes in remote networks capture mDNS packets from Chromecast, Apple TV, Playercast, etc.  
They securely forward these packets to the central server.

### 2. 🖥️ Server & database
The server parses packets, stores metadata, and exposes them in the web UI.  
Administrators review and publish devices, set ACLs, and configure policies.

### 3. 🌍 Users request discovery
A user enters a **device ID** or scans a **short link**.  
If authorised, the system transmits the device’s mDNS packets into the user’s local network.

### 4. 🔄 Optional proxy mode
For networks requiring full isolation or NAT traversal:
- All traffic goes through the eBPF proxy
- No direct connection is ever made to the device
- Sessions automatically terminate after a timeout


---

## 📁 Repository Structure

The project is structured into several Rust crates:

- `edumdns` – the main binary (server + web + database layer)
- `edumdns_server` - the main component of the system. It routes data and commands, facilitates probe connections and targeted packet transmission to clients.
- `edumdns_web` - Actix web interface
- `edumdns_db` - library for the database layer shared between the server and web 
- `edumdns_probe` – standalone binary for remote packet-capturing probes
- `edumdns_proxy` – standalone eBPF-powered data-proxy for secure forwarding

Each individual crate contains **its own README** with implementation details, APIs, and usage notes.  
This README focuses on the **system-level overview**.

---

# 🧩 System Overview

edumDNS solves the problem that **mDNS is link-local** and cannot cross subnet boundaries.  
Enterprise networks, especially large campus deployments, make local discovery difficult or impossible.

edumDNS provides:

- 🔍 **Secure, on-demand discovery** across any subnet
- 📡 **Remote probes** to capture real device packets
- 🌐 **Web interface** for administrators and users
- 🛡️ **Optional eBPF proxy** to relay all traffic securely
- 🧩 **Full access control** (per-device ACLs, per-user permissions)
- 🗄️ **Centralised database**

The system safely relays discovery information **only when requested** and **only to authorised users**.

---

## Architecture Overview

![diagram](diagrams/diagram.png)

## 🏗️ Binaries

### 1. 🖥️ `edumdns`
**(server + web + database access layer)**

This is the main application running on the central host.  
It includes three tightly integrated components compiled into a single binary:

#### **🔸 Server**
- Receives encapsulated mDNS packets from remote probes
- Stores records in the database
- Receives commands from the web interface
- Controls probe behaviour (commands, adoption, status)
- Triggers on-demand discovery for users
- Transmission control (timers, proxy mode, discovery mode)
- Communicates with the proxy

#### **🔸 Web Interface**
- User login & session-based authentication
- Handling discovery requests and queries to an external database 
- Probe remote configuration and management
- Device search and management
- Packet crafting and editing tools
- Administration UI for probes, devices, packets, users, groups, and permissions

#### **🔸 Database Layer**
A uniform DB abstraction crate included inside `edumdns`, responsible for:
- schema creation and migrations
- database queries
- unpacking and packing DNS-like data
- maintaining device records and packet definitions

PostgreSQL is used as the backend DB.

---

### 2. 🛰️ `edumdns_probe`
**Remote probes that capture mDNS packets on local subnets**

The probes are lightweight agents designed to operate in VLANs where smart devices live.  
Their tasks include:

- Listening only for mDNS traffic
- Parsing and encapsulating packets
- Forwarding them securely to the central server
- Identifying themselves using a random UUID
- Receiving commands (restart, flush, config updates)
- Automatically appearing in the system for adoption

Probes make the system **vendor-independent** and **infrastructure-agnostic**.

They never respond to devices directly, they only observe.

---

### 3. 🧷 `edumdns_proxy`
**Optional eBPF-based secure traffic relay**

Some networks require not only discovery but also controlled communication between the client and the device.

The proxy enables:

- Secure L3 forwarding of traffic between client and device
- Automatic session expiration
- Fine-grained ACL enforcement
- No direct client-to-device connectivity needed

The proxy runs **on the same host as the server**, but is a **separate binary** to ensure isolation:

- Server configures the proxy
- Proxy handles data plane
- eBPF ensures high performance and in-kernel filtering

---


## 🧪 Deployment Notes

edumDNS has been successfully deployed across:

- Masaryk University’s metropolitan network
- eduroam SSIDs
- Multiple remote buildings with separate L2 segments
- SOHO networks during testing

The system is production-ready and supports large-scale deployments with many probes and devices.

---

## 🚀 Getting Started

See the README files in each crate:

- `./edumdns/README.md` – full server/web/DB instructions
- `./edumdns_probe/README.md` – running probes in remote VLANs
- `./edumdns_proxy/README.md` – enabling proxy mode

---

## 🛠️ Build

Run `cargo build --release` in each binary's directory.