# 🧦 SockEm - Documentation

> "Do you know who you're talking to?"

Welcome to the official documentation for **SockEm**, the forensic network scanner that identifies suspicious or potentially malicious socket activity in real-time.

SockEm was built for minimal environments with a zero-write philosophy — ideal for analysts working with sensitive systems or within constrained digital forensics environments.

---

## 📖 What is SockEm?

SockEm monitors live socket connections and correlates them with running processes. It helps you identify:

- **Unexpected listening ports**
- **Unusual memory consumption**
- **Blacklisted processes (e.g., `nc`, `telnet`, `socat`)**
- **Ports typically used by known services, but served by suspicious processes**

---

## 📜 Rulesets

SockEm supports externally defined JSON rulesets to allow custom detection logic.

We currently support:

- `match_process_pair` – Check if a process is valid for a specific port
- `blacklist_process` – Flag certain process names
- `blacklist_port` – Flag connections on suspicious ports
- `match_state` – Match memory or other runtime stats (e.g., memory_kb > 100000)

→ See [custom-rulesets.md](./custom-rulesets.md) for detailed rule examples and schema.

---

## 🚀 Getting Started

```bash
sudo DAEMONIZE=1 python3 src/SockEm.py
