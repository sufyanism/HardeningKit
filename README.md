# 🛡️ HardeningKit

### Lightweight Linux Security Baseline Scanner Written in Go

**Audit your Linux system. Identify security misconfigurations. Generate a clear security report.**

HardeningKit is a lightweight, read-only Linux security baseline scanner designed to help developers and system administrators identify common host security issues through a single executable.
Built with Go, HardeningKit produces a colorized terminal report, supports JSON output, and helps you review important security settings without automatically modifying your system.

## Checks
- SSH root-login and password-authentication directives (main config only)
- Firewall signals for UFW, firewalld, and nftables
- World-writable temporary directories without sticky bit
- Sampled SUID inventory in common binary directories
- IPv4 TCP listening socket count
- Package-manager metadata signal (not update freshness)


## 🚀 Quick Start

### Requirements

- Linux host for the security audit
- Go 1.22 or later to build from source
- Appropriate permissions for the checks you want to perform

### Clone the Repository

```bash
git clone https://github.com/sufyanism/HardeningKit.git
cd HardeningKit
```

### Run Tests

```bash
go test ./...
```

### Build

```bash
go build -trimpath -ldflags="-s -w" -o hardeningkit ./cmd/hardeningkit
```

### Run the Scanner

```bash
./hardeningkit
```

For broader system visibility, run with appropriate privileges:

```bash
sudo ./hardeningkit
```


## Exit codes
- `0`: no HIGH or CRITICAL findings
- `1`: report output error
- `2`: one or more HIGH or CRITICAL findings


## 🔍 What Does HardeningKit Check?

| Security Area | Purpose |
|---|---|
| SSH configuration | Review root-login and password-authentication directives |
| Firewall | Detect common Linux firewall implementations |
| Temporary directories | Find world-writable directories without the sticky bit |
| SUID files | Inventory selected system binary locations |
| Network sockets | Count IPv4 TCP listening sockets |
| Package metadata | Inspect package-manager metadata signals |

HardeningKit provides an initial security assessment to help prioritize further investigation.

## ✨ Features
- **SSH Security Checks** — Inspect root-login and password-authentication directives.
- **Firewall Visibility** — Detect firewall signals from UFW, firewalld, and nftables.
- **Filesystem Permissions** — Identify world-writable temporary directories missing the sticky bit.
- **SUID Inventory** — Inspect selected common binary directories for SUID files.
- **Network Visibility** — Count IPv4 TCP listening sockets.
- **Package Metadata** — Check package-manager metadata signals.
- **Readable Reports** — Generate colorized ANSI terminal output.
- **JSON Export** — Save audit results for automation and further analysis.
- **Single-Binary Deployment** — Build a standalone executable with Go.
- **Read-Only Operation** — Inspect system state without automatically changing host configuration.
  
## ⚠️ Scope and Limitations
HardeningKit is a lightweight baseline scanner, not a compliance certification tool or a replacement for CIS benchmarks, penetration testing, or professional security reviews.
Its checks are heuristic and may produce false positives or false negatives. It does not evaluate every SSH configuration include, assess the quality of firewall rules, inventory every SUID file, or verify package update freshness.

## 🧰 Built With
- **Go** — Compiled, portable implementation
- **Linux interfaces** — Host configuration and system inspection
- **ANSI terminal output** — Readable command-line reports
- **JSON** — Machine-readable audit results

## About Me 
✨ I’m **Sufyan bin Uzayr**, an open-source developer passionate about building and sharing meaningful projects.
You can learn more about me and my work at [sufyanism.com](https://sufyanism.com/) or connect with me on [Linkedin](https://www.linkedin.com/in/sufyanism)

## Your all-in-one learning hub! 
🚀 Explore courses and resources in coding, tech, and development at **zeba.academy** and **code.zeba.academy**. Empower yourself with practical skills through curated tutorials, real-world projects, and hands-on experience. Level up your tech game today! 💻✨

**Zeba Academy**  is a learning platform dedicated to **coding**, **technology**, and **development**.  
➡ Visit our main site: [zeba.academy](https://zeba.academy)   </br>
➡ Explore hands-on courses and resources at: [code.zeba.academy](https://code.zeba.academy)   </br>
➡ Check out our YouTube for more tutorials: [zeba.academy](https://www.youtube.com/@zeba.academy)  </br>
➡ Follow us on Instagram: [zeba.academy](https://www.instagram.com/zeba.academy/)  </br>

**Thank you for visiting!**
