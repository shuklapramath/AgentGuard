# AgentGuard

**Linux eBPF LSM supervisor for coding agents.**

One binary: loads policy into the kernel and starts the agent as the invoking user (not `root`). 

* **Enforcement:** Always runs via Linux. On macOS, Linux runs inside a Docker/Colima VM (`agentguard up`). A native Darwin `claude` binary is *not* supervised.
* **Status:** `v0.1.0` (Early). Tested primarily with [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

---

## Requirements

| OS | Requirements & Setup |
| :--- | :--- |
| **Linux** | Kernel BTF (`/sys/kernel/btf/vmlinux`), BPF LSM (`lsm=bpf` in cmdline, securityfs mounted), `sudo` access, and Claude (or another agent) on your `PATH`. |
| **macOS** | Docker or Colima (`install.sh` automatically installs Colima via Homebrew if `docker info` fails). Supports Apple Silicon and Intel. |
| **Windows** | WSL2 Ubuntu (follow the Linux path). |

> **Note:** The Docker image does **not** include Claude by default. The published image is `ghcr.io/shuklapramath/agentguard`.

---

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/shuklapramath/AgentGuard/master/install.sh | bash
```

This installs `/usr/local/bin/agentguard` from GitHub Releases (checksummed) and runs `agentguard doctor` (failures prior to initialization are expected).

To pin a specific release version: AGENTGUARD_VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/shuklapramath/AgentGuard/master/install.sh | bash.

First run

macOS
> **Important:** OAuth login inside the container does not work. You must use an API key from console.anthropic.com.

```
agentguard login          # Paste key on stdin; writes ~/.agentguard/anthropic_key (not argv)
cd /path/to/your-project  # Do not run in $HOME
agentguard init           # Once per project: creates policies/default.yaml + Claude hooks
agentguard up             # Runs without sudo; pulls :latest on first launch
```

You are ubuntu in /workspace (your project, bind-mounted).

Install Claude inside the runtime (once per machine):
```
curl -fsSL https://claude.ai/install.sh | bash
sudo agentguard -- claude
```

Later sessions (macOS)
Run the following inside your initialized project directory:

```
cd /path/to/your-project
agentguard up
sudo agentguard -- claude
```

Warnings:

* Do NOT run sudo agentguard -- claude directly in a Mac host terminal.
* Do NOT run sudo agentguard up (this uses root's home directory and will miss your API key).


Linux (native)
Prerequisite: Claude must already be installed on the host machine.

```
cd /path/to/your-project
agentguard init
sudo agentguard -- claude
```

> **Note on Login:** `agentguard login` is used for `up` (injecting `ANTHROPIC_API_KEY` into the container). Native `sudo agentguard -- claude` does not read `~/.agentguard/anthropic_key`. Export the key in your environment in a way your `sudoers` retains, or log into Claude normally.

### What `init` Writes

| Path | Scope & Behavior |
| :--- | :--- |
| `$PWD/policies/default.yaml` | **Per project.** Existing file is not overwritten. |
| `$PWD/.claude/settings.json` | **Per project.** Merges hooks. |
| `~/.claude/settings.json` | **Per user** on that machine. |

> **Important:** `agentguard up` requires `./policies/default.yaml` in your current working directory (it does not traverse parent directories). Always `cd` to your project root before running.

**Starter Rules** (edit `policies/default.yaml`):
* **Credential Protection:** Blocks access to sensitive files (`.env`, `id_rsa`, etc.).
* **Egress Allow-list:** only listed hosts (Anthropic, GitHub, …) on port `443`, via the local proxy (`proxy_only`). Anything else, including `google.com`, is denied.
* **Destructive Commands:** Blocks execution of dangerous tools like `rm` or `dd`.

*(See `policies/default.yaml.example` for reference.)*

### Command Reference

| Command | Description |
| :--- | :--- |
| `sudo agentguard -- <agent> [args...]` | Load BPF as root; start the agent process as `SUDO_USER`. |
| `sudo agentguard <pid>` | Attach BPF enforcement to an existing PID. |
| `agentguard init` | Generate default policy configuration and Claude hooks. |
| `agentguard doctor` | Check environment compatibility (Kernel/BTF, policy, Docker, hooks). |
| `agentguard login` | Save `~/.agentguard/anthropic_key` securely from `stdin`. |
| `agentguard up` | Launch privileged container, mount `$PWD` → `/workspace`, and persist runtime. |
| `agentguard hook` | Internal command invoked by Claude *(do not run manually)*. |
| `agentguard version` / `help` | Display CLI version or general usage details. |

### Configuration & Environment

#### Flags & Options
* **CLI Flags** *(must precede the command)*:
  * `-v`, `--verbose` — Enable verbose debug logging.
  * `--policy PATH` — Path to custom policy YAML configuration.

#### Environment Variables
* `AGENTGUARD_POLICY` — Override default policy file path.
* `AGENTGUARD_STATE_DIR` — State directory *(default: `/tmp/agentguard`)*.
* `AGENTGUARD_IMAGE` — Override the default Docker image.
* `ANTHROPIC_API_KEY` — Overrides the saved key in `~/.agentguard/anthropic_key` for `agentguard up`.

> **Note for Linux:** Running `sudo agentguard -- claude` resolves `~/.local/bin/claude` for `SUDO_USER` and automatically routes traffic through AgentGuard’s allow-list proxy using `HTTP(S)_PROXY`.

---

#### macOS Layout (`~/.agentguard`)

| Path | Purpose / Description |
| :--- | :--- |
| `~/.agentguard/anthropic_key` | Mode `0600`; API key generated via `agentguard login`. |
| `~/.agentguard/runtime/.local` | Mounted at `/home/ubuntu/.local` *(stores Claude binary)*. |
| `~/.agentguard/runtime/.claude` | Mounted at `/home/ubuntu/.claude` *(persists settings/state)*. |

> Running container cleanup (`--rm`) deletes container instances, **not** your `~/.agentguard` runtime directory or local project files.

### Updating

There are two separate artifacts to keep in mind: `install.sh` does not automatically refresh the Docker image, and `agentguard up` will not perform a `docker pull` if `:latest` is already present locally.

| Component / Change | How to Refresh |
| :--- | :--- |
| **Host CLI** (`up`, `login`, `install.sh`) | Re-run `install.sh`. |
| **Image / Linux Enforcer** (`Dockerfile`, `sudoers`, `eBPF`) | Run `docker pull ghcr.io/shuklapramath/agentguard:latest`. |
| **Both** | Perform both steps above. |

> **Note:** The initial (`first-ever`) `agentguard up` command will automatically pull the GHCR image by itself.

### Limitations (v0.1.0)

* **Pre-installed Binaries:** Claude is not included in the default Docker image; install it inside `agentguard up` once per machine.
* **Authentication:** `claude login` (OAuth) inside Docker does not work. Use `agentguard login` with an API key instead.
* **Kernel Requirements:** `install.sh` does not enable `lsm=bpf` or mount `securityfs`. A stock kernel or Colima instance without BPF LSM enabled will fail when attaching hooks.
* **Privileges:** `agentguard up` runs with `--privileged` flags and BPF capabilities (required by design).
* **Feedback Loops:** In-chat denial warnings require Claude hooks (`agentguard init`) and a writable `/tmp/agentguard` directory.
* **Scope:** Designed specifically as an eBPF LSM supervisor—not a Mac-native enforcer or hosted sandbox.

> **Logs:** Output is written to `/tmp/agentguard/agentguard.log` (or `$AGENTGUARD_STATE_DIR`). To monitor in real-time, run `tail -f /tmp/agentguard/agentguard.log` in another terminal, as the active TTY is handed off to the agent.

---

### Building from Source

#### Linux Enforcer
```bash
CGO_ENABLED=0 go build -o agentguard .
```
