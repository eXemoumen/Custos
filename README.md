# Custos

> **Declarative permission middleware and transactional execution sandbox for autonomous AI agents.**

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](https://pypi.org/project/custos-middleware/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://pypi.org/project/custos-middleware/)

---

## 1. What is Custos?

Autonomous AI agents execute complex tools: they read and edit codebases, execute terminal commands, query databases, make HTTP requests, and deploy infrastructure. When an agent is exposed to untrusted external input (web pages, user issues, database contents, API responses), a single prompt injection or agent hallucination can result in catastrophic outcomes: data exfiltration, arbitrary file deletion, credential compromise, or unconstrained resource mutation.

Most agent platforms attempt to address this using either:
1. **Advisory system prompts** ("Do not run dangerous commands"), which fail trivially against prompt injection.
2. **In-memory virtual diff overlays**, which break immediately when agent shell tools run real compilers, test suites, or linters (`pytest`, `npm test`, `git status`).
3. **All-or-nothing containerization**, which provides no granular per-tool permission policies, no approval workflows, and no transactional rollback for the workspace.

**Custos combines two complementary control planes into a unified agent runtime:**
* **Control Plane 1 (Authorization & Consent)**: An in-process gateway that intercepts every tool invocation and evaluates it against deterministic policies, context inspectors (indirect prompt injection defense), AI risk assistants, capability leases, and human approval responders before execution occurs.
* **Control Plane 2 (Transactional Execution Enclave)**: An ephemeral single-root sandbox that executes tool file edits and terminal subprocesses within an isolated Git worktree backed by kernel namespace confinement (on Linux) and monotonic taint-driven network egress filtering.

```
                  ┌──────────────────────────────────────────────────────────┐
                  │                 CUSTOS AGENT RUNTIME                     │
                  │                                                          │
  ┌──────────┐    │  ┌────────────────────┐      ┌────────────────────────┐  │      ┌──────────────┐
  │ Autonomous│───┼─>│ 1. Authorization   │─────>│ 2. Execution Enclave   │──┼─────>│ Host System  │
  │  Agent   │    │  │    Gateway         │      │    (Sandbox Bubble)    │  │      │ & External   │
  └──────────┘    │  └────────────────────┘      └────────────────────────┘  │      │ Services     │
                  │    • Default-Deny Policy       • Ephemeral Git Worktree  │      └──────────────┘
                  │    • Taint Tracking            • bwrap Confinement       │
                  │    • Capability Leases         • Monotonic Egress Filter │
                  │    • Human Approvals (Quorum)  • Process Tree Cleanup    │
                  │    • Cryptographic Audit       • Atomic Local Rollback   │
                  └──────────────────────────────────────────────────────────┘
```

---

## 2. Security Boundaries & Threat Model (The Truth First)

Security tools lose credibility when marketing outruns technical reality. Custos makes explicit, binding distinctions between what it defends against, what it mitigates, and what lies strictly outside its security boundaries.

### ✅ What Custos Guarantees
1. **Single-Root Filesystem Consistency**: File tools (`resolve_path`) and terminal commands (`run_command`) operate on the exact same physical path via ephemeral Git worktrees (`.custos/worktrees/<session_id>`). There is zero desync between file modification tools and subprocess tools.
2. **Transactional Local Workspace Rollback**: Uncommitted file additions and modifications are staged in the worktree. Upon session abort or quarantine, local filesystem modifications are discarded, leaving the base host repository untouched.
3. **Fail-Closed Linux Confinement**: When `IsolationLevel.CONFINED` is configured, Custos probes the kernel for unprivileged user namespaces (`bwrap`). If unprivileged namespaces are disabled or missing (e.g. nested unprivileged Docker containers or hardened hosts), Custos **fails closed immediately** with `IsolationUnavailableError`. It never silently degrades to unconfined execution while claiming isolation.
4. **Policy Floor Invariance**: An AI risk assistant, inspector, or human responder can escalate strictness or prompt for approval, but **can never relax a standing policy `deny`**. Default-deny is structurally enforced.
5. **Monotonic Egress State Degradation**: Network egress permissions degrade irreversibly upon session taint escalation (`ALLOWLISTED` -> `READ_ONLY` -> `REVOKED`). Once untrusted data is ingested, subsequent payload-bearing HTTP methods (`POST`, `PUT`, `DELETE`) are blocked to halt exfiltration.
6. **Argument-Gated Capability Leases**: High-privilege tools can be restricted to short-lived, single-use capability leases bound to strict argument predicates. Taint escalation dynamically invalidates active leases.

### ⚠️ Explicit Non-Guarantees & Known Operational Boundaries
1. **Irreversible External Side Effects**: Worktree rollback operates on **local filesystem storage only**. It cannot rewind external network requests, third-party API mutations, webhook deliveries, or database writes dispatched prior to quarantine. If an agent executes an authorized `POST /v1/charges` before taint escalation triggers, that external mutation has occurred. Custos provides an immutable audit trail of the event, not distributed rollback.
2. **LocalBubble is Staging, Not Hostile Confinement**: On platforms lacking unprivileged Linux namespaces (macOS and native Windows), execution runs under `LocalBubble`. Subprocesses run with the executing user's privileges on the host. `LocalBubble` provides transactional filesystem rollback and emits prominent alerts, but does **not** protect against hostile native code probing localhost sockets or escaping relative paths.
3. **Environment Variable Scrubbing is Hygiene, Not Secret Isolation**: Custos strips standard credentials (`AWS_*`, `OPENAI_*`, `CUSTOS_*`) and dynamic loader hooks (`LD_PRELOAD`, `DYLD_LIBRARY_PATH`) from child processes. However, denylist scrubbing is fundamentally incomplete: it does not isolate nonstandard environment keys, credentials stored in files (`~/.aws/credentials`, `~/.ssh/id_rsa`, `.env`), or secrets mounted on disk.
4. **Test Coverage vs. Adversarial Hardening**: Passing unit and integration suites confirms that implemented logic and anticipated edge cases function as designed. It does not constitute formal mathematical proof against active kernel exploits, hardware side-channels, or microsecond TOCTOU race conditions.

---

## 3. How It Works: The Dual-Plane Architecture

Every agent action flows through two coordinated layers:

```
                          Agent Tool Invocation
                                   │
═══════════════════════════════════╪═════════════════════════════════════════════════
 [CONTROL PLANE 1: AUTHORIZATION] │
                                   ▼
                        ┌─────────────────────┐
                        │ 1. Policy Evaluator │  Deterministic YAML rules.
                        │    (Default-Deny)   │  First-match-wins: allow/deny/prompt/assist.
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ 2. Context Inspector│  (Optional) Scans context for indirect
                        │    (IPI Defender)   │  prompt injection and data poisoning.
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ 3. AI Risk Assistant│  (Optional) LLM-backed risk scorer (A1–A12).
                        │    & Fatigue Filter │  Deduplicates prompts; prevents alert storms.
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ 4. Human Responder  │  (Optional) CLI / Slack / Webhook / Quorum
                        │    & Capability Leases│  issues scoped, argument-gated leases.
                        └──────────┬──────────┘
                                   │
                                   ▼ Decision: ALLOW / PROMPT / DENY / QUARANTINE
═══════════════════════════════════╪═════════════════════════════════════════════════
 [CONTROL PLANE 2: EXECUTION]      │
                                   ▼
                        ┌─────────────────────┐
                        │ 5. Sandbox Bubble   │  Single physical execution root:
                        │    (Worktree Manager│  detached Git worktree per session.
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ 6. Isolation Probe  │  CONFINED (bwrap user namespaces on Linux)
                        │    & Confinement    │  or LOCAL (transactional staging + warnings).
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ 7. Monotonic Egress │  ALLOWLISTED -> READ_ONLY (untrusted taint)
                        │    Controller       │  -> REVOKED (malicious/quarantine).
                        └──────────┬──────────┘
                                   │
                                   ▼ Command / Tool Execution
═══════════════════════════════════╪═════════════════════════════════════════════════
 [POST-EXECUTION & LIFECYCLE]      │
                                   ▼
                        ┌─────────────────────┐
                        │ 8. Audit Trail &    │  Cryptographic hash-chained JSONL record.
                        │    Commit / Rollback│  Atomic commit to host on success;
                        └─────────────────────┘  process kill + worktree wipe on quarantine.
```

---

## 4. Quickstart

### Installation

Custos has zero required runtime dependencies beyond `jsonschema`. Optional features are modular:

```bash
# Core gateway + YAML policy support (recommended starting point)
pip install "custos-middleware[yaml]"

# Add LLM-backed risk assistants (LiteLLM)
pip install "custos-middleware[llm]"

# Framework adapters
pip install "custos-middleware[langchain]"      # LangChain / LangGraph
pip install "custos-middleware[mcp]"            # Model Context Protocol (MCP)
pip install "custos-middleware[openai-agents]"  # OpenAI Agents SDK
pip install "custos-middleware[anthropic]"      # Anthropic Messages API
```

### 5-Minute Minimal Example

```python
from pathlib import Path
from custos import Gateway, Policy
from custos.audit import FileAuditSink
from custos.responders import CLIResponder
from custos.sandbox import BubbleManager, BubbleConfig, IsolationLevel

# 1. Define declarative policy rules
policy_yaml = """
version: 1
default: deny

overlays:
  - id: dev_rules
    rules:
      - match: { tool: "fs.read*" }
        action: allow_and_audit

      - match: { tool: "fs.write*" }
        action: allow_and_audit

      - match: { tool: "shell.run", risk_tier: [4, 5] }
        action: prompt

      - match: { tool: "network.fetch" }
        action: allow_and_audit
"""
policy = Policy.from_yaml_string(policy_yaml)

# 2. Configure execution enclave (transactional git worktree staging)
bubble_mgr = BubbleManager(
    base_config=BubbleConfig(
        workspace_root=Path("."),
        isolation_level=IsolationLevel.LOCAL,  # or IsolationLevel.CONFINED on Linux
    )
)

# 3. Assemble Gateway
gw = Gateway(
    policy=policy,
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),
    bubble_manager=bubble_mgr,
)

# 4. Gated tool implementations using the bubble's unified root
def write_code(file_path: str, content: str) -> str:
    # Resolve target strictly inside the session's ephemeral worktree
    session = gw.session_store.get_or_create("session-123")
    target = session.bubble.resolve_path(file_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} bytes to {file_path}"

def run_tests(command: str) -> str:
    # Execute command strictly within the bubble's worktree
    session = gw.session_store.get_or_create("session-123")
    result = session.bubble.run_command(command.split())
    return result.stdout or result.stderr

# 5. Wrap tools with Custos
gated_write = gw.wrap_tool(write_code, name="fs.write")
gated_test = gw.wrap_tool(run_tests, name="shell.run")

# Agent executes actions in staging
gated_write("src/app.py", "print('hello from bubble')")
gated_test("pytest")

# 6. Commit staged changes back to the real repository, or rollback
bubble_mgr.commit("session-123")    # Applies staged edits to host workspace
# or bubble_mgr.rollback("session-123")  # Eradicates worktree; host stays untouched
```

---

## 5. Core Architectural Components

### A. Single-Root Worktree Manager (`GitWorktreeManager`)
Virtual in-memory filesystems desync the moment an agent spawns a real shell subprocess (`pytest`, `npm build`, `cargo test`). Custos eliminates this failure mode by binding every session to an isolated Git worktree (`git worktree add --detach .custos/worktrees/<session_id> HEAD`):
* **Single Physical Root**: Python file tools (`resolve_path`) and terminal commands (`run_command`) operate on the exact same physical disk blocks.
* **Path Traversal Containment**: `resolve_path()` prevents directory escaping (`../../`) and strictly denies direct access to internal metadata (`.git`, `.custos`).
* **Symlink Boundary Defense**: Staged symlinks targeting host paths outside the workspace are rejected during commit. Existing symlinks at destination paths are unlinked prior to writing to avoid redirecting file copies outside the workspace.
* **Non-Git Staging & Preserved Directories**: For projects not managed under Git, Custos falls back to an isolated copy with fallback content diffing. To prevent destructive commits, dependency trees (`node_modules`, `.venv`, `venv`, `__pycache__`) are registered under `EXCLUDED_DIRS` and are never scanned, staged, or removed from the host repository.

### B. Linux Kernel Confinement (`AgentBubble`)
When running on Linux with `IsolationLevel.CONFINED`, Custos wraps command execution in Bubblewrap (`bwrap`) unprivileged user namespaces:
* **Minimal System Mounts**: Only essential host system binaries (`/usr`, `/bin`, `/lib`, `/lib64`, `/etc/ssl`) are bound read-only.
* **Writable Workspace Jail**: Only the session's ephemeral worktree path is mounted read-write (`--bind`). Temporary storage uses an isolated tmpfs (`--tmpfs /tmp`).
* **Complete Namespace Unsharing**: Drops network, PID, IPC, and UTS namespaces (`--unshare-all`).
* **Lifecycle Supervision**: Child processes die automatically if the supervising runtime exits (`--die-with-parent`).
* **Fail-Closed Guarantee**: If user namespaces are disabled (`kernel.unprivileged_userns_clone = 0` or restricted Docker profile), Custos refuses to execute and raises `IsolationUnavailableError`.

### C. Monotonic Egress State Machine (`EgressController`)
Network egress controls dynamically adapt to session taint level:

```
┌─────────────┐   Ingest Untrusted Input     ┌───────────┐   Detect Injection / Exploit   ┌─────────┐
│ ALLOWLISTED │ ───────────────────────────> │ READ_ONLY │ ─────────────────────────────> │ REVOKED │
└─────────────┘                              └───────────┘                                └─────────┘
  • Configured domains                         • GET / HEAD only                            • All traffic
  • All HTTP methods                           • POST/PUT/DELETE blocked                      blocked
  • Pre-taint execution                        • Exfiltration neutralized
```

Permissions degrade monotonically: an agent that has ingested untrusted content can never restore itself to `ALLOWLISTED` status within the same session.

### D. Capability Leases & Taint Invalidation (Invariant 6)
High-risk tools (cloud deployments, database mutations, external communications) are governed by `CapabilityLease`:
* **Argument-Gated Authority**: Leases constrain the tool name, expiration timestamp, maximum invocations, and arbitrary boolean predicates over input arguments (`allowed_args_predicates`).
* **Automatic Taint Invalidation**: When a session ingests an untrusted source (`TaintLevel.UNTRUSTED`), all active capability leases for that session are invalidated under thread lock, terminating in-flight authority before exfiltration tools can be called.

### E. Quarantine Purge & Process Termination
When the gateway issues `Decision.QUARANTINE`:
1. Network egress is instantly locked to `REVOKED`.
2. All active child subprocesses spawned by the bubble are terminated (`SIGTERM` followed by `SIGKILL`).
3. Staged worktrees are purged via `worktree.rollback()`.
4. Host workspace remains clean and byte-for-byte untouched.

### F. Tamper-Evident Cryptographic Audit Trail
Every decision and lifecycle event is recorded in append-only JSON Lines with SHA-256 hash chaining:
* **Attributed Metadata**: Records timestamp, session ID, tool name, argument hash, decision, policy rule match, session taint, capability lease ID, and execution bubble ID.
* **Hash-Chaining**: Each entry incorporates the preceding entry's hash (`event_hash = SHA256(prev_hash + canonical_json(event))`).
* **Integrity Verification**: Verifiable offline via `custos audit verify audit.jsonl`.
* **Deep Redaction**: Sensitive arguments (passwords, tokens, API keys) are recursively redacted before reaching audit logs or human approver interfaces.

---

## 6. Permission Assistants (A1–A12)

Custos reproduces the 6 permission assistants from the Janus academic reference (arXiv:2607.01510) and adds 6 production-focused extensions:

| ID | Name | Strategy | Needs LLM? | `exfiltrates_args` | Description |
|:---|:---|:---|:---:|:---:|:---|
| **A1** | Auto-Approve | Baseline | No | No | Always approves. Baseline for evaluation only. |
| **A2** | User Confirmation | Interactive | No | No | Prompts user on every un-allowed invocation. |
| **A3** | Constitution | Model-driven | Yes | Yes | Evaluates action against written constitutional principles. |
| **A4** | Policy Suggestion | Synthesizer | Yes | Yes | Proposes permanent policy rules from repetitive approval decisions. |
| **A5** | Risk Assessment | Risk Scorer | Yes | Yes | Evaluates operational risk (1–5) and prompts user on high risk. |
| **A6** | Autonomous Risk | Hard Gate | Yes | Yes | Denies requests exceeding risk threshold without prompting. |
| **A7** | Rule Policy | Deterministic | No | No | Fast-path evaluation of deterministic Python rules. |
| **A8** | Summarize Batch | Consolidator | No | No | Batches identical or parallel tool calls into a single prompt. |
| **A9** | Context Adaptive | Dynamic | Yes | Yes | Adjusts prompt detail based on sensitivity of agent context. |
| **A10** | Learned Policy | Statistical | No | No | Computes Bayesian approval probabilities from historical audit logs. |
| **A11** | Delegation Aware | Hierarchy | No | No | Automatically restricts permissions as agent delegation depth increases. |
| **A12** | IPI Defender | Context Inspector | Configurable | No | Detects indirect prompt injection using causal leave-one-out token attribution. |

---

## 7. Responders

When an invocation requires human oversight, Custos dispatches requests to pluggable responders:

* **CLI Responder** — Terminal prompt (`y`/`N`/`a`/`A`/`l`/`d`) with configurable timeout.
* **Web Responder** — Embeddable SSE-backed web UI (`127.0.0.1` binding, bearer token authenticated, escaped text rendering to prevent XSS).
* **Slack Responder** — Block Kit messages with signed interactions and approver role validation.
* **Webhook Responder** — HMAC-signed HTTP POST callbacks with nonce replay protection.
* **Quorum Responder** — Requires $N$ distinct approvals from disjoint roles for high-impact operations.

---

## 8. Reality Matrix & Comparison

| Security Property | Unrestricted Agents (LangChain, AutoGen, CrewAI) | Containerized Agents (Docker / Podman) | In-Memory Virtual Diffs | **Custos Runtime** |
| :--- | :--- | :--- | :--- | :--- |
| **Tool-Level Authorization** | ❌ None (direct tool call) | ❌ None (runs inside container) | ⚠️ Partial (in-memory) | **✅ Declarative Policy Engine + Leases** |
| **Filesystem Consistency** | ⚠️ Direct host modification | ⚠️ Direct container modification | ❌ Desyncs with subprocesses | **✅ Single Physical Worktree Root** |
| **Workspace Rollback** | ❌ Manual git reset | ❌ Discard entire container | ⚠️ Fragile patch revert | **✅ Atomic Worktree Rollback** |
| **Prompt Injection Defense** | ❌ Advisory system prompt | ❌ None | ❌ None | **✅ Context Inspector (A12) + Taint Engine** |
| **Network Egress Control** | ❌ Unrestricted | ⚠️ Static IP/Port allowlist | ❌ Unrestricted | **✅ Monotonic Taint-Degraded Egress** |
| **External Side-Effect Rollback** | ❌ Impossible | ❌ Impossible | ❌ Impossible | ⚠️ **Impossible** *(Accurately Audited, Not Rewound)* |
| **Hostile Isolation on macOS/Win** | ❌ None | ⚠️ VM required (Docker Desktop) | ❌ None | ⚠️ **Local Staging Only** *(Linux Confinement via bwrap)* |

---

## 9. Framework Adapters

Custos integrates non-invasively into popular agent frameworks without modifying tool signatures:

```python
# LangChain & LangGraph
from custos.integrations.langchain import wrap_langchain_tools
agent_tools = wrap_langchain_tools(gateway, [read_file, write_file, run_bash])

# FastMCP / Model Context Protocol
from custos.integrations.mcp import wrap_mcp_tools
wrap_mcp_tools(gateway, mcp_server)

# OpenAI Agents SDK
from custos.integrations.openai_agents import gated_function_tool
@gated_function_tool(gateway=gateway, name="db.execute")
def execute_query(query: str) -> list[dict]: ...

# Anthropic Messages API
from custos.integrations.anthropic import gated_anthropic_tool
dispatch_map = gated_anthropic_tool(gateway, tool_definitions)
```

---

## 10. Evaluation, Testing, and Assurance Policy

### Continuous Integration Suites
* **Janus-v1 Parity Suite**: Reproduces the published 72-cell evaluation matrix from Brigham et al. (arXiv:2607.01510).
* **Adversarial Suite (53+ Cells)**: Validates prompt injection detection, confused deputy resistance, tool spoofing prevention, delegation depth limits, policy poisoning defense, and quorum bypass resistance.
* **Sandbox Regression Suite**: Exercises Git worktree creation, rollback hygiene, copy fallback diffing, bwrap argument wrapping, and process termination.

### Roadmap for Adversarial Assurance
Unit and integration test suites confirm expected behavioral paths. Custos maintains an active adversarial roadmap to harden invariants beyond unit assertions:
1. **Concurrency & TOCTOU Fuzzing**: Stress testing worktree `commit()` against concurrent symlink replacement.
2. **Asynchronous Taint Race Verification**: Validating atomic capability lease invalidation under high-throughput concurrent tool execution.
3. **Containerized Worker Backend (`IsolationLevel.CONTAINER`)**: Providing rootless Docker/Podman isolation for macOS, Windows, and container-nested environments where Linux user namespaces are unavailable.

---

## 11. Documentation Index

* 📘 [Quickstart Guide](docs/quickstart.md) — Walkthrough of gateway initialization and tool wrapping.
* 📋 [Policy Schema Reference](docs/policy.md) — Match syntax, glob rules, predicate arguments, and overlays.
* 🛡️ [Normative Threat Model](docs/THREAT_MODEL.md) — Formal STRIDE breakdown mapping assets, trust boundaries, and mitigations.
* 🔬 [Sandbox Bubble Engine Specification](docs/sandbox_bubble.md) — Single-root execution, `bwrap` flags, and rollback semantics.
* 🤖 [Permission Assistant Catalog](docs/assistants.md) — Details on A1 through A12 with configuration examples.
* 🔍 [Audit Reference & Verification](docs/audit.md) — Hash-chain validation, sinks, and forensic verification.
* 🧪 [Evaluation Harness](docs/eval.md) — Janus v1 parity benchmarks and Custos adversarial test suite.
* 📜 [IR Contract Specification](IR_CONTRACT.md) — Cross-language JSON schema pinning Python and TypeScript runtimes.

---

## 12. License

Apache-2.0. See [LICENSE](LICENSE) for details.

