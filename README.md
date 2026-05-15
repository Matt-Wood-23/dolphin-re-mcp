# dolphin-re-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes [Dolphin
emulator](https://dolphin-emu.org/)'s GDB stub plus a process-attach memory
backend as tools an LLM agent (Claude Code, Cursor, etc.) can call. It turns
Dolphin into a live reverse-engineering target: read/write game memory, set
breakpoints and watchpoints, capture register state on hit, disassemble
PowerPC, and trace writers/callers — all from natural-language prompts.

Built and tested against Monster Hunter Tri (Wii), but the tool surface is
generic to any GameCube or Wii title.

## What you need

| Component | Required? | Notes |
|---|---|---|
| Python 3.10+ | yes | tested on 3.11/3.12 |
| Dolphin (patched fork, see below) | strongly recommended | upstream Dolphin works but its GDB stub permanently wedges on every save-state load and over-polls on Windows |
| A GameCube/Wii game image | yes | `.iso` / `.nkit.iso` / `.rvz` etc. |
| Ghidra + [GhidraMCP plugin](https://github.com/LaurieWired/GhidraMCP) | optional but recommended | enables function-lookup + decompile + plate-comment workflows alongside the live Dolphin tools |
| Windows | recommended | the process-attach memory backend is Windows-only; GDB-stub-only mode works on Linux/macOS but is slower |

### Dolphin fork (patched)

The upstream Dolphin GDB stub has two limitations that this project hit hard:

1. **Save-state load permanently wedges the stub.** `CoreTiming::DoState`
   replaces the live event queue with the serialized one, dropping the stub's
   self-rescheduling `GDBStubUpdate` event. The stub appears connected
   (sockets intact, `IsActive()` true) but stops servicing packets.
2. **Windows socket-poll overhead.** The stub polls every 100k cycles
   (~137 µs) for incoming packets — ~7,300 syscalls/sec on Windows.

The fork at [Matt-Wood-23/dolphin (branch `fix/gdbstub-save-state-resume`)](https://github.com/Matt-Wood-23/dolphin/tree/fix/gdbstub-save-state-resume) adds:

- `GDBStub::OnAfterStateLoad()` — re-arms the update event after a save-state
  load. Called from `Core::State::LoadAsFromCore`.
- `GDB_UPDATE_CYCLES` bumped from 100,000 → 1,000,000 (~1.4 ms interval) to
  cut Windows poll overhead 10×. Breakpoint/watchpoint *hit* latency is
  unaffected (those fire via `SendSignal`, not the poll).

Both changes are upstream-PR-ready. Once they land in mainline Dolphin you
can use any official Dolphin build.

## What you get

- **Memory** — typed reads (u8/u16/u32/s32/f32/f64), raw byte reads, hex
  dumps, struct reads, pointer chains, region searches, full-memory snapshots
  and diffing.
- **Execution** — pause, resume, step, step over, step out, run-until-address.
- **Registers** — PC, LR, CTR, all GPRs / FPRs / SPRs, walked stack frames.
- **Breakpoints / watchpoints** — software BPs, HW write/read/access
  watchpoints, capture-on-hit (auto-continue + record GPRs/FPRs/LR/stack on
  every fire) with optional Python-predicate filtering.
- **Disasm** — Capstone-backed PPC disassembly with operand classification,
  effective-address resolution for load/stores, and `lis`+`addi/ori` pair
  fusion into single immediate-load entries.
- **Compound flows** — `trace_writes_to` (cheatmine writer-trace in one
  call), `trace_calls_to`, `trace_until` (step-by-step instruction trace
  with stop conditions).
- **Diagnostics** — `health_check` reports connection state, attach status,
  pending stop replies, and current PC.

## Install

```powershell
git clone https://github.com/<you>/dolphin-re-mcp
cd dolphin-re-mcp
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest    # 117 tests, no Dolphin needed
```

Linux/macOS: the GDB-stub backend works cross-platform; the process-attach
backend currently only implements Windows (via `pymem`). Without attach,
memory reads fall back to GDB `m`/`M` packets — slower but functional.

## Wire into Claude Code

A ready-to-edit [`.mcp.json.example`](.mcp.json.example) ships in this repo.
Copy it to `.mcp.json` and replace the placeholder paths:

```bash
cp .mcp.json.example .mcp.json
# then edit .mcp.json to point at your venv python and (optionally) ghidra-mcp
```

`.mcp.json` is gitignored — your local paths stay local.

Full template:

```json
{
  "mcpServers": {
    "dolphin": {
      "command": "E:\\dolphin_re_mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "dolphin_re_mcp.server"],
      "cwd": "E:\\dolphin_re_mcp",
      "env": {
        "DOLPHIN_GDB_HOST": "localhost",
        "DOLPHIN_GDB_PORT": "55432"
      }
    },
    "ghidra": {
      "command": "python",
      "args": ["E:\\ghidra-mcp\\bridge_mcp_ghidra.py", "--no-lazy"],
      "env": {
        "GHIDRA_SERVER_URL": "http://127.0.0.1:8089/"
      }
    }
  }
}
```

The `ghidra` block is optional. With it, the same agent can pull function
decompiles, plate comments, and symbol lookups from your live Ghidra project
in the same conversation it's setting watchpoints and reading registers —
e.g. "set a write WP on `0x806ADAC4`, then look up the PC of the hit in
Ghidra and decompile that function." See
[GhidraMCP](https://github.com/LaurieWired/GhidraMCP) for the plugin install.

Claude Code will list the dolphin (and ghidra) tools on next launch.

## Launching Dolphin

The GDB stub is enabled by setting a port; **don't** use the `-d` debug
flag (it disables JIT optimizations and tanks emulation speed).

**PowerShell (Windows):**

```powershell
& "D:\path\to\dolphin-fork\Binary\x64\Dolphin.exe" --config "Main.Core.GDBPort=55432"
```

**bash (Linux / macOS):**

```bash
"/path/to/dolphin-fork/Binary/x64/Dolphin"  --config "Main.Core.GDBPort=55432"
```

The `--config` flag is one-shot — it sets the port for this launch only.
If you'd rather make it permanent, edit
`%APPDATA%\Dolphin Emulator\Config\Dolphin.ini` (Windows) or
`~/.config/dolphin-emu/Dolphin.ini` (Linux/macOS) and add `GDBPort = 55432`
under the `[General]` section, then launch with no flags.

> If you're using the [patched fork](#dolphin-fork-patched), substitute its
> build path. If you're using stock Dolphin, same command — just expect the
> stub to wedge after the first save-state load (you'll need to relaunch).

## Per-session sequence

1. Launch Dolphin using the command above.
2. **Do not open any Dolphin debug panel** (Code, Memory, Registers,
   Breakpoints) during the session. The GDB stub is single-client; opening
   any panel mid-session will drop the MCP's connection.
3. Boot your game ISO. The CPU starts halted, waiting for the first GDB
   connection.
4. **Issue any MCP tool call** (e.g. ask the agent to `health_check_tool` or
   `get_pc_tool`). The first call triggers connect + process-attach +
   auto-resume — the game will start running.
5. Once the game is at a playable state, **load a save state** if you have
   one. With the patched fork, save-state loads no longer wedge the stub
   (the classic upstream bug); on stock Dolphin, you must relaunch after
   every load.

## Operating notes

These are the things that surprise people. Read once.

- **The MCP doesn't connect until you make a tool call.** It's lazy. So if
  you launch Dolphin and the game looks stuck, just ask the agent to do
  *anything* — `health_check_tool`, `get_pc_tool`, etc. That call kicks off
  the connection sequence and sends `c` to release the GDB-stub halt.
- **Addresses accept int or string.** Every `addr` parameter takes either a
  prefixed hex string (`"0x806BBC74"`), a decimal int (`2154544244`), or a
  decimal string (`"2154544244"`). Bare hex without `0x` is rejected so an
  ambiguous value can't be silently read as decimal. Use `addr_info_tool` if
  you need to convert: it returns `{decimal, hex, region, valid}` for any
  input.
- **If `pause` ever fails, memory reads still work** — they go through the
  process-attach backend and don't need the GDB stub. Useful fallback when
  the CPU thread is unreachable (e.g. UI-pause).
- **`stub_responsive: false` in `health_check` is normal while running.**
  The stub only services queries when the CPU is paused; it's not a
  connection problem.

## Roadmap (in progress)

Open work items, roughly ordered by likelihood we'll do them:

- **Eager auto-connect.** Right now the MCP doesn't dial Dolphin's GDB
  socket until the first tool call. Plan: small background task in
  `session.py` that retries the connect on a loop after MCP startup, so the
  moment Dolphin appears on the port we attach + auto-resume — no need to
  poke the agent to start the game.
- **`arm_at_boot_tool`.** Single MCP call that halts the CPU, arms a list
  of breakpoints / watchpoints, and resumes — replacing the
  `DOLPHIN_NO_AUTO_RESUME=1` escape hatch for the common "I want to catch
  the very first hit" case.
- **Further bump `GDB_UPDATE_CYCLES`** (1M → 10M) if Windows perf still
  feels sluggish in long sessions. Conservative ship at 1M for the
  upstream PR; we can tune higher locally.
- **Linux/macOS process-attach memory backend.** Today the attach backend
  is Windows-only (via `pymem`). Falling back to GDB `m`/`M` works but is
  slower. Plausibly `procfs` on Linux, `mach_vm_read` on macOS.

PRs and issues welcome.

## Critical: GDB stub is one-shot per Dolphin launch

Dolphin's GDB stub stops listening after any disconnect — clean detach,
crash, or just `socket.close()`. Once gone, you cannot reconnect without
restarting Dolphin.

The MCP holds **one** persistent connection for the whole session. If you
see `ConnectionLost`, restart **both** Dolphin and the MCP server.

### Save-state load (patched fork only)

Upstream Dolphin permanently wedges the stub on any save-state load. The
[patched fork](https://github.com/Matt-Wood-23/dolphin/tree/fix/gdbstub-save-state-resume)
re-arms the stub's update event after a load (`OnAfterStateLoad`), so the
stub keeps serving packets. **You must still re-arm any breakpoints or
watchpoints after a state load** — the BPs/WPs are tracked by the MCP, not
serialized with the state, so they go stale silently.

### UI-pause behavior

Pausing via Dolphin's UI (Emulation → Pause) freezes the CPU thread that
serves GDB packets. MCP tools will raise `StubWedged` until you unpause.
It's not destructive — the stub recovers cleanly when you resume.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `DOLPHIN_GDB_HOST` | `localhost` | GDB stub host |
| `DOLPHIN_GDB_PORT` | `55432` | GDB stub port |
| `DOLPHIN_NO_AUTO_RESUME` | unset | If set, skip the auto-`c` after connect |
| `MHTRI_DUMPS_DIR` | unset | Directory for `snapshot_to_dump` output |
| `DOLPHIN_RE_MCP_LOG` | unset | If set, write structured logs to this path |

## Pairing with Ghidra

When the `ghidra` MCP is wired alongside (see [Wire into Claude Code](#wire-into-claude-code)),
the agent can do round-trip RE in one conversation:

1. **Dolphin**: set a write watchpoint with `capture_on_hit` on a candidate
   address.
2. Play through the in-game action you want to trace (shoot, throw, take
   damage, pick up item, etc.).
3. **Dolphin**: pull the capture log — PC, GPRs, stack at every hit.
4. **Ghidra**: `get_function_by_address(<captured_PC>)` resolves it to a
   named function, `decompile_function` returns the C-like source, and any
   plate comments you've left in prior sessions are returned verbatim.
5. The agent reads the surrounding context and tells you what the
   captured instruction is doing, who its callers are, and what other
   addresses to watch next.

## Architecture

- `gdb/client.py` — bare GDB Remote Serial Protocol implementation
  (packet framing, ack handling, stop replies, register access).
- `memory/attach.py` — Windows `pymem` backend that scans the live Dolphin
  process for MEM1/MEM2 mappings and reads/writes them directly (no JIT
  pause).
- `memory/routing.py` — virtual-address routing (MEM1: 0x80000000–0x81800000,
  MEM2: 0x90000000–0x94000000) and the `coerce_addr` parser used at every
  MCP tool boundary.
- `session.py` — single owner of the GDB connection, both memory backends,
  and the breakpoint registry. Tools never open their own socket.
- `stop_watcher.py` — background thread that consumes stop replies for
  `capture_on_hit`-armed breakpoints and auto-continues.
- `tools/` — the `@mcp.tool()` registrations grouped by capability
  (memory / execution / breakpoints / disasm / compound flows).

## PowerPC / Wii gotchas worth knowing

- Dolphin's `g` packet returns 32 GPRs only (128 bytes).
- PC = `p40`, MSR = `p41`, CR = `p42`, **LR = `p43` (NOT 41)**, CTR = `p44`,
  XER = `p45`.
- Stop replies contain PC + SP only; query LR separately.
- MEM1 = `0x80000000+`, MEM2 = `0x90000000+`. The mirror at `0x00000000`
  and the cached aliases at `0xC0000000+` are deliberately unsupported —
  use the canonical `0x8XXXXXXX` / `0x9XXXXXXX` addresses.
- Software BPs interact with Dolphin's JIT cache; HW BPs are more reliable
  for hot code paths.

## License

MIT.
