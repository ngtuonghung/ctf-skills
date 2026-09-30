# Pwnable.tw Heap and Object Cases

Instance-preserving casebook for ten pwnable.tw challenges whose primary surface is heap, C++ object, or heap-managed control data. Generic technique explanations live in the parent references; this file retains challenge-specific facts, every historical exploit path, negative findings, exact offsets, provenance, and solution indexes.

## How To Use This File

Use this file when object/array lifetime, C++ copy/destructor behavior, type confusion, function/vtable pointer, or language-object confusion creates the first primitive. For decisive tcache/fastbin/unsorted/House/FILE mechanics, open `allocator-file-cases.md` instead.

## Case Index

| Challenge | Canonical route |
|---|---|
| [`applestore`](#applestore) | Stack node inserted into a heap cart list → Unsafe unlink/type confusion, arbitrary read/write, and EBP pivot to GOT |
| [`babyallocator`](#babyallocator) | `scanf` versus split-stack metadata mismatch → Stack-segment/heap overlap, ROP, TLS destructor, or stdout FSOP |
| [`caov`](#caov) | C++ copy-assignment lifetime bug → UAF/double-free, BSS House of Spirit/fastbin, and FSOP |
| [`criticalheap`](#criticalheap) | Environment-controlled heap read plus FORTIFY-safe format read → Heap flag leak; optional `realpath(path,path)` overflow for shell |
| [`criticalheap_pp`](#criticalheap_pp) | `realpath` off-heap overflow → Controlled free/UAF, fastbin poison, unsafe unlink, overlapping chunks, or stdout FSOP |
| [`digimon`](#digimon) | Missing NUL followed by tokenizer overwrite → Unbounded task-queue writes, Partner overlap, vtable/UAF, and race-sensitive hooks or thread-stack ROP |
| [`ghost_party`](#ghost_party) | Missing C++ copy constructor → Temporary-destructor double-free, fastbin dup, fake vtable, or stdout FSOP |
| [`hacknote`](#hacknote) | Global note pointer UAF/double-free → Fake note/function pointer and content, GOT leak, then `system(";sh")` |
| [`omegago`](#omegago) | History-array OOB into board state → Leak/arbitrary read, fake BSS sizes, House of Spirit, and vtable overwrite |
| [`stupid_boss`](#stupid_boss) | Cross-language object-model type confusion → Arbitrary C-string read, 20-byte write, hooks, stack ROP, or FILE vtable |


## applestore
> **Canonical route:** Stack node inserted into a heap cart list → Unsafe unlink/type confusion, arbitrary read/write, and EBP pivot to GOT
> **Read this case when:** A shopping-cart program inserts a stack-local iPhone 8 node during checkout.
> **Primary defect:** Stack node inserted into a heap cart list
> **Exploit primitive/result:** Unsafe unlink/type confusion, arbitrary read/write, and EBP pivot to GOT
> **Search terms:** cart; `$7174`; iPhone 8; unsafe unlink; `my_read`; EBP pivot
> **Version/protection clue:** Case target `applestore` — i386, glibc 2.23, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; distinguish from ordinary menu unlink because the inserted node lives on the stack.

### Metadata

```yaml
tags:
  - stack-pivoting
  - type-confusion
  - arbitrary-write
  - got-overwrite
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
description: Inserting a stack-allocated item node into the heap-managed cart doubly-linked list enables an arbitrary write primitive during item deletion, allowing GOT overwrite to hijack control flow.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10104`.
- Flag: `FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}`.
- Community provenance: 167 solutions. Write-up IDs: `100`, `138`, `170`, `1006`, `1155`, `1177`, `1200`, `1297`, `1303`, `1316`, `1351`, `1384`, `1387`, `1395`, `1524`, `1715`, `10115`, `11540`, `13060`, `14121`, `16633`.

### Facts

- The 32-bit store keeps a cart as a doubly linked list of `malloc`ed 16-byte device nodes. Protections are Partial RELRO, canary, NX, and no PIE (`0x8048000`).
- Device node layout: `+0x00 name`, `+0x04 price`, `+0x08 next`, `+0x0c prev`.
- BSS cart state: `0x0804B068` head, `0x0804B06C` tail, and `0x0804B070` first-node pointer used for a heap-base leak. Fixed GOT addresses are `atoi=0x0804B040`, `puts=0x0804B028`, `printf=0x0804B010`, and `read=0x0804B00C`.
- V1 (primary, exploitable): `checkout` inserts a local iPhone 8 node into the cart when the total is exactly `$7174` (`0x1c06`). After return, the stale stack node overlaps later `handler`, `cart`, and `delete` frames, letting the 21-byte `my_read(buf, 0x15)` input control `name`, `price`, `next`, and `prev`.
- Total equation: `199*a + 299*b + 399*c + 499*d = 7174`. Source examples include `6*199 + 20*299`, `16*199 + 10*399`, and solution `16633`'s `19*199 + 6*399 + 1*299`.
- V2 (exploitable): in `cart`, `buf` is at `ebp-0x22`; the iPhone node starts at `ebp-0x20`, two bytes into the read. `"y\0"` plus a target pointer makes node 27 print four bytes through the controlled `name`.
- V3 (exploitable): in `delete`, input can similarly replace node 27's links. Unlink performs `*(prev+8)=next` and `*(next+12)=prev`, yielding an arbitrary four-byte write plus a reciprocal four-byte side effect.
- V4 (enabler): exact `my_read` layout is `ebp-0x22` marker, `ebp-0x20` name, `ebp-0x1c` price, `ebp-0x18` next, and `ebp-0x14` prev.
- Remote libc offsets: `atoi=0x2d050`, `system=0x3a940`, `environ=0x1b1dbc`, `puts=0x5f140`, `printf=0x49020`, `read=0xd5980`, `/bin/sh=0x158e8b`, and one-gadgets `[0x5f065, 0x5f066, 0x3a819]`. `__environ` to the handler saved EBP offset is `260` (`0x104`).

### Exploit Paths

- Paths A-E share the V1 stack node, V2 read, and V3 unlink write; they differ in the final control-flow transfer.
- Path A (most common; source `exp.py`, solutions `138`, `170`, `1155`, `1200`, `1297`, `1303`, `1316`, `1384`, `1387`, `1395`, `1524`, `1715`, `10115`, `11540`, `13060`, `14121`, `14479`, `16633`, and more): checkout, read GOT through V2, read `__environ`, overwrite saved EBP through V3 so `leave; ret` pivots `atoi@GOT+0x22` to `ebp-0x22`, then send `p32(system)+";/bin/sh\0"` so `atoi(buf)` becomes `system(buf)`. Deterministic.
- Path B (solutions `1006` and a `1316` variant): delete to leave only the stack node, repeatedly use unlink to write one byte at a time into `__malloc_hook` by selecting stack/BSS source addresses containing the desired byte, then trigger allocation and one-gadget. Source pseudocode uses `malloc_hook - 0xC + offset`; reliability stated as 100% but complex.
- Path C (solutions `138`, `1155`, `1177`, `1351`): pivot EBP/return control to a one-gadget; example sends `'6aaa' + p32(one_gadget)` after pivoting.
- Path D (solution `1316`): overwrite `puts@GOT` with `add esp, 0x1c; ret`, then use the next menu payload containing `system` and `/bin/sh` to pivot and execute.
- Path E (solutions `1351`, `1384`, `10115`): leak heap through `myCart+8` or `main_arena`, walk heap nodes to recover the stack address embedded in the final node's `next`, and derive saved EBP without `__environ`; requires heap-layout knowledge.

### Assets and Provenance

- Historical `exp.py`: working pure-socket exploit.
- `desc.txt`: challenge description.
- `artifacts/applestore`: stripped i386 challenge binary.
- `artifacts/libc_32.so.6`: remote glibc 2.23 i386 libc.
- `solution/*.md`: 167 community write-ups.
- Path-to-write-up notes: `100`=A with `__libc_start_main@GOT` and heap stack leak; `138`=C/Ruby; `170`=A clean Python; `1006`=B; `1155`=C/heap; `1177`=C after deleting 25 items; `1200`=A and `system(";sh")`; `1297`=A/Z3; `1303`=A/two-stage leak; `1316`=D; `1351`=E/main arena; `1384`=E/BSS node; `1387`=A/read GOT; `1395`=A/direct EBP to GOT+0x22; `1524`=A/heap walk; `1715`=A/`;/bin/sh`; `10115`=E; `11540`=A/fixed 21-byte read; `13060`=A/multibyte leak; `14121`=A/puts and environ; `16633`=A/EBP pivot.

## babyallocator
> **Canonical route:** `scanf` versus split-stack metadata mismatch → Stack-segment/heap overlap, ROP, TLS destructor, or stdout FSOP
> **Read this case when:** A recursive/split-stack allocator corrupts stack-segment metadata through `scanf`/`alloca`.
> **Primary defect:** `scanf` versus split-stack metadata mismatch
> **Exploit primitive/result:** Stack-segment/heap overlap, ROP, TLS destructor, or stdout FSOP
> **Search terms:** `-fsplit-stack`; `stack_segment`; `alloca`; recursion; `_IO_2_1_stdin_`
> **Version/protection clue:** Case target `babyallocator` — x86-64, glibc 2.23, Full RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; start at split-stack corruption, not ordinary tcache/fastbin mechanics.

### Metadata

```yaml
tags:
  - stack-exhaustion
  - heap-overlap
  - arbitrary-write
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
description: Exhausting mmap-allocated split-stack segments forces libgcc morestack to overlap dynamic stack allocations with heap buffers, enabling return address overwrite.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10404`.
- Flag: `FLAG{Spl1t_st4ck_spl1t_h34p_th3n_spl1t_7h3_sh3ll}`.
- Community provenance: 21 solutions. Write-up IDs: `59`, `363`, `550`, `821`, `1194`, `1351`, `1458`, `1980`, `2673`, `2972`, `5586`, `6748`, `8153`, `9251`, `10102`, `14523`, `26957`, `31599`, `32010`, `35917`, `37983`.

### Facts

- Stripped x86-64 GCC `-fsplit-stack` binary, glibc 2.23, Full RELRO, canary, NX, no PIE (`0x3fe000/0x400000`). Menu actions are stack `alloca` size `0x80..0xfff` with `scanf("%15s")`, heap allocation `>0xff`, write, recursive new allocator, release, and exit.
- `struct stack_segment`: `+0x00 next`, `+0x08 prev`, `+0x10 size`, `+0x18 old_stack`, `+0x20 old_stack_limit`, `+0x28 free_dynamic_allocation`.
- `struct dynamic_allocation_blocks`: `+0x00 next`, `+0x08 size`, `+0x10 block`.
- V1 (primary, exploitable): non-split-stack-aware `__isoc99_scanf` has large locals and can underflow onto the segment header at the mmap page base. Recursion and `alloca` positioning can overwrite `free_dynamic_allocation` with `_IO_2_1_stdin_`; `size`, `prev`, or `next` can also be corrupted. The allocator then interprets stdin as `dynamic_allocation_blocks`: `_flags=0xfbad208b` becomes `next`, `stdin+8` becomes `size`, and `stdin+0x10` becomes a block near `_IO_2_1_stdin_+0x84..0x90`, enabling writes to stdin and surrounding hooks/FILE data.
- V2 (alternative): adjusted alignment can target `prev` to pop to a wrong/control segment, `next` to push a fake header, or `size` to inflate usable space.
- V3 (alternative): an inflated `size` makes later `alloca` cross the segment into older recursive frames and overwrite saved RBP/RIP.
- Exact gadgets/PLT: `pop_rdi=0x40194e`, `pop_rsi=0x4016df`, `pop_rdx_rax=0x4026c5` (`pop rdx; pop rax; add rsp,8; pop rbp; ret`), `pop_rsp_r13=0x401ee1`, `mprotect=0x400e98`, `read=0x400e48`, `puts=0x400e10`, `write=0x400e18`, `GOT_puts=0x603f40`.
- Remote libc offsets: one-gadgets `[0x45216, 0x4526a, 0xef6c4, 0xf0567]`, `system=0x45390`, `__malloc_hook=0x3c3b10`, `__free_hook=0x3c57a8`, `_IO_2_1_stdin_=0x3c38e0`, `_IO_2_1_stdout_=0x3c4620`.

### Exploit Paths

- Path A (`free_dynamic_allocation -> stdin -> __malloc_hook`/FSOP; `exp.py` plus `1351`, `1980`, `8153`, `31599`, `32010`, `35917`, `37983`): recurse deeply, position `scanf` corruption, make `__morestack_allocate_stack_space` return `stdin+0x90` or a similar offset, craft stdout `_IO_write_base` to leak libc, then either overwrite the stdin vtable so `scanf` dispatch reaches a one-gadget or overwrite `__malloc_hook`. Two-stage hook variants first use a puts gadget for leak then a one-gadget. Deterministic after calibration; local and remote depth/size offsets differ by a small constant.
- Path B (most common; solutions `59`, `363`, `550`, `821`, `1194`, `1458`, `1980`, `2673`, `5586`, `6748`, `9251`, `10102`, `14523`, `26957`): create adjacent or arranged segments, optionally with mmap/heap gaps, corrupt `size`/`prev`, return through releases, overlap an older frame, and ROP. Leak with `puts(GOT)`/`write`, then finish with BSS read + `system`, `mprotect` + shellcode, or one-gadget.
  - Variant `821`: create stacks A-D, use mmap'd heap to make a gap, free it, allocate higher segments into the gap, corrupt the lower segment size, and overflow downward.
  - Variant `14523`: overwrite A's `prev` to a fake header between A and B; partially overwrite the fake `prev` to D with 1/16 brute force, skipping segments to reach C.
  - Other documented forms include fake heap-alloca buffers/ret2csu (`1194`), a fake stack address at `[rbx+0x28]` (`2673`), and overwrite of header `+0x00` with a low address (`26957`). Most are deterministic; `14523` is 1/16.
- Path C (solution `9251`): position a segment next to TLS; corrupt `fs:[-0x108]`, the `__call_tls_dtors` list, with controlled data; corrupt pointer guard `fs:[0x30]` as `value ^ read_gadget`; trigger exit and use the demangled read gadget to input ROP. Reliability about 15/16, dependent on libc nibble constraints.
- Path D (solution `8153`): spray `0xff` allocations of `malloc(0x20000)` filled with a target gadget, use the stdin-derived write to place a puts gadget then one-gadget in `__malloc_hook`, and trigger `malloc(GOT_entry)` for leak followed by shell. About 1/32 due to spray/page placement.

### Assets and Provenance

- Historical `exp.py`: Path A stdin/stdout FILE and vtable exploit.
- `desc.txt`: challenge description.
- `artifacts/babyallocator`: stripped x86-64 `-fsplit-stack` binary.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- `solution/*.md`: 21 community write-ups.
- Path notes: `59`=B/lucky alignment later explained; `363`=B/mprotect; `550`=A/B core mechanism; `821`=B/memory gap; `1194`=B/fake buffer + ret2csu; `1351`=B/mprotect; `1458`=A/two-stage hook; `1980`=B/header mechanism; `2673`=B/fake stack address; `2972`=B/trial-and-error; `5586`=B/fills/releases; `6748`=B/mass recursion; `8153`=D/spray; `9251`=C/TLS; `10102`=B/fake prev 1/16; `14523`=B/adjacent mmap stacks and eight failed approaches; `26957`=B/header low-address overwrite; `31599`=A/hook two-stage; `32010`=A/stdout vtable `[rax+0x38]`; `35917`=A/stdin+0x90 and realloc alignment; `37983`=B/local-only mmap ordering and IDA script.

## caov
> **Canonical route:** C++ copy-assignment lifetime bug → UAF/double-free, BSS House of Spirit/fastbin, and FSOP
> **Read this case when:** A C++ `Data::operator=` returns by value and a temporary destructor frees live state.
> **Primary defect:** C++ copy-assignment lifetime bug
> **Exploit primitive/result:** UAF/double-free, BSS House of Spirit/fastbin, and FSOP
> **Search terms:** CAOV; `operator=`; copy assignment; temporary destructor; `Data::key`; double free
> **Version/protection clue:** Case target `caov` — x86-64, glibc 2.23, Full RELRO, NX, no canary/PIE, source provided
> **Variant boundary:** Standalone; the C++ lifetime bug creates the allocator primitive.

### Metadata

```yaml
tags:
  - use-after-free
  - type-confusion
  - fastbin-dup
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: Reusing dangling object pointers across C++ key-value edit routines causes heap type confusion, enabling fastbin corruption to overwrite the fake vtable.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10306`.
- Flag: `FLAG{CAOV_stands_f0r_C0py_Ass1gnment_Operat0r_Vuln3rabil1ty_r3memb3r_alway5_r3turn_r3ference_typ3}`.
- Source provided: `caov.cpp`.
- Community provenance: 52 solutions. Write-up IDs: `81`, `194`, `331`, `375`, `821`, `1220`, `1316`, `1351`, `1763`, `3480`, `3851`, `5586`, `6748`, `8153`, `11954`, `13019`, `32305`, `34817`, `36134`.

### Facts

- C++ key-value database, g++/glibc 2.23, Full RELRO, no canary, NX, no PIE. A global `Data *D` manages one heap object; name is a 160-byte BSS buffer; keys can be edited up to ten times.
- `Data` layout: `+0x00 key`, `+0x08 value`, `+0x10 change_count`, `+0x18 year`, `+0x1c month`, `+0x20 day`, `+0x24 hour`, `+0x28 minute`, `+0x2c second`. Object usable size is `0x40`.
- BSS: `D=0x6032A0`, `name=0x6032C0`, `stderr pointer=0x603280`, `stdout pointer=0x603288`. The `0x7f` at `0x60328d` forms a fake `0x70` fastbin size.
- V1 (primary): `Data::operator=` returns by value. The returned temporary's destructor frees the newly allocated key that also becomes `old.key`; `edit()` therefore leaves `old.key` dangling and `old`'s destructor double-frees it. Every `edit()` produces the double-free pattern.
- V2 (primary): `set_name()`'s 150-byte `[rbp-0xb0]` buffer overlaps `edit()`'s `Data old`. Stale bytes at `tmp+0x60` / `name+0x60` become the initial `old.key` at `[rbp-0x50]`, so `~Data` performs arbitrary `delete[]` on an attacker-chosen address.
- V3 (enabler): `edit_data` reallocates only when `new_len > old_len`; shrinking or equal-length edits reuse the old key and write `new_len+1` bytes, preserving a chosen key pointer after fake-chunk placement.
- Libc offsets: `_IO_2_1_stderr_=0x3c4540`, `_IO_2_1_stdout_=0x3c4620`, `__malloc_hook=0x3c3b10`, `__free_hook=0x3c57a8`, `system=0x45390`, `stdin_fileno=0x3c38e0`, one-gadgets `[0x45216, 0x4526a, 0xef6c4, 0xf0567]`. BSS fake-size address is `0x603285`.

### Exploit Paths

- All paths combine V1 and V2 to obtain arbitrary free, then choose a corruption/finish route.
- Path A (source `exp.py`; solutions `81`, `194`, `331`, `1316`, `1351`, `3480`, `3851`, `5586`, `6748`, `8153`, `32305`, `34817`, `36134`): place a fake chunk at `name+0x10=0x6032d0`, put its address at `name+0x60`, free it, poison its writable fd to `0x603285`, allocate twice so user data at `0x603295` overlaps `D=0x6032a0`, point `D` at `name`, read through `D->key` for libc, repeat against `__malloc_hook-0x23`, and write a one-gadget. Deterministic.
- Path B (solutions `821`, `1220`, `13019`): use a BSS free to leak a heap fd, arbitrary-free the real Data object, allocate a same-size key over it, control `D` fields, gain arbitrary read through `show` and write through `edit`, then hit `__malloc_hook`.
- Path C (solutions `375`, `3851`): forge a `0xc1` or larger BSS chunk with valid next headers, arbitrary-free it to unsorted bin, read `fd`/`bk` from `name` for libc, then fastbin-poison `__malloc_hook`.
- Path D (solutions `331`, `1316`, `11954`, `exp.py`): after libc leak, corrupt stdout or stderr to a heap fake vtable, populate the called slot with `system`, put `/bin/sh` in FILE flags/name, and trigger `cout` I/O.
- Path E (solution `821`): after libc, read `__environ` through `D->key`, compute the return slot, write a one-gadget/ROP there, and exit so `main` returns.
- Primitive reliability: arbitrary free, BSS fastbin poison, `D` control, arbitrary read/write, hook overwrite, and hook/FSOP execution are all deterministic once the source sequence is complete.

### Assets and Provenance

- `artifacts/caov.cpp`: author-provided source.
- `artifacts/caov`: x86-64 Full RELRO no-PIE binary.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- Historical `exp.py`: working exploit.
- Path-to-write-up notes: `81`=A/time-field leak; `194`=B/Data free/GOT; `331`=A+D/stdout; `375`=A/stderr and repeated fastbin; `821`=A+E/environ return; `1220`=B/Data overlap; `1316`=A+D/stderr `system`; `1351`=A/read GOT; `1763`=A/`malloc_hook+0x48`; `3480`=A/0x40 fake chunks; `3851`=A+C/multiple rounds; `5586`=A/compact; `6748`=A/exit GOT; `8153`=A/stderr; `11954`=A+D/FSOP fallback; `13019`=B+E/heap+stack; `32305`=A/layout; `34817`=B+C/heap-heavy; `36134`=A/well documented.

## criticalheap
> **Canonical route:** Environment-controlled heap read plus FORTIFY-safe format read → Heap flag leak; optional `realpath(path,path)` overflow for shell
> **Read this case when:** `TZ` causes `localtime` to read the flag into heap and output passes through FORTIFY-safe formatting.
> **Primary defect:** Environment-controlled heap read plus FORTIFY-safe format read
> **Exploit primitive/result:** Heap flag leak; optional `realpath(path,path)` overflow for shell
> **Search terms:** TZ; localtime; `__printf_chk`; heap flag leak; realpath; decoy flag
> **Version/protection clue:** Case target `criticalheap` — x86-64, glibc 2.23, Full RELRO, canary/NX, no PIE, FORTIFY
> **Variant boundary:** Predecessor of Critical Heap++; this case may accept the decoy flag.

### Metadata

```yaml
tags:
  - type-confusion
  - arbitrary-write
  - shellcode
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: Type confusion between system and normal heap objects permits modifying structure pointers, granting arbitrary write into an RWX page to execute shellcode.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10500`.
- Decoy file flag: `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}`; source labels it as read directly and not the real-shell flag, but explicitly states the platform accepts it for this 200-point challenge.
- Real shell flag: `FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}`.
- Community provenance: 36 solutions. Write-up IDs: `59`, `194`, `278`, `550`, `821`, `1162`, `1351`, `2315`, `2797`, `3480`, `3851`, `4082`, `7905`, `8153`, `8410`, `8942`, `11540`, `18331`, `21490`, `24887`, `29544`, `31599`, `34817`, `36997`.

### Facts

- Heap manager, glibc 2.23, Full RELRO, canary, NX, no PIE, FORTIFY. Ten `0x48`-byte slots begin at `0x604040`; menu is Create/Show/Rename/Play/Delete/Exit.
- Types and magics: Normal `1`/`0x13371337`; Clock `2`/`0xdeadbeef`; System `3`/`0x48694869`. Normal content is `0x28` bytes with `is_changed` at slot+`0x40`. System has `dirname` at +`0x18` and `detail` at +`0x20`.
- V1 (arbitrary read): `__printf_chk(1, user_content)` is a format-string bug. FORTIFY blocks `%n` and positional `%N$`, but `%c`, `%p`, `%s`, `%x` work. `%c*11 + %s + p64(target)` reaches the address as approximately argument 12/13.
- V2 (leak): `read(0, content, 0x28)` does not append NUL; `Show` uses `printf("%s", content)`, so full content leaks adjacent stale data, often a System heap `getenv()` pointer at +`0x20`.
- V3 (UAF/type confusion): Delete only clears `in_use`; it neither frees `name`, zeroes content, nor resets type. Recreating the slot exposes stale type-specific data.
- V4 (file-read secret): Clock creation calls `localtime() -> tzset_internal() -> __tzfile_read()`. Setting `TZ` to a path (for example `/home/critical_heap++/flag`), or combinations such as `TZDIR=/home/critical_heap++` with `TZ=flag`/`:./flag`, makes glibc open/read that file into heap data.
- V5 (shell-only overflow): System `realpath(buf, buf)` with `PWD="."` after `unsetenv("PWD")` expands a tiny cwd buffer to an absolute path and overwrites adjacent chunk metadata, enabling fastbin corruption.
- Exact addresses/libc: `heap_array=0x604040`; `puts_got=0x603f40`; `system=0x45390` or `0x46390` by build; one-gadgets `[0x45216, 0xef6c4, 0xf0567]`; `__malloc_hook=0x3c3b10`; `__free_hook=0x3c57a8`. The flag-in-heap offset varies from `0x320` through `0x5e0` with environment count.
- Decoy trap: `/home/critical_heap++/flag` contains the localtime-themed decoy. The 200-point service accepts it; criticalheap++ shares the binary and instead needs shell plus setuid `get_flag` and passphrase `"Crazy heap !!"`.

### Exploit Paths

- Path A (~90%; TZ read + format string): leak heap via V2+V3 by recreating a Normal slot over System residue, with heap-base deltas observed at `0x30`, `0x50`, `0x62`, `0x142`, or `0x145`; set `TZ`/`TZDIR`; create Clock to read the file; use `%c*11 + %s + p64(heap_base + flag_offset)` to print it. Some exploits scan offsets in `0x10` or `8` steps because environment count shifts layout. This yields the decoy accepted for criticalheap.
- Path B (shell path; `1162` detailed, `7905` partial): leak libc from `puts@GOT`, leak heap, create a freed `0x70` fastbin chunk by changing `TZ` from a `0x40` filler after an initial `/etc/localtime` allocation, trigger `realpath` overlap, poison the overlapping chunk fd to `__malloc_hook-0x23`, allocate twice, write a one-gadget, and trigger `strdup`/Create. Layout is environment-sensitive; `1162` dynamically calculates offsets. Shell command: `cd /home/critical_heap++ && echo 'Crazy heap !!' | ./get_flag`.
- Path C (solution `34817`): leak a stack pointer from a long un-NUL'd name, let `__tzfile_read` place flag data on its stack frame, calculate `flag_stack_addr = leaked_stack - known_offset`, and format-string-read it. The source labels this fragile because the leak-to-flag offset differs across environments.
- Primitive reliability: heap leak, arbitrary format read, TZ file-to-heap, GOT libc leak, and `realpath` overflow with `PWD="."` are deterministic; resulting arbitrary write via fastbin is environment-dependent.

### Assets and Provenance

- Historical `exp.py`: Path A exploit.
- `desc.txt`: challenge description.
- `artifacts/critical_heap.tar.gz`: binary plus Docker environment.
- `solution/*.md`: 36 community write-ups.
- Path notes: `59`, `194`, `278`, `550`, `821`, `1351`, `2315`, `2797`, `3480`, `3851`, `8410`, `8942`, `11540`, `18331`, `21490`, `24887`, `29544`, `31599`, `34817`, `36997`=A, with source-specific details including TZDIR, `/proc/self/cwd/flag`, Chinese analyses, screenshots, offset retries, `%p` leak forms, and stack variant C. `1162`=B/full shell and `_IO_list_all`; `7905`=B partial/decoy analysis; `4082`=A Chinese analysis.

## criticalheap_pp
> **Canonical route:** `realpath` off-heap overflow → Controlled free/UAF, fastbin poison, unsafe unlink, overlapping chunks, or stdout FSOP
> **Read this case when:** The real flag requires a shell and `PWD=.` makes `realpath(path,path)` overflow a small chunk.
> **Primary defect:** `realpath` off-heap overflow
> **Exploit primitive/result:** Controlled free/UAF, fastbin poison, unsafe unlink, overlapping chunks, or stdout FSOP
> **Search terms:** realpath; `PWD=.`; setenv/realloc; `__malloc_hook`; unsafe unlink; real flag
> **Version/protection clue:** Case target `criticalheap_pp` — x86-64, glibc 2.23, Full RELRO, canary/NX, no PIE
> **Variant boundary:** Successor of `criticalheap`; target shell, not the heap flag leak alone.

### Metadata

```yaml
tags:
  - type-confusion
  - use-after-free
  - arbitrary-write
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: Polymorphic C++ object destruction without virtual destructors leads to dangling pointer reuse and type confusion, achieving arbitrary memory write.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10500`.
- Flag: `FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}`.
- Decoy: `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}` can be read via localtime/TZ without shell; real flag requires shell and setuid `get_flag`.
- Community provenance: 24 solutions. Write-up IDs: `11`, `59`, `278`, `370`, `550`, `560`, `678`, `755`, `821`, `1351`, `1912`, `1980`, `2972`, `3851`, `7905`, `8153`, `34817`, `38838`.

### Facts

- Same 10500 service family and binary class as [criticalheap](#criticalheap): ten `0x48` slots at `0x604040`, Normal/Clock/System magics and capabilities, glibc 2.23, Full RELRO, canary, NX, no PIE. No explicit application `free()` exists; frees are induced through `setenv/realloc`, `localtime/tzset`, and `realpath`.
- Delta from criticalheap: the real 600-point objective is shell, and the source foregrounds the primary exploitable `realpath` primitive rather than the accepted TZ decoy path.
- V1 (primary): `realpath(path, path)` on a tiny System cwd chunk. Set `PWD="."` by `unsetenv` then `setenv`; `get_current_dir_name()` returns `strdup(".")`; resolving to an absolute path writes `"me"` from `/home/critical_heap++/home` over the next chunk size, producing `0x656d`. A source PoC pairs the tiny chunk with `malloc(1)` / size `0x21`.
- V2 (read): `__printf_chk(1, Normal content)` accepts sequential `%c`, `%p`, `%s`; `%n` and `%N$` are blocked. `%c*11 + %s + p64(target)` leaks libc/GOT, heap residue, or libc `environ`.
- V3 (controlled free): changing `TZ`, then Clock update, makes `tzset()` free the old TZ `strdup`; `setenv("TZ", "A"*0x60)` followed by `":"` creates/frees a `0x70` chunk.
- V4 (controlled alloc/free): `setenv` reallocs glibc's environ array, yielding old/new unsorted-bin chunks for layout.
- V5 (minor leak): `Show` uses `printf("%s", name)`; un-NUL'd `strdup` boundaries can leak adjacent metadata including freed-chunk libc pointers.
- Exact offsets: `__malloc_hook=0x3c3b10`, `__free_hook=0x3c57a8`, `_IO_list_all=0x3c4520`, `system=0x45390`, one-gadgets `[0x45216, 0x4526a, 0xef6c4, 0xf0567]`, fake fast address `__malloc_hook-0x23` (user data at `-0x13`), heap slots `0x604040`.
- Post-shell files: `.You_found_the_fl4g` is mode `400`, owner/group `1001`; `get_flag` is mode `-r-sr-xr-x`, owner/group `1001`, size `9232`. Shell is uid 1000. Run `cd /home/critical_heap++ && ./get_flag`, enter `"Crazy heap !!"`.

### Exploit Paths

- Path A (most common; `exp.py` plus `11`, `59`, `370`, `678`, `755`, `1351`, `1912`, `1980`, `2972`, `3851`, `7905`, `34817`, `38838`): leak libc via V2/V5; create/free the `0x70` TZ chunk; trigger V1 to set adjacent size `0x656d`; carve overlapping chunks; poison the `0x70` fd to `__malloc_hook-0x23`; allocate twice; rename-write `\0*3 + p64(one_gadget)`; trigger `strdup`. Deterministic after layout.
- Path B (solutions `278`, `550`, `755`): overlap an environ realloc buffer, forge metadata passing `FD->bk == P && BK->fd == P` with `fd=0x604088-0x18`, `bk=0x604088-0x10`, and force unsafe unlink via `setenv`. Overwrite BSS slot names, forge `_IO_FILE_plus` with `__xsputn=system` and `/bin/sh` flags, point `stdout` at it, and trigger `printf`.
- Path C (solutions `550`, `755`, `821`): overlap chunks; corrupt a free chunk's `bk` to a BSS fake-size address; allocate there; overwrite slot names; point one at saved RBP and rename-write a pivot/ROP (`pop rdi`, `/bin/sh`, `system`); return into it.
- Path D (`exp.py`, `38838`): gain arbitrary BSS-slot write, forge `_IO_FILE_plus` with `/bin/sh\0` flags, valid `_IO_write_base < _IO_write_ptr`, and fake vtable `__overflow=system`; overwrite `_IO_list_all`; trigger malloc abort so `_IO_flush_all_lockp` dispatches.
- Primitive reliability: `0x656d` overflow, format read, TZ-controlled `0x70` free, environ realloc control, libc leak, and post-layout hook/FSOP execution are deterministic.
- Source catalog also records solution `560` as A using `tsearch` tree corruption and BSS links; `755` includes tree repair; `1980` uses `gets` gadget/stdout overwrite; `34817` uses `PWD=../critical_heap++`; `8153` has only a one-line realpath note.

### Assets and Provenance

- Historical `exp.py`: `_IO_list_all` FSOP exploit.
- `desc.txt`: challenge description.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- `solution/*.md`: 24 community write-ups.
- Path notes: `11`=A/Ruby; `59`=A/clean Python2; `278`=B; `370`=A/both flags; `550`=C/eight-step; `560`=A/tsearch; `678`=A/compact; `755`=B+C/tree repair; `821`=A/environ realloc; `1351`=A/methodical; `1912`=A/localtime fastbin; `1980`=A/env manipulation and FSOP; `2972`=A/clean Python3; `3851`=A/verbose layout; `7905`=A/Chinese decoy analysis; `8153`=`—`/one-line note; `34817`=A/relative PWD; `38838`=D.

## digimon
> **Canonical route:** Missing NUL followed by tokenizer overwrite → Unbounded task-queue writes, Partner overlap, vtable/UAF, and race-sensitive hooks or thread-stack ROP
> **Read this case when:** A game partner/task parser misses NUL termination and `strtok` overwrites an adjacent argument.
> **Primary defect:** Missing NUL followed by tokenizer overwrite
> **Exploit primitive/result:** Unbounded task-queue writes, Partner overlap, vtable/UAF, and race-sensitive hooks or thread-stack ROP
> **Search terms:** Digimon; Toolmon; Partner struct; task queue; missing NUL; race
> **Version/protection clue:** Case target `digimon` — x86-64, glibc 2.23, Partial RELRO, canary/NX/PIE
> **Variant boundary:** Standalone; treat unreliable race/item paths as documented alternatives, not the primary deterministic route.

### Metadata

```yaml
tags:
  - use-after-free
  - race-condition
  - vtable-hijack
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: A race condition between concurrent battle threads creates a use-after-free on Digimon objects, allowing virtual method table pointer overwrite.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10501`.
- Flag: `FLAG{You_have_conquered_the_world_of_digimon!}`.
- Community provenance: 11 solutions. Write-up IDs: `370`, `821`, `2311`, `3148`, `3498`, `7905`, `8153`, `9251`, `15989`, `31599`, `34817`.

### Facts

- Multithreaded 20x20 game, glibc 2.23, PIE, Partial RELRO, NX, canary. Supports map encounters, battle/recruit, roster, pthread tasks, shop, and hidden Toolmon; commands parse through `strtok`.
- V1 (primary): `read_line(buf, 0x68)` does not NUL-terminate a full buffer. For `task`, the second `strtok` parses partner index 32 while the third walks past the buffer and NUL-overwrites `arg1`'s low byte, converting it to 0. Trigger `'task 32'.ljust(0x66, '_') + ' 3n   '` (0x6c bytes) passes the busy check on 32 but calls `add_task(0, type)`.
- `enqueue_task` has no `task_count` bound, so repeated commands append task values `\x01`, `\x02`, or `\x03` past `Partner[0].task_queue[4]` into the adjacent Partner struct, eventually reaching its nickname pointer.
- V2 (leak): Toolmon `scanf("%u", ...)`, `scanf("%u", &amount)`, and `scanf("%u %u", &x, &y)` leave variables uninitialized on `+`/`-` failures and print them. Two 32-bit leaks recover PIE; when Toolmon is shop-adjacent, `"+ +"` leaks the canary as low/high words.
- V3 (minor/situational): `use_item` validates `item_id >= ITEM_COUNT`, but an error path prints `g_item_names[item_idx]` without complete validation. OOB read can reach mapped BSS/GOT with about `1/0x2000` reliability.
- V4 (enabler): `read_line` never appends `\0`; this is the root enabler for V1.
- V5 (explicit negative): `sprintf(line_buf[24], "%.2lf / %.2lf", hp, max_hp)` can overflow with large trained stats, but output consists only of floating-point digits and cannot control past the canary. Not exploitable.
- V6 (explicit negative): concurrent training and Philosopher's Stone can double-evolve `stage > 3`, causing an image-pointer OOB read that crashes. Not exploitable.
- V7 (explicit negative): killing Toolmon compacts partners with `memmove` but leaves `g_active_partner_index` stale; resulting OOB is not useful.
- V8 (exploitable but impractical): corrupted large `task_count` makes a thread repeat `strncat(notification_buf[1024], line_buf, 0x100)`, overflowing the worker stack, but requires canary leak and potentially hours.
- Partner layout (`0xa0`): inline `name[24]` at `+0`; species/stage/charge at `+0x18..+0x1b`; speed/luck at `+0x20/+0x24`; doubles max HP, HP, attack, potential at `+0x28..+0x40`; notification at `+0x50`; nickname at `+0x58`; pending money at `+0x60`; busy at `+0x64`; mutex at `+0x68`; task thread at `+0x90`; count at `+0x98`; queue at `+0x9c`.
- Libc offsets: `environ=0x3c5f38`, `system=0x45390`, `__free_hook=0x3c57a8`, `__malloc_hook=0x3c3b10`, `/bin/sh=0x18c177`, `pop rdi=0x21102`, one-gadgets `[0x4526a, 0xef6c4, 0xf0567]`.

### Exploit Paths

- All known solutions use V1; paths differ in leak and finish. Prerequisites for A/B are 33 partners (index 32 is ASCII space) and a Naming Document for `nick`.
- Path A (solutions `370/exp.py`, `821`, `2311`, `3148`, `3498`, `7905`, `8153`, `15989`, `31599`, `34817`): grind, repeatedly send the V1 task payload, write task bytes through Partner 1's name while reading leaked heap bytes, corrupt `nickname+0x58` low byte, align it into another Partner struct (~50% success), convert overlap into arbitrary read/write. Leak heap from name; leak libc through pthread/mmap data, GOT with known PIE, or freed notification fd/main arena; optionally read `__environ`. Finish with `__free_hook=system` and free a `/bin/sh` nickname (kill Toolmon frees nickname then object), `__malloc_hook=one_gadget`, or main-thread `nick()` stack ROP.
- Path B (`370` second script, `2311`, `9251`): add V2 leaks; recover PIE from two `+` responses and optionally canary from `"+ +"`; with PIE, point fake nickname directly at GOT for libc; finish as Path A with `__free_hook=system`.
- Path C (`2311`, noted primary in that source): corrupt task count; raise potential with many Potential Arousers so ~133-character task strings accumulate through `strncat`; leak canary via V2; place ROP in nickname; repair the canary NUL by shortening; wait roughly one hour / ~3500 seconds. Explicitly impractical.
- Path D (`2311` alternative, `15989` commented code): use V3 `item <large_index>` for code/heap leak with ~`1/0x2000` mapped-memory success, then shorten Path A's egg hunt. Very unreliable.
- Primitive reliability: deterministic overflow; ~50% nickname alignment; deterministic Toolmon PIE/canary leak once acquired; arbitrary read/write and execution deterministic after alignment.

### Assets and Provenance

- `digimon.c`: logic-equivalent reconstructed C source from Ghidra.
- Historical `exp.py`: working exploit.
- `desc.txt`: challenge description.
- `artifacts/digimon.tar.gz`: original challenge binary.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- `solution/*.md`: 11 community write-ups.
- Path notes: `370`=A+B/two scripts; `821`=A+B/mass automation; `2311`=A plus C/most detailed; `3148`=A+B/free hook; `3498`=A/spray and brute N; `7905`=A/nickname layout; `8153`=A+B/scanf; `9251`=A+B/image cache/pthread and thread BOF; `15989`=A/heap scan; `31599`=A+B/tracking; `34817`=A/one-gadget.

## ghost_party
> **Canonical route:** Missing C++ copy constructor → Temporary-destructor double-free, fastbin dup, fake vtable, or stdout FSOP
> **Read this case when:** C++ `Vampire` lacks a copy constructor and pass-by-value shallow-copies `blood`.
> **Primary defect:** Missing C++ copy constructor
> **Exploit primitive/result:** Temporary-destructor double-free, fastbin dup, fake vtable, or stdout FSOP
> **Search terms:** Vampire; Alan; Devil; copy constructor; shallow copy; `blood`; double free; vtable
> **Version/protection clue:** Case target `ghost_party` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE, source provided
> **Variant boundary:** Standalone; compare Alan/Devil class behavior before selecting the fastbin path.

### Metadata

```yaml
tags:
  - type-confusion
  - use-after-free
  - vtable-hijack
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
description: Reallocating mismatched C++ derived class objects into freed slots leads to type confusion, enabling vtable redirection to system.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10401`.
- Flag: `FLAG{D0n7_f0g07_7H3_c0pY_c0Ns7Ruc70R}`.
- Source provided: `ghostparty.cpp`.
- Community provenance: 51 solutions. Write-up IDs: `59`, `185`, `278`, `331`, `568`, `786`, `821`, `1172`, `1351`, `1912`, `2972`, `6247`, `8153`, `9251`, `24887`, `31599`, `32858`, `34817`, `38838`.

### Facts

- C++ polymorphic `vector<Ghost*>` manager with ten subclasses, glibc 2.23, PIE, Full RELRO, NX, canary. Virtual methods include speak, changemsg, ghostinfo, and destructor.
- V1 (primary UAF/double-free): `Vampire` has raw `char *blood` and no user copy constructor, so pass-by-value in `speaking(*ghost)` shallow-copies `blood`; the temporary destructor `delete[] blood` frees it while the original retains it. Reading `Blood:` leaks heap/libc; later original destruction double-frees.
- V2 (UAF read): `Alan::addlightsaber(string str)` stores `str.c_str()` from a temporary; the string dies on return, leaving `lightsaber` dangling. `~Alan` does not delete, so no double free, but `Lightsaber:` leaks reclaimed heap/libc data.
- V3 (explicit negative/control contrast): Devil, Zombie, and Werewolf define deep-copy constructors and are not vulnerable. The source shows Devil allocating/copying `power`.
- Base Ghost layout: vtable `+0`, age `+8`, `char *name` `+0x10`, `std::string type` `+0x18`, `std::string msg` `+0x38`, total about `0x68`.
- Vampire and Alan objects use about `0x70` chunk / `0x60` usable; vulnerable pointer at `+0x58` (`blood` or `lightsaber`). Werewolf stores int `trans` at `+0x58`.
- Libc offsets: `main_arena+88=0x3c3b78`, `__malloc_hook=0x3c3b10`, `__free_hook=0x3c57a8`, `system=0x45390`, `__libc_start_main=0x20740`, `stdout=0x3c4620`, `_IO_list_all=0x3c5520`, one-gadgets `[0x45216, 0x4526a, 0xef6c4, 0xf0567]`. PIE-relative: Werewolf vtable `0x210b98`, ghostlist `0x211030`, `GOT[__libc_start_main]=0x210e90`.

### Exploit Paths

- Path A (solutions `185`, `821`, `1912`, `2972`, `34817`, and many others): free large Vampire blood through option 3 and read unsorted fd/bk for libc; create a `0x60` blood/`0x70` chunk Vampire, free by option 3, then `rmghost` for explicit double-free; poison fd to `__malloc_hook-0x23`; allocate through the corrupted fastbin and write a one-gadget at +`0x13`; trigger malloc. Deterministic; Full RELRO makes hooks standard on glibc 2.23.
- Path B (solutions `59`, `568`, `786`, `6247`, `9251`, `31599`, `32858`): Vampire blood UAF overlaps a same-size Werewolf to leak its vtable/PIE; `rmghost(Vampire)` then frees the Werewolf while `ghostlist[0]` dangles; allocate a Mummy/Kasa/Dullahan string over it to forge `name`; arbitrary-read `GOT[__libc_start_main]` and ghostlist for libc/heap; build a fake Ghost/vtable with `ghostinfo` slot at vtable+`0x10` set to one-gadget and call `showinfo(0)`. Deterministic after leaks and does not require fastbin manipulation.
- Path C (solutions `331`, `821`, `1351`, `6247`): use Alan's dangling lightsaber for libc, often via libc internal reuse or a second large string/unsorted placement; perform Vampire double-free/fastbin poisoning and `__malloc_hook` overwrite.
- Path D (solutions `278`, `331`, `1351`, `38838`): after libc/heap, fastbin-poison near the `0x7f` byte around `_IO_list_all` or stdout, overwrite stdout vtable to heap fake vtable with `__overflow` or `xsputn` set to `system`/one-gadget, and trigger `cout`. More fragile due FILE crafting.
- Path E (solutions `59`, `32858`): use Devil's raw `power` for UAF overlap. Devil has a proper copy constructor, but by-value `speaking` and removal still enable layout manipulation. Similar to B.
- Primitive reliability: Vampire dangling read/double-free and Alan dangling read deterministic; libc, PIE, heap leaks, arbitrary read, hook overwrite, and fake vtable execution deterministic after their setup. FILE route is more fragile.

### Assets and Provenance

- `artifacts/ghostparty.cpp`: author-provided source.
- `artifacts/ghostparty`: PIE Full RELRO x86-64 binary.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- Historical `exp.py`: Path B fake-Ghost vtable exploit.
- `desc.txt`: challenge description.
- `solution/*.md`: 51 community write-ups.
- Path notes: `59`=B; `185`=A; `278`=D/Ruby stdout; `331`=D/Alan+Vampire; `568`=B/Alan leak; `786`=B; `821`=A+C; `1172`=B/Mummy; `1351`=D; `1912`=A; `2972`=A; `6247`=A+C; `8153`=A/realloc variant; `9251`=B; `24887`=B+E/C++ bindings; `31599`=B/Kasa; `32858`=B+E/spray; `34817`=A/minimal; `38838`=D.

## hacknote
> **Canonical route:** Global note pointer UAF/double-free → Fake note/function pointer and content, GOT leak, then `system(";sh")`
> **Read this case when:** A note delete action leaves the global note pointer live.
> **Primary defect:** Global note pointer UAF/double-free
> **Exploit primitive/result:** Fake note/function pointer and content, GOT leak, then `system(";sh")`
> **Search terms:** note; print function; `print_func`; UAF; fastbin; `;sh`
> **Version/protection clue:** Case target `hacknote` — i386, glibc 2.23, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Standalone; do not overwrite the whole function pointer when semicolon routing suffices.

### Metadata

```yaml
tags:
  - use-after-free
  - got-overwrite
  - ret2libc
platform: pwnable.tw
points: 150
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: A use-after-free in note management allows reallocating user data into note metadata chunks, overwriting the print function pointer to call system.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10102`.
- Flag: `FLAG{...}` (dynamic).
- Community provenance: 218 solutions. Write-up IDs: `100`, `138`, `1006`, `1126`, `1155`, `1220`, `1236`, `1251`, `1269`, `1297`, `1303`, `1316`, `1351`, `1384`, `10115`, `10128`, `10453`, `11540`, `12245`, `12705`, `13060`, plus source `exp.py`.

### Facts

- Classic i386 note manager, glibc 2.23, Partial RELRO, canary, NX, no PIE. `notelist[5]` and a monotonic `count` manage each note as separate metadata and content allocations.
- Metadata is `malloc(8)`: `+0x00 print_func`, `+0x04 content`.
- Add allocates metadata, sets `print_func=0x0804862b` (puts content), reads size, allocates content, and `read`s exactly size. Delete frees content then metadata but does not set `notelist[idx] = NULL`. Print dereferences the dangling metadata and calls `print_func(note)`.
- V1 (primary): UAF via retained metadata pointer. Reallocation controls both called function pointer and its struct argument.
- V2: repeated Delete on the same index is a double free and can form a fastbin cycle.
- V3: count never decrements, so five total add operations remain the limit, but already-freed slots still permit UAF/double-free.
- Fixed addresses: default printer `0x0804862b`, `puts@GOT=0x0804a024`, `read@GOT=0x0804a00c`, `printf@GOT=0x0804a010`, `free@GOT=0x0804a034`.
- Remote libc offsets: `puts=0x5f140`, `system=0x3a940`, `read=0xd41c0`, `printf=0x49010`, `free=0x70750`, `main_arena=0x1b07b0`, `/bin/sh=0x158e8b`.

### Exploit Paths

- Path A (canonical, ~90%; `exp.py`, solutions `100`, `138`, `1155`, `1251`, `1269`, `1297`, `1303`, `1387`, `10453`, `11699`, `12705`, `13060`, and others): allocate/free two small notes so metadata chunks enter the `0x10` fastbin; add an 8-byte-content note so metadata takes one chunk and content reuses the other; write `p32(0x0804862b)+p32(PUTS_GOT)`; print dangling note 0 to leak `puts`; delete and reallocate with `p32(system)+";sh\0"`; print to call `system(struct)`. The first four binary bytes form a failing command and `;sh` starts shell. Source also documents `"||sh"`, `"&&sh"`, `"; cat /home/hacknote/flag;"`, and `";/bin/sh\0"`. Deterministic.
- Path B (solutions `1220`, `10115`, `10453`, `12245`, `14032`): allocate/free content >=`0x80` with a guard against top consolidation; realloc and read four bytes past controlled data to leak unsorted fd/main arena; then perform Path A.
- Path C (solutions `1006`, `1126`, `1236`, `10128`): free two medium notes and allocate one large content buffer spanning old metadata; cyclic padding (commonly 504 or 1008 bytes) places a fake print pointer/content pointer; print a dangling index. Source calls it less elegant but reliable; `1126` uniquely uses `printf` as print function and `%19$p`.
- Path D (solutions `1303`, `1316`, `1384`, `11540`): explicitly `delete(0); delete(1); delete(0)` on 8-byte notes to create `note0 -> note1 -> note0`; allocate through the cycle and continue as A. `1316` adds an extra allocation for dedup.
- Primitive reliability: UAF, double free, function-pointer hijack, GOT/unsorted leak, and `system(";sh")` execution are deterministic.

### Assets and Provenance

- Historical `exp.py`: vanilla-Python canonical exploit.
- `desc.txt`: challenge description.
- `artifacts/hacknote`: stripped i386 binary.
- `artifacts/libc_32.so.6`: remote 32-bit glibc 2.23.
- `solution/*.md`: 218 community write-ups.
- Path notes: `100`=A/Python2; `138`=A/Ruby; `1006`=C/stdout leak; `1126`=C/format leak; `1155`=A/size 20; `1220`=B+overlap; `1236`=C/heap spray; `1251`=A; `1269`=A/read GOT; `1297`=A/checksec; `1303`=D; `1316`=D/dedup; `1351`=A/heap leak; `1384`=D/cycle; `10115`=B+D; `10128`=C/best narrative; `10453`=B+A/Japanese; `11540`=D/raw `%04d`; `12245`=B/main arena+0x30; `12705`=A; `13060`=A/Python3.

## omegago
> **Canonical route:** History-array OOB into board state → Leak/arbitrary read, fake BSS sizes, House of Spirit, and vtable overwrite
> **Read this case when:** A Go-board history array overflows into a two-bit board bitmap.
> **Primary defect:** History-array OOB into board state
> **Exploit primitive/result:** Leak/arbitrary read, fake BSS sizes, House of Spirit, and vtable overwrite
> **Search terms:** OmegaGo; history; board bitmap; regret; 2-bit cell; House of Spirit; vtable
> **Version/protection clue:** Case target `omegago` — x86-64, glibc 2.23, Partial RELRO, NX, no canary/PIE
> **Variant boundary:** Standalone; board values constrain fake chunk bytes and create retry probability.

### Metadata

```yaml
tags:
  - type-confusion
  - out-of-bounds-write
  - got-overwrite
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: Coordinate encoding confusion on the Go board permits out-of-bounds array indexing, enabling arbitrary GOT overwrite to hijack program execution.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10405`.
- Flag: `FLAG{now_you_can_try_to_fight_with_AlphaGo~}`.
- Community provenance: 14 solutions. Write-up IDs: `59`, `821`, `2121`, `2311`, `2972`, `5586`, `6247`, `6748`, `8153`, `11954`, `14523`, `22319`, `26957`, `34817`.

### Facts

- Stripped dynamically linked 19x19 Go binary, glibc 2.23, Partial RELRO, NX, no canary, no PIE. Commands include coordinates, `regret`, and `surrender`.
- Board is 2 bits/cell in 12 qwords at `g_cur_state=0x609fc0`: `0` empty, `1` white/O, `2` black/X, `3` invalid/NUL leak marker. 361 cells occupy 11.28 qwords.
- History is at `g_history=0x609460`, capacity 364 snapshot pointers (182 pairs), with no index check. The C++ AI object is a `0x10` heap allocation whose first field is vtable. `scanf("%10s", g_input)` targets `g_input=0x60943c`; effective fixed vtable input address is `0x609440`.
- V1 (primary): ko cycles generate more than 182 pairs. `history[364+]` overwrites board qwords with heap pointers, which the board renderer exposes as 2-bit data for heap reconstruction. A further move shifts the latest pointer predictably, such as `+0x80`.
- V2: `regret` removes two entries, copies `g_history[new_last]` to current board, and displays it. A controlled history pointer therefore reads arbitrary mapped memory as board data.
- V3 (House of Spirit): player-controlled cells encode arbitrary non-`0b11` patterns in heap snapshots. Two encoded `0x21` headers (example stones `R8`, `D12`) and an overflow-directed surrender free create a fastbin `0x20` fake chunk; the next AI `new` reuses it.
- V4: encode vtable target `0x609440` into the AI object's vtable field. A move such as `"F8\0\0" + p64(one_gadget)` (source also shows `"D1\0\0"`) leaves the command valid while placing the function pointer at `0x609440`; next virtual call jumps through it.
- Encoding constraint: the player cannot place cell value `0b11`; heap addresses/values containing any `0b11` pair are unrepresentable and force retry. This is the principal failure source.
- Exact addresses/offsets: `g_input=0x60943c`, usable `0x609440`, `g_history=0x609460`, `g_cur_state=0x609fc0`; `main_arena+88=0x3c3b78`; one-gadgets `[0xf0567, 0xf1247, 0x4527a]`; `system=0x45390`; source leaves `setcontext+87` as an unspecified gadget offset used by variants.

### Exploit Paths

- Path A (most common; solutions `59`, `821`, `2121`, `5586`, `6247`, `6748`, `8153`, `11954`, `14523`, `22319`, `34817`): surrender 1-2 times for heap alignment, overflow ~365 entries, decode heap leak, shift with one move, `regret` a region containing `main_arena`/`_IO_wfile_jumps` for libc; restart/align; encode two `0x21` headers; free one through history-targeted surrender; allocate AI there; encode `0x609440` over vtable; append one-gadget to a coordinate. Reliability ~50-80%, retrying disallowed `0b11` layouts.
- Path B (solution `2311`): use padded `surrender`/`regret` input to write fake `0x31` headers into the predictable heap stdin buffer, free one via a history pointer, allocate the AI object there, overwrite vtable via stdin, and use `setcontext+87` for reliable `execve("/bin/sh")`; a one-gadget variant also exists.
- Path C (solution `26957`): use history/regret leaks, plant a fake `0x1a1` header in stdin, unsorted-free it, perform unsorted-bin attack on `_IO_list_all`, forge `_IO_FILE` with `system` vtable, and trigger malloc error.
- Path D (solutions `59`, `8153`): mirror-Go strategy uses predictable AI mirrors and precomputed external sequences `mirror1`, `super_mirror`, `super_mirror2` to fill/control the board without complex ko setup.
- Primitive reliability: overflow, heap leak, arbitrary-memory board read, fake chunk, vtable hijack, and post-control execution are deterministic subject to encoding/alignment; Path A explicitly retries.

### Assets and Provenance

- Historical `exp.py`: working exploit.
- `desc.txt`: challenge description.
- `flag.txt`: captured flag.
- `artifacts/omegago`: stripped x86-64 ELF.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- `solution/*.md`: 14 community write-ups.
- Path notes: `59`=A mirror/files; `821`=A helpers; `2121`=A direct fill; `2311`=B setcontext; `2972`=A bug description; `5586`=A one-gadget/setcontext; `6247`=A rows/address; `6748`=A OOP Pos; `8153`=A long mirror oracle; `11954`=A/stdin padding; `14523`=A ko encode; `22319`=A step-by-step; `26957`=C; `34817`=A/DECODE helper.

## stupid_boss
> **Canonical route:** Cross-language object-model type confusion → Arbitrary C-string read, 20-byte write, hooks, stack ROP, or FILE vtable
> **Read this case when:** `compatible()` converts between C, Python, Java, and JavaScript object models without real type safety.
> **Primary defect:** Cross-language object-model type confusion
> **Exploit primitive/result:** Arbitrary C-string read, 20-byte write, hooks, stack ROP, or FILE vtable
> **Search terms:** stupid boss; compatible; C/Python/Java/JavaScript; type confusion; destructor `memset`; hooks
> **Version/protection clue:** Case target `stupid_boss` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE, source provided
> **Variant boundary:** Standalone; preserve fake-chunk size-zero constraints through the C++ destructor.

### Metadata

```yaml
tags:
  - use-after-free
  - type-confusion
  - got-overwrite
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
description: A use-after-free vulnerability in employee class structures allows corrupting function pointers to hijack execution flow to system.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10409`.
- Flag: `FLAG{My_5+up1d_B0s5es_ar3_s0_dumb_th3y_Thlnk_J4v4_&_J4v45cripT_4r3_th3_s4m3}`.
- Source provided: `stupid.cpp`.
- Community provenance: 18 numbered solutions plus source `exp.py`. IDs: `370`, `821`, `2311`, `3148`, `375`, `564`, `7905`, `8153`, `9251`, `10128`, `1351`, `14523`, `18331`, `22319`, `31599`, `34817`, `5586`, `6748`.

### Facts

- C++11 programmer RPG, glibc 2.23, PIE, Full RELRO, NX, canary. Slime wins give language EXP; at threshold the two projects each expose editable `Language*` slots. Trojan has ASM/C/Python; Web has Ruby/Java/Javascript; Python and Javascript unlock at 500 skill.
- Every subclass is 64 bytes: vptr `+0`, enum `+8`, 32-byte `std::string name` `+0x10`, exact-printed ratio `+0x30`, version `+0x38`. `info()` is virtual; `set_version()` is nonvirtual and selected by static type in `set_lang`.
- V1 (primary): `compatible()` permits bad in-place reinterpretation without changing vptr. Web uses substring matching, so `"Java" ⊂ "Javascript"`; Trojan explicitly allows C↔Python.
  - C→Python arbitrary read: `L_Python::set_version` writes `scanf("%lf", &version)` over L_C's `char*`; unchanged L_C vptr then prints it as a C string. Address is encoded as little-endian `double`.
  - Javascript→Java→Javascript arbitrary write: Java writes a double-encoded target over `char*`; switching back invokes `read(0, version, 20)`.
- V2 (leak): `scanf("%lu", &r)` failures on `+`, `-`, or `.5` leave `r` uninitialized; `basic_info()` prints it exactly. In deep `main -> fight_slime -> boss -> make_web -> create`, this yields a precise stale stack pointer.
- V3 (oracle): `L_Javascript::set_version`'s `read(0, version, 20)` returns EFAULT without crashing on unmapped addresses and leaves input unconsumed, allowing valid/invalid address probing.
- V4 (enabler): minion RNG uses static `srand(0x44444444 + 4444*k)`; king uses `srand(time(NULL))`. Replicating glibc `rand()` (source shows `ctypes.CDLL`) predicts minion battles and automates ~15-30 fights to unlock four 500-EXP languages.
- Libc offsets: `__free_hook=0x3c57a8`, `__malloc_hook=0x3c3b10`, `system=0x45390`, one-gadgets `[0x45216, 0x4526a, 0xef6c4, 0xf0567]`, `stdin=0x3c48e0`, `environ=0x3c5f38`.

### Exploit Paths

- Path A (most common; `exp.py` plus solutions `370`, `821`, `2311`, `3148`, `7905`, `22319`, `5586`, `6748`, `18331`, and others): predict/grind, leak stack via failed ratio scan, use C↔Python reads to recover a PIE pointer (typically binary base + `0x20d048`) and libc from GOT/BSS (`read`, `scanf`, or stdin), use Java↔Javascript to write 20 bytes, set `__free_hook=system`, put `/bin/sh\0` in known writable memory, and trigger destructor free by switching Javascript to incompatible Ruby. Because `~L_Javascript` calls `memset(version, 0, malloc_usable_size(version))` before delete, fake chunk metadata sets next chunk `PREV_INUSE=0` so usable size is zero and `/bin/sh` survives. Reliability ~95%+ unless the stale stack value is unusual.
- Path B (solutions `821`, `6748`, `34817`): same leaks, but write one-gadget to `__malloc_hook`, or use `__realloc_hook` plus realloc trampoline for alignment; triggered by later new/malloc. Constraints `[rsp+X]==NULL` / `rax==NULL` often require trigger selection.
- Path C (solutions `2311`, `18331`): leak libc/stack, optionally read `__environ`, write `pop rdi; ret; /bin/sh; system` over a return address such as `manage_project`, and return.
- Path D (solution `9251`): glibc 2.23-only stdout vtable hijack; write one-gadget into `__xsputn` and trigger `cout`.
- Path E (solutions `564`, `8153`, `9251`, `1351`, and `31599`'s described experience): without V2, leak high heap bits from Python→C double precision loss, brute-force remaining bits with the V3 read oracle, scan vtables for PIE then GOT/libc. Reported rates range from 1/1500 to roughly one minute with enlarged heap/binary search and hundreds of probes.
- Primitive reliability: stack leak, arbitrary read/write, address oracle, and RNG prediction deterministic; heap brute force slow/unreliable; post-leak execution deterministic.

### Assets and Provenance

- `artifacts/stupid.cpp`: author-provided source.
- `artifacts/stupid`: stripped PIE binary.
- `artifacts/libc_64.so.6`: remote glibc 2.23.
- Historical `exp.py`: Path A exploit.
- `desc.txt`: challenge description.
- Path-to-write-up notes: `370`=A/two scripts; `821`=A+B/random server; `2311`=A+C/`"++"`; `3148`=A; `564`=E/1/1500; `7905`=A/fake chunk; `8153`=E/IEEE converter; `9251`=E+D; `34817`=E+B/binary search; `31599`=`—`/"worst possible way, 1/1500"; `375`=E/cyclic spray; `1351`=E/ASM spray; `10128`=A/binary heap search; `14523`=A/clean; `18331`=A/fallback brute; `22319`=A/no slime prediction; `5586`=A/King-only; `6748`=A+B/realloc trampoline.
