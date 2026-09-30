# Pwnable.tw Restricted Shell Cases

Instance-preserving casebook for the two pwnable.tw restricted-bash challenges. It retains deployment restrictions, exact CVE behavior, intended and unintended paths, historical flags/ports, artifacts, and solution indexes.

## How To Use This File

Use this file when bash policy, executable loader, chroot, restricted commands, controlled shell-allocator free, or leaked/reused descriptors dominate. Do not use it for an ordinary libc `system("/bin/sh")` chain.

## Case Index

| Challenge | Canonical route |
|---|---|
| [`bash`](#bash) | Executable `ld-linux` plus intended `popd` controlled free/UAF → Loader-interpreter execution, `/proc/self/mem` builtin overwrite, or controlled-free escape |
| [`bash_revenge`](#bash_revenge) | Controlled bash-allocator free → `SHELL_VAR`/function reclaim, code execution, and raw-socket flag FD |


## bash
> **Canonical route:** Executable `ld-linux` plus intended `popd` controlled free/UAF → Loader-interpreter execution, `/proc/self/mem` builtin overwrite, or controlled-free escape
> **Read this case when:** A restricted bash allows limited commands while its dynamic loader remains executable.
> **Primary defect:** Executable `ld-linux` plus intended `popd` controlled free/UAF
> **Exploit primitive/result:** Loader-interpreter execution, `/proc/self/mem` builtin overwrite, or controlled-free escape
> **Search terms:** restricted bash; `ld-linux`; `popd`; CVE-2016-9401; `/proc/self/mem`
> **Version/protection clue:** Case target `bash` — x86-64, glibc 2.23, Partial RELRO, canary/NX, no PIE
> **Variant boundary:** Predecessor of `bash_revenge`; the unintended loader route differs from Revenge’s chroot/FD route.

### Metadata

```yaml
tags:
  - logic-flaw
  - race-condition
  - command-injection
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: A race condition during temporary environment file creation in a restricted bash shell allows executing arbitrary shell commands to bypass restrictions.
proof-of-concept: no
```

- Endpoint: `nc chall.pwnable.tw 10108`.
- Flag: `FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`.
- Community provenance: 22 solutions. Write-up IDs: `14`, `821`, `1763`, `2972`, `3052`, `3498`, `3578`, `5586`, `6247`, `6748`, `7905`, `8153`, `9251`, `10128`, `12672`, `21490`, `25916`, `27939`, `28605`, `32010`, `32901`, `33090`.

### Facts

- Ubuntu 16.04 deployment runs custom interactive bash 4.3.0 as low-privilege user `bash` with `--noprofile --norc -i`. `/flag` is root-owned mode 400. A root xinetd service at `127.0.0.1:1337` runs `cat /flag` when connected.
- Restrictions: `chmod o-x` applies across `/bin/*`, `/sbin/*`, `/usr/bin/*`, and `/usr/sbin/*`; only `/bin/cat` and `/bin/ls` retain other-execute. `/tmp`, `/var/tmp`, `/dev/shm`, and `/home/bash` are read-only bind mounts.
- Three blocked routes, exactly as recorded: challenge bash lacks `--enable-net-redirections`, so `/dev/tcp` is unavailable; direct `nc`/`python`/`perl` etc. lack other-execute; loadable builtins (`enable -f evil.so builtin`) are technically supported but impossible because every writable directory is read-only.
- W1 (unintended primary): `/lib/x86_64-linux-gnu/ld-2.23.so` and symlink `/lib64/ld-linux-x86-64.so.2` remain world-executable. The kernel executes the loader, which reads an other-readable target and maps it for execution. `/usr/bin/perl` is shown as `-rwxr-xr--` (other read, no execute). Thus every readable dynamic binary—including perl, Python, system `/bin/bash`, and awk/gawk—runs through the loader.
- W2 (intended): bash 4.3.0 CVE-2016-9401 makes `popd -NNN` perform a controlled `free()` without adequate bounds checks. It enables in-process heap corruption/control flow and direct use of loaded `socket`/`connect`, requiring no disk write, external program, or `/dev/tcp`.
- W3 (variant enabler): `exec 3>/proc/self/mem` opens process memory for writing. A loader-launched `dd` can seek to the known `echo` builtin code address and write shellcode; executing `echo` then runs it.

### Exploit Paths

- Path A (~45%, simplest): invoke system `/bin/bash` through ld.so and use its enabled `/dev/tcp`:
  ```bash
  /lib64/ld-linux-x86-64.so.2 /bin/bash -c "cat < /dev/tcp/127.0.0.1/1337"
  ```
  Reliability 100%; the system shell is distinct from the challenge shell.
- Path B (~45%, most common): invoke readable perl through the loader and use `IO::Socket::INET`, raw `Socket` calls, or the `perl -de1` debugger REPL to connect to `127.0.0.1:1337`. Reliability 100%; Perl socket support needs no additional file load.
- Path C (intended): exploit CVE-2016-9401 in process, hijack bash control flow, and call already-loaded `socket`, `connect`, `read`, and `write`. It was designed to survive the read-only filesystem. Solution `3498` is the only one explicitly mentioning it (redacted); most used W1.
- Path D (creative rare, solution `33090`): open `/proc/self/mem`, run `dd` via ld.so with `seek=4601712 bs=1 count=123` to overwrite `echo` with 123 bytes of connect-back shellcode, then invoke `echo`. Reliability 100%.
- Path E: loader-run interpreters include awk/mawk/gawk using `/inet/tcp/0/127.0.0.1/1337`, Python `socket`, and Ruby `TCPSocket`. Source gives the awk `BEGIN { ... |& getline line; print line }` form.
- Loadable `.so` builtin is explicitly not feasible remotely because it requires a disk write.
- Technique matrix from source: ld.so+bash `/dev/tcp` uses W1, no disk write, external binary through loader, 100%; ld.so+perl same; CVE path uses W2/no external binary, complex deterministic; `/proc/self/mem` uses W1+W3/dd, 100%; loadable builtin is blocked.

### Assets and Provenance

- `desc.txt`: challenge description.
- Historical `exp.py`: ld.so + perl exploit.
- `artifacts/bash.tgz`: original archive containing Dockerfile, bash binary, and xinetd config.
- `solution/*.md`: 22 community write-ups.
- Path notes: `14`, `8153`, `21490`, `25916`, `32010`, `32901`=A; `821`, `1763`, `3052`, `3578`, `5586`, `6247`, `10128`, `12672`, `27939`=B; `2972`=link/reference only; `3498`=C/intended; `6748`=same as Bash Revenge/libc difference; `7905`=A+B and CVE coverage; `9251`=Bash Revenge variant; `33090`=D.

## bash_revenge
> **Canonical route:** Controlled bash-allocator free → `SHELL_VAR`/function reclaim, code execution, and raw-socket flag FD
> **Read this case when:** A chroot contains only bash/libraries and `popd +-N` can free an attacker-selected address.
> **Primary defect:** Controlled bash-allocator free
> **Exploit primitive/result:** `SHELL_VAR`/function reclaim, code execution, and raw-socket flag FD
> **Search terms:** chroot escape; `popd`; CVE-2016-9401; bash malloc; `SHELL_VAR`; raw socket
> **Version/protection clue:** Case target `bash_revenge` — x86-64, glibc 2.23, Full RELRO, canary/NX/PIE (source header conflicts and is preserved)
> **Variant boundary:** Successor of `bash`; do not rely on Bash’s executable-loader shortcut.

### Metadata

```yaml
tags:
  - logic-flaw
  - file-descriptor-leak
  - command-injection
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
description: Exploiting leaked file descriptors and internal bash builtins enables escaping restricted execution mode to execute privileged binaries.
proof-of-concept: no
```

- Prompt: “There is an old version bash with some vulnerabilities, such as CVE-2016-9401. Can you develop a 1-day exploit for this challenge? :p”
- Endpoint: `nc chall.pwnable.tw 10407`.
- Flag: `FLAG{us3_4ft3r_fr33_1n_bash_1s_p0w3rful}`.
- Community provenance: 21 solutions. Write-up IDs: `370`, `821`, `1351`, `1428`, `2311`, `2972`, `3148`, `3498`, `6748`, `7905`, `8153`, `9251`, `15989`, `22319`, `26957`, `28605`, `28652`, `31599`, `33090`, `35463`, `36714`.

### Facts

- Chroot-jailed bash 4.3.0(2) on x86-64 contains only bash and libraries—no `cat`, `ls`, `id`, or other tools. `/flag` is outside the chroot and root-owned; a separate root xinetd on `127.0.0.1:1337` runs `/bin/cat /flag`. Challenge bash lacks `/dev/tcp`, so arbitrary code execution and raw socket/connect syscalls are required.
- Source binary header states `bin/bash`: amd64, Partial RELRO with writable GOT, canary, NX, **non-PIE fixed `.text`/`.bss`/`.got`**, not stripped. This directly conflicts with YAML `pie: yes` and `relro: full`; both source forms are preserved here rather than reconciled.
- Bash uses its own allocator `lib/malloc/malloc.c`, not glibc malloc. Custom allocated chunk header `union mhead` has `mi_alloc` (`0xf7` allocated, `0x54` free), `mi_index`, `mi_magic2` must be `0x5555`, and `mi_nbytes`; a trailing u32 guard repeats size. A valid `0x30` allocation in bucket 3 has header qword `0x30555503f7`.
- `SHELL_VAR` (`0x30`): `name +0x00`, `value +0x08`, `exportstr +0x10`, `dynamic_value +0x18`, `assign_func +0x20`, attributes `+0x28`, context `+0x2c`.
- V1 (sole entry point): CVE-2016-9401 in `builtins/pushd.def`. `popd +-N` accepts negatives through `legal_number`; the check rejects only `which > offset`. `free(pushd_directory_list[i])` at line 384 then executes. If `pushd` was never called and the list is NULL, `popd +-N` is effectively `free(*(void**)(8*N))` at an attacker-chosen fixed BSS/data address.
- V2: global `localbuf[128]` at `0x6b7c40` stores raw `read()` bytes including NULs, which the command parser ignores. It can hold a forged allocator chunk at a fixed known address.
- V3: `printf` and `echo -ne` decode `\x00` into buffered stdout at a predictable heap offset, enabling binary/NUL fake chunks without localbuf.
- V4 heap leak: freeing BSS heap pointers such as `ps1_prompt`, `ps2_prompt`, `the_current_wd`, or `dollar_vars[1]` replaces string data with free-list `next`; reading `PS2`, `$1`, or `pwd` leaks it.
- V5 (alternative, revenge-only): `/proc` is accessible on port 10407; `cat /proc/$$/maps` directly reveals heap and libc bases.
- Exact offsets: bash `localbuf=0x6b7c40`, `read_got=0x6b2288`, `snprintf_got=0x6b2030`, `stdin_bss=0x6b5110`, `ps1_prompt=0x6b86d8` (solution-dependent), `the_current_wd=0x6b7ec0`, `dollar_vars=0x6b8920`. Ubuntu libc 2.23-0ubuntu10: `read=0xf7250`, `gets=0x6ed80`, `setcontext=0x47b75` (`+53` register-loading gadget), `mprotect=0x101770`, `pop rdi=0x21102`, `pop rsi=0x202e8`, `pop rdx=0x1b92`, `pop rax=0x33544`, `syscall; ret=0xbc375`.
- Inherited sibling context: unlike [bash](#bash), revenge removes usable external binaries and makes CVE-2016-9401 the required route; its larger point value reflects the 1-day exploitation requirement.

### Exploit Paths

- Universal flow: V1 arbitrary fixed-address free → plant fake chunk → reclaim it as a controlled internal structure → arbitrary read and RIP hijack → ROP/mprotect/shellcode → raw socket to `127.0.0.1:1337`. Paths differ in fake-chunk placement, reclaimed structure, and hijack.
- Path A (`localbuf` fake chunk → `SHELL_VAR`; solutions `370/exp.py`, `1428`, `2311`, `2972`, `3498`, `7905`, `8153`, `15989`, `36714`): place valid header/body/footer at localbuf +`0x30`/`+0x40`; use `popd +-(localbuf_offset/8)` to free it; allocate variables such as `A=B C=D`; overwrite `SHELL_VAR.value` with `read@got` and `echo $C` for libc; set `dynamic_value` to `gets` or `setcontext+53`; use `$VAR` to read a ucontext+ROP or pivot; ROP into `read`/`mprotect`/shellcode; shellcode performs socket/connect/read/write.
- Path B (`printf`/`echo -ne` stdout-buffer fake chunk → `SHELL_VAR`; solutions `821`, `1351`, `2311` bash variant, `9251`, `22319`, `26957`, `28605`, `28652`, `31599`, `33090`): leak heap from freed BSS, forge a chunk at approximately `heap_base+0x2808`, free it through V1, reclaim as SHELL_VAR, and apply Path A steps 4-7. Some solutions repeatedly printf-overwrite the reclaimed structure directly.
- Path C (array/JOB hijack; solutions `1351`, `22319`, `35463`, `36714`): reclaim with bash array elements `{int64 index; char *value; ...}` to trigger assignment paths such as `assign_func`/`bind_array_var_internal`, or with background JOB structures and `j_cleanup`. `jobs` can leak through command string; cleanup yields RIP control.
- Path D (hook/longjmp; solutions `2972`, `36714`): overwrite `tilde_expansion_preexpansion_hook` in BSS and trigger long tilde expansion with partially controlled RDI/RSI/RDX; alternatively read `top_level` jmp_buf at `0x6b90e0`, recover glibc `PTR_MANGLE` key, write encrypted RBP/RSP/RIP, and `exit 0` to `longjmp` into a pivot/ROP.
- Path E (solution `1428`): place chunks on bash free list, use `printf -v` allocations to control free-list next pointers, chain to write `add_ret_gadget` into GOT such as `dcgettext@got`, and use the gadget call to `gets` a full ROP chain.
- Path F (revenge-only, solution `1351`): skip heap leak with `cat /proc/$$/maps`, then follow Path B.
- Primitive reliability: fixed arbitrary free, fake chunk, heap leak, GOT libc read, optional stack leak, structure RIP hijack, setcontext execution, and socket exfil are deterministic.
- Source primitive table additionally identifies optional stack leak through `shell_environment` or `__environ`.

### Assets and Provenance

- Historical `exp.py`: localbuf fake-chunk exploit.
- `desc.txt`: challenge description.
- `artifacts/`: original tarball `bash_revenge.tgz`.
- `solution/*.md`: 21 community write-ups.
- Detailed solution table: `370`=A/current working directory, setcontext; `821`=B/`$1`, history disabled; `1351`=B+F/maps revenge and brute bash, array assign; `1428`=A/localbuf; `2311`=A+E/gets→setcontext and Bash 200 documentation; `2972`=D/nested functions; `3148`=B/PS1 and `echo -ne`; `3498`=A/xchg edi,esp; `6748`=B/array spray; `7905`=A/dollar vars and BashInterface; `8153`=A/GOT leak/Docker; `9251`=B/`$0` and JOB; `15989`=B/current host name/JOB; `22319`=C/export/coproc; `26957`=B/history object; `28605`=B/PS2 and 14-chunk spray; `28652`=B/current wd and `read -e -N 128`; `31599`=B/export/SHELL_VAR; `33090`=B/`printf -v`; `35463`=C/C_ENV/coproc; `36714`=D/encrypted jmp_buf.
