# DumperPro - Optional Kernel-Assisted Reader

This document specifies the **optional** kernel-assisted memory reading path of DumperPro:
what it is for, the exact client-visible contract, and the duties a driver implementation must
fulfill. DumperPro ships only the **client side** (`KernelReader.cpp`, a backend of
`IMemoryReader`). No driver source is included in this repository.

Use this path only on systems you own or are authorized to test, for legitimate debugging and
dumping. See the Legal and Safety section at the end.

---

## 1. Purpose and when it matters

DumperPro's default backends use ordinary user-mode process access. That is sufficient for the
majority of targets, but two classes of situations benefit from a kernel-assisted reader:

1. **Protected or restricted processes.** Some games and hardened builds restrict or strip
   user-mode handles (`OpenProcess` fails, or opens with fewer rights than needed), or hook /
   filter the usual reading paths. A kernel reader bypasses nothing illegitimate - it simply
   performs reads from kernel mode against the target process, which the operator has already
   selected - and keeps working where user-mode handle acquisition fails.
2. **Large-scan stability.** DumperPro performs hundreds of thousands of small reads
   (module snapshot, FName pool walks, object array sampling, offset probing). A single,
   consistent read path in kernel mode avoids mixed-handle flakiness and repeated
   acquire/release cycles on some configurations, making long scans more reliable.

What it is **not**: a stealth or evasion component. DumperPro documents the interface openly,
requires the operator to run a signed driver they built or installed knowingly, and performs
read-only access. Anti-cheat evasion and multiplayer misuse are out of scope and unsupported
(see `README.md` Disclaimer and section 5 below).

When **not** to use it:

- file mode (`--file`) covers offline analysis and needs no kernel component;
- whenever the default process reader works, there is no benefit;
- on systems where you cannot install/test-sign a driver.

---

## 2. Architecture

```
+-----------------------------+          +--------------------------------+
| DumperPro.exe (user mode)   |          | kernel driver (provided by you)|
|                             |          |                                |
| KernelReader (IMemoryReader)|          |   device: \\.\DumperPro        |
|   Read(va, buf, size)       |  ----->  |   IOCTL_DUMPERPRO_READ         |
|   Modules()                 |  IOCTL   |     input:  KReadReq           |
|   TargetName() ...          |  <-----  |     output: requested bytes    |
+-----------------------------+          +--------------------------------+
                                                    |
                                                    | attach to TARGET process
                                                    v
                                          [ target address space ]
```

- The client is a thin, synchronous wrapper: every `IMemoryReader::Read(va, out, size)` call
  becomes exactly one device IOCTL with a `KReadReq` in the input buffer and the raw bytes in
  the output buffer. There is no caching layer, no batching, no protocol negotiation - a
  driver that implements the contract below "just works".
- Device enumeration (`Modules()`, `MainModuleBase()`) is implemented on the client side from
  standard user-mode snapshots; only *memory reads* travel through the driver. This keeps the
  driver surface minimal.
- If the device cannot be opened, the reader reports failure through the standard
  `IsOK()` / `LastError()` path and DumperPro exits with its usual `Hint:` message; it does not
  silently fall back to the user-mode reader.

---

## 3. Client-visible contract

### 3.1 Device and IOCTL

| Item | Value |
|---|---|
| Device name | `\\.\DumperPro` |
| IOCTL | `IOCTL_DUMPERPRO_READ` |
| Definition | `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| Method | `METHOD_BUFFERED` (the I/O manager supplies `SystemBuffer` for both directions) |
| Access | `FILE_ANY_ACCESS` |

### 3.2 Input structure

```c
typedef struct _KReadReq {      /* 16 bytes, no dynamic parts */
    unsigned long long address; /* target VA to read from (target process) */
    unsigned long      size;    /* number of bytes to read, 1 .. KREAD_MAX  */
    unsigned long      pad;     /* zero; keeps the struct 16-byte aligned   */
} KReadReq;
```

- `InputBufferLength` is exactly `sizeof(KReadReq)` = 16.
- `pad` must be zero on the wire; drivers should reject nonzero padding to keep the
  format extensible and unambiguous.
- `address` is a **user-mode virtual address in the target process** chosen by the operator
  (never a kernel address; drivers must validate this - section 4.2).

### 3.3 Output

- `OutputBufferLength` equals `KReadReq.size`.
- On success, the driver fills the output buffer with exactly `size` bytes read from
  `address` in the target process and completes the IRP with `STATUS_SUCCESS`.
- On failure, the driver completes the IRP with an informative NTSTATUS and writes **zero**
  meaningful bytes; the client surfaces the failure as a failed `Read()`. Partial reads are
  not supported in v1: a read either returns all `size` bytes or fails.

### 3.4 Recommended limits

- Cap single reads (`KREAD_MAX`, e.g. 1-4 MiB). DumperPro's largest single reads are module
  snapshots; it issues big reads as one call, so the cap should comfortably exceed the largest
  module size or the client will chunk. A missing cap is a stability and safety hazard
  (an unchecked `size` is a classic kernel bug class).
- No minimum alignment requirement; the driver must handle arbitrary byte-aligned addresses.

---

## 4. Driver-side contract

What a driver developer must implement to satisfy the client. This is a specification, not
source code.

### 4.1 Dispatch surface

The driver needs at minimum:

- a device object with a symbolic link exposing `\\.\DumperPro`;
- `IRP_MJ_CREATE` / `IRP_MJ_CLOSE` handlers (allow operator access; restrict concurrently if
  desired - the client opens one handle for its lifetime);
- `IRP_MJ_DEVICE_CONTROL` handling `IOCTL_DUMPERPRO_READ` and rejecting every other IOCTL
  with `STATUS_INVALID_DEVICE_REQUEST`.

The core routine has the logical signature:

```
NTSTATUS ReadTargetMemory(
    PEPROCESS  TargetProcess,   // resolved via PsLookupProcessByProcessId (see 4.4)
    u64        Address,         // user-mode VA inside TargetProcess
    void*      OutBuffer,       // caller-provided kernel buffer, >= Size bytes
    SIZE_T     Size,            // bytes to read
    SIZE_T*    BytesRead);      // must equal Size on success (no partial reads in v1)
```

and must return `STATUS_SUCCESS` only when the full range was copied.

### 4.2 Mandatory sanity checks

1. **Buffer length validation.** Reject the IOCTL unless
   `InputBufferLength == sizeof(KReadReq)` and `OutputBufferLength == KReadReq.size`. With
   `METHOD_BUFFERED`, `SystemBuffer` is the I/O manager's buffer for both directions; validate
   it is non-null.
2. **Size capping.** Enforce a hard maximum on `size` (section 3.4) and reject `size == 0`.
3. **Address validation.** Reject kernel-space addresses; the interface is defined for
   user-mode targets only. Validate that the range `[address, address + size)` is plausibly
   readable in the target before copying (see 4.3).
4. **Padding.** Reject `KReadReq.pad != 0`.

All validation happens *before* any copy. Every failure path must complete the IRP with a
specific NTSTATUS (`STATUS_INVALID_PARAMETER`, `STATUS_ACCESS_DENIED`,
`STATUS_PARTIAL_COPY`, ...) rather than a silent success.

### 4.3 Safe memory access

The read must be exception-safe: touching a target address that is paged out or inaccessible
would otherwise bugcheck the machine. Two acceptable implementations:

- **`MmCopyVirtualMemory`** - the documented workhorse: copies between a source process and
  the current context with internal probing. Simplest correct choice for a read-only interface.
- **Manual attach + probe**: attach to the target (4.4) and wrap the copy in
  `ProbeForRead` on the source range, with the write side protected by the equivalent probe
  discipline (`ProbeForWrite` where the driver builds any intermediate buffers in target
  context), all inside SEH (`__try`/`__except`) so a race with the target's own memory
  management yields a clean failure instead of a crash.

In both approaches the driver must never trust user-supplied pointers as kernel pointers, and
must never copy into a user-mode buffer directly from kernel context without the buffered
method handling it.

### 4.4 Process attachment rules

- The target process is **chosen by the operator at runtime** through the normal DumperPro
  CLI (`--process` / `--pid`). The driver receives the target's PID from the client (the
  client resolves it before opening the device) and resolves it with
  `PsLookupProcessByProcessId`, checking the returned `PEPROCESS` against liveness
  (`PsGetProcessId` round-trip or equivalent sanity check).
- The driver must **never** hardcode a process, never default to the calling process's
  address space for target reads, and never cache a stale `PEPROCESS` across calls.
  Reference counting rules apply: every successful `PsLookupProcessByProcessId` must be
  balanced with `ObDereferenceObject`.
- Attach/detach must be paired: `KeStackAttachProcess` / `KeUnstackDetachProcess` around any
  code executing in the target context, or no attach at all when using
  `MmCopyVirtualMemory` (which attaches internally).
- Reads must be performed against the *selected* target only. There is no enumeration, no
  discovery, and no cross-process access beyond the single selected process per request.

### 4.5 No write support in v1

- The contract defines exactly one operation: read. There is no write IOCTL, and a driver
  implementing this interface must not add one in a way that satisfies this client.
- `IMemoryReader::Write` is unused by DumperPro and returns failure in the kernel backend.
- Read-only operation is a deliberate safety property: it bounds what a compromised or
  misused driver build can do through this interface. Future versions, if any, would define a
  separate, explicitly versioned IOCTL with additional controls; none is specified today.

### 4.6 General hygiene

- Correct IRQL discipline: all work for this IOCTL runs at `PASSIVE_LEVEL`; do not call
  paging-unsafe APIs above it.
- Complete every IRP exactly once, on every path.
- No spinlocks held across the copy; no waiting at raised IRQL.
- Unload must be safe: `IRP_MJ_CREATE` should reject new opens once the driver is deleting
  the device (or use the standard `IoCreateDeviceSecure`/delete ordering).

---

## 5. Legal and safety

**Driver signing.** Windows loads kernel drivers only if they are signed. To build and run a
driver implementing this contract you need either:

- **WHQL or attestation signing** through the Microsoft partner program (required for normal
  distribution on up-to-date systems with Secure Boot/HVCI), or
- **test signing** on your own machine:
  `bcdedit /set testsigning on` (then reboot; the desktop shows a test-mode watermark), and
  sign the driver with a self-generated certificate trusted on that machine.

Test signing is appropriate for private debugging/dumping on machines you control. It is not a
distribution mechanism, and enabling it system-wide is itself a security trade-off you should
understand before doing it.

**Permitted use.** This interface is provided for legitimate debugging and dumping of software
you own or are licensed to analyze, on systems you own or are authorized to operate.

**Out of scope and unsupported.** Using this interface (or a driver implementing it) to evade
anti-cheat systems, to cheat in multiplayer or competitive games, to attack third-party
systems, or for any unauthorized access is explicitly outside the intended use. DumperPro will
not assist with such use, and the software carries no warranty for any purpose (see the
DISCLAIMER in `README.md`).

**Operational risk.** Kernel bugs crash machines, not processes. Keep the driver minimal,
validate every input (section 4.2), test on a disposable system or VM first, and never run a
driver you did not build from source you have read.

---

## 6. Quick reference

| Item | Value |
|---|---|
| Client implementation | `KernelReader.cpp` (backend of `IMemoryReader`) |
| Enabled by | `--kernel` |
| Device | `\\.\DumperPro` |
| IOCTL | `IOCTL_DUMPERPRO_READ = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| Input | `KReadReq { u64 address; u32 size; u32 pad; }` (16 bytes) |
| Output | exactly `size` bytes, or an NTSTATUS failure |
| Semantics | all-or-nothing read, target process selected by the operator at runtime |
| Write support | none in v1 |
| Driver source | not shipped; contract only (this document) |
