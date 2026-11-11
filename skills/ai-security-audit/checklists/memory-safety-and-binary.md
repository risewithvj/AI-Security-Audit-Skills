<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Memory Safety, Binary, and Kernel Hunting

> **Reading from source only.** This skill inspects code; it never runs the target. Anywhere the text below mentions a harness, a fixture, a sandbox, or a local reproduction, treat that as the standard you would need to *reach* a `confirmed` verdict — then satisfy it from the source if you can. When the source alone cannot settle a question, stop at `needs_validation` and name the one fact that is still missing. Checklist references use the `checklists/...` form, and the decision gate in `rules/evidence-gate.md` governs every verdict here.

---

## 1. Scope: is this the right checklist?

Open this file when the target takes bytes it does not control and handles them in a language or context where the runtime will not catch mistakes for you — C, C++, Objective-C, Rust blocks marked `unsafe`, anything crossing an FFI line, kernel modules and device drivers, decoders and parsers, long-running network daemons, firmware images, binary loaders, bytecode interpreters, and JIT compilers.

There is one neighbour to keep straight. Protocol authorisation, session state machines, and "who is allowed to ask for this" live in `protocols-rpc-and-messaging.md`. Everything about the *integrity of the process itself* — memory, object lifetime, ABI contracts, how images get loaded — stays here. If a payroll gateway daemon both authorises a request and then memcpy's the request body into a fixed struct, the authorisation half is the other file's job and the copy is ours.

Large native targets are hard to reason about in one pass. Partition the work and give each slice its own subagent: one for each parser, one for allocation and object lifetime, one for the FFI surface, one for concurrency, one for the loader, one for the runtime or JIT, and one for any privileged interface. Phase 1 should pick only the classes that actually apply.

---

## 2. Operating discipline for every native subagent

Paste the block below into each agent prompt you spawn for this domain. It fixes the mindset before any class-specific hunting starts.

```
- Recompute every size, offset, and object lifetime yourself, starting from
  the attacker-reachable input and walking through all callers. Reason about
  the worst input the code will accept, never the input your test happened to use.
- A crash, a panic, or a sanitizer hit is only a vulnerability once you show a
  plausible untrusted input that drives execution there. The name of the bug
  class does not by itself prove corruption, RCE, or an availability hit.
- Prove it the narrow way: sanitizer-built local harness, a deterministic
  concurrency schedule, any fuzz target already in the tree, and a debugger to
  classify the fault. Stop the moment the broken invariant and its visible
  effect are shown — never build anything that happens after corruption.
- Hand-written assembly, JIT output, bespoke allocators, accesses inside a
  single object, and third-party native libraries routinely sit outside
  sanitizer coverage. State plainly which of the involved operations are
  actually instrumented.
- Reserve `confirmed` for the case where source reading AND a bounded local
  check together pin down both the defect and its effect. Fall back to
  `needs_validation` whenever ABI, allocator internals, target architecture,
  a build feature, the deployment, or reachability is still unknown.
```

---

## 3. How to read the class tables

The classes below are grouped into five families. Each family is a subagent of `subagent_type: general`. For every class you keep the same two-step obligation: locate the source disagreement, then show the effect with the narrowest possible check. The families are:

| # | Family | What breaks |
|---|--------|-------------|
| 4 | Bounds, integers, representation | Sizes and indices computed wrong |
| 5 | Lifetime, type, concurrency | Objects used at the wrong time or as the wrong thing |
| 6 | FFI and ABI | Two sides of a language border disagree |
| 7 | Loading and runtime | Wrong code gets mapped, verified, or generated |
| 8 | Kernel and privileged interfaces | A trusted side trusts an untrusted caller |

---

## 4. Bounds, integers, and representation (subagent: `general`)

**Reads and writes that leave the buffer**
Some length, offset, index, or terminator lands in a fixed or heap buffer without a bound that actually holds. Redo the arithmetic *after* every header, alignment pad, filler byte, and terminator has been accounted for — the room left is rarely what the first glance suggests. Check capacity on both ends of a copy, and watch for code that consumes a short input before it has confirmed the length field it claims to trust.

**Integer overflow, underflow, truncation, sign flips**
Audit any attacker-influenced arithmetic that feeds an allocation, a copy length, a loop count, an index, or a pointer step. The usual suspects: `a - b` where `b` can exceed `a`; `count * element_size` wrapping; an addition that tips past the type's ceiling; a negative signed value reinterpreted as a huge unsigned one; a 64-bit length squeezed into a 32-bit field; and sentinels like `-1` turning into an enormous size. Always confirm *which* computed value the later code actually uses — the checked one or the unchecked one.

**Mixing up units and pointer depth**
The code counts in bytes in one place, elements in another, and maybe pages, words, code units, wire units, or the element size of a nested pointer somewhere else. Line up the unit at each stage: parse, validation, allocation, API boundary, copy. A bounds check that uses the same wrong unit the allocation used is not a safe bounds check — it is a consistent mistake.

**Data that was never fully initialised**
A buffer, a struct padding gap, an unset field, or reserved-but-unwritten vector capacity gets returned, compared, hashed, serialised, or handed across a trust line before anyone wrote to it. To call this a disclosure you need a real consumer on the far side and an output long enough to carry the stale bytes. A buffer merely sitting on the stack is not, on its own, a leak.

---

## 5. Lifetime, type, and concurrency (subagent: `general`)

**Use-after-free, stale views, double free**
An owner is dropped while something still points into it — a queued callback, a wait entry, a timer, an iterator, a borrowed slice, a cached raw pointer. Walk every error return, cancellation, close, and reallocation path, because those are where ownership and liveness part ways. When the freed object carried an intrusive notification hook, every free path has to detach or drain *all* of its observers, not just the common one.

**Type confusion and bad downcasts**
A discriminator — tag, vtable, union selector, object-kind byte, foreign handle — is validated in a form that does not match the form later code reads. Hunt for dynamic casts with no check, tags that went stale after the slot was reused, and serialised types where the element you validated is not the element you later consume. Prove a wrong-type read or write in the local harness and stop there; do not chase it past the broken invariant.

**Refcount and ownership races**
A retain/release pair that is not atomic, a validity check followed by an unlocked use, or threads that disagree about who owns an object can all free or mutate it mid-access. Put the fast path, the error path, the shutdown path, and any backward-compatibility path side by side and confirm they take the same lock and honour the same ownership rule.

**Shared-state races and TOCTOU**
Concurrent parser instances, shared caches, lazy one-time initialisation, signal handlers, and teardown can quietly invalidate a bound, a policy decision, or a pointer that earlier code already established. You need a repeatable schedule, a barrier, or a thread sanitizer trace that shows the race crossing into a security-relevant state change. A merely *imaginable* interleaving with no such transition stays `needs_validation`.

**Lock order, deadlock, starvation**
Externally reachable operations grab locks in different orders, or hold a lock across a callback or a blocking I/O. Only file this under availability when a bounded input can actually wedge shared progress; otherwise log it as a concurrency defect worth fixing and move on.

---

## 6. FFI and ABI boundaries (subagent: `general`)

**Pointer/length and ownership contracts that disagree**
Caller and callee differ on who allocates and who frees, who pins or may mutate a buffer, how long a pointer stays live, or whether a length counts bytes or elements. Read *both* sides of every `extern`, every CGo / JNI / Python-native / ctypes binding, and every generated wrapper. Probe the awkward inputs: null, zero length, aliasing arguments, and pointers a callback quietly retains past its call.

**Layout, alignment, and enum mismatches**
Foreign code receives a calling convention, an enum, an integer width, a callback signature, a packed record, a bitfield, or a struct whose shape differs across architecture or build flag. Pin down `repr`, packing, alignment, endianness, and ABI-specific widths. If the mismatched declaration lives *in this repo* on both sides, you can confirm it locally; if the other side is an opaque third-party binary, it is `needs_validation`.

**Unwinding, exceptions, thread affinity**
An exception or panic crosses an ABI that forbids unwinding, a callback fires after its owner was torn down, or a single-threaded-only API is called from the wrong thread. Read the error-conversion and cancellation code carefully, and work out whether the real outcome is a clean abort or silent state corruption *before* you assign an impact.

---

## 7. Binary loading and runtime (subagent: `general`)

**Who controls the search order**
A privileged process reaches for a helper, a runtime image, a plugin, or a shared library out of some path that a less-trusted principal can write, or resolves a bare name through a working directory or environment variable an attacker can nudge. Compare where the thing is *meant* to be installed (and owned) against every fallback and compat path the resolver will try. When someone loads a plugin they themselves supplied into a process they already control, no trust boundary was crossed — do not flag it.

**Verifying one file but mapping another**
The loader checks a signature or a metadata record, then maps a *different* image because path resolution, a file swap between check and use, a multi-arch slice, or an embedded resource was never bound to the thing that was verified. Authenticity of the *supply channel* belongs in `supply-chain-and-release.md`; what we own here is the local gap between "what was checked" and "what was mapped".

**Malformed binary metadata and relocations**
Offsets, counts, section headers, relocations, symbol tables, bytecode, or debug records get trusted before anyone range-checks them, checks for overlap, or validates their representation. Exercise the parser with small local fixtures under sanitizers. Keep a clean line between genuine memory corruption and a malformed file that was safely rejected.

**JIT and generated-code agreement**
The validator, the interpreter, the optimiser, and the emitted code disagree about a type, a bound, a side effect, or a lifetime. Feed the same local input through the optimised and unoptimised paths and diff the behaviour. You must land on a real process-integrity effect — output that merely varies while staying inside the language's defined semantics is not a finding.

**Unload, reload, teardown**
Live function pointers, registered callbacks, worker threads, or data views outlive the module unload or runtime reset that should have invalidated them. Give shutdown and failed-load cleanup the same scrutiny you give startup — that is where these survive.

---

## 8. Kernel and privileged interfaces (subagent: `general`)

**User-copy bounds and double reads**
A syscall, ioctl, driver, or in-kernel parser reads a value out of user memory, decides something based on it, then reads the *same* mutable user address again — and the second read may differ. Either copy the whole request once into kernel memory, or revalidate after the second read. Check size, direction, and access rights at every user-copy primitive too.

**Lifecycle and dispatch of privileged objects**
Externally reachable kernel objects with unbalanced retain/release, teardown that forgets to drain observers, selector or table indices used without a range check, or duplicated compat paths where one copy quietly drops a guard the other keeps. Put each dispatch and each free path next to its sibling and diff them line by line.

**Powerful interfaces with weak authorisation**
A device node, admin socket, privileged helper, or management API validates the *shape* of a request but never checks that this caller has authority over the resource being touched. Establish who really owns the interface and whether an unprivileged caller can reach it. When the deciding factor — file permissions, a sandbox profile — lives outside the repository, the verdict is `needs_validation`.

---

## 9. Moves that cut across all of the above

- **Chase the shape, not the single site.** Once you find a source-to-sink pattern, grep for its twins. A guard present in one caller, on one architecture, in one protocol role, behind one feature flag, or on the modern path tells you nothing about the compat path right next to it. Old fixes especially tend to miss a sibling.
- **Tabulate every parser and FFI edge.** One row per boundary: the length/type it accepts, the representation it actually checks, who owns the allocation, who consumes it, which thread, and what happens at teardown. The overwhelming majority of native bugs are a single disagreement between two columns in that table.
- **Reuse corpora, keep fixtures tiny.** Lean on any existing corpus and hand-craft small boundary inputs. Record the exact sanitizer or runtime output and the precise property of the input that set it off. Do not burn large amounts of memory or CPU, and never point any of this at a live system.

---

## 10. Gate every finding before you write it down

Run all five checks. Anything that cannot clear them is `needs_validation`, not `confirmed`.

1. **Entry and operation.** Name a realistic untrusted entry point and the exact operation that violates an invariant of authority, the loader, concurrency, the ABI, object lifetime, a type, or a bound.
2. **Honest effect.** State the observable effect and no more than you saw: a read out of bounds, a write out of bounds, a dangling alias, access to the wrong object, uninitialised output, an unauthorised image load, a deadlock, or a safe process exit. Do not inflate it into a stronger primitive.
3. **Narrowest reproduction.** Use the smallest harness, existing test, sanitizer, or fuzzer that shows the effect — and confirm the faulting operation is actually within sanitizer coverage. Record the architecture and build conditions it depended on.
4. **Class-specific proof.** For concurrency, bring a deterministic schedule or a sanitizer trace. For loading, show that the checked identity and the mapped identity differ, and name the lower-trust principal who can write the mapped file.
5. **Verdict discipline.** A `confirmed` finding ships only with the exact input, the source trace, and the observed result. A `needs validation` finding names the single open question — whether that is runtime behaviour, the deployment, a build setting, the ABI, or reachability — and states the bounded check that would resolve it.
