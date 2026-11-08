# Vault Breaker slot 7 owner and dispatch

REA with Ghidra 12.1.4 decompiled 11 bounded entry points from the private `row7-analysis-view.exe` and recovered the publisher, setter, getter, virtual-call instruction, tag reader, resolver, and fallback result store. The 64 KiB PE maps selected pages from the existing reconstructed images at their original virtual addresses. Export names are analyst labels that seed disassembly. The view was used only for static analysis. The [REA evidence snapshot](D:/Marathon-preservation/analysis/row7-rea-slices/row7-rea-evidence.json) and [page manifest](D:/Marathon-preservation/analysis/row7-rea-slices/row7-analysis-view-manifest.json) preserve the inputs and results. REA's Windows Ghidra provider accepted the PE view after rejecting a headerless x64 slice. Its pseudocode for the protected entry points ends at trampolines. The reconstruction below uses the decompiled fragments and previously captured protected continuations.

## Owner and publisher

| Address | Recovered behavior | Evidence |
| --- | --- | --- |
| `0x16f2b417e` | Calls the owner initializer with RCX loaded from `[RBX]`. | REA xref and direct call bytes in recovered text. The full-text branch scan finds one matching call. |
| `0x16f65d540` | Owner initializer entry. The fragment at `0x16f65d55e` loads `0x172d886d0`; the protected fragment at `0x1525cdbed` stores it at owner +8. | PE unwind range `0x16f65d540..0x16f65d80a` and existing entry replay. The register stop shows RDI equal to the input owner and RAX equal to the table. The store bytes also match the preserved on-disk PE. |
| `0x16f65d799` | Sets owner +0x40 to -1 and calls the setter with owner +8. | REA pseudocode, recovered disassembly, and existing isolated publisher replay. The publisher sits in the same unwind range as the initializer. |
| `0x16f6dd3c0` / `0x170b705f0` | Store and load the context pointer at `0x1767f3338`. | REA pseudocode for both functions. |

The older secondary table candidate at `0x172e2cd70` crosses into a neighboring destructor table at +0x48. The stronger candidate is `0x172d886d0`, which the recovered initializer installs at the exact offset the publisher exposes. Its +0x48 entry contains `0x16efee9b0`; those eight table bytes match the original PE. The initializer's uninterrupted replay stops at a CRT import before publication, so the connection between the two fragments remains an inference from unwind coverage, object offset, and compatible behavior.

## Fallback and virtual method

At `0x16f765b80`, the slot 7 fallback reaches the getter, loads the vtable from the returned context, and dispatches through +0x48 at `0x170497f91`. REA decodes the call as `CALL qword ptr [RDX + 0x48]`. The saved-state probes and virtual method controls establish the following fragment-level behavior.

```c
// 0x16f65d799, publication fragment
owner->field_40 = UINT64_MAX;
context_set((uint8_t *)owner + 8);

// 0x16efee9b0, virtual method at +0x48 of 0x172d886d0
uint32_t tag = read_u32(tag_source_at_0x174f6f240 + 0x40);
if (tag == UINT32_MAX)
    return NULL;
return resolve_package_record(tag) + 8;

// Slot 7 fallback, selected operations only
context = context_get();
table = context->vtable->method_48(context);
row = lookup_sorted_32_byte_rows(table, &key);  // 0x17038efa0
*result = (int32_t)read_i8(row + 0x1c);         // 0x15f8daa10
```

The method's tag read at `0x1499be355` and bucket resolver at `0x146a477dd` match the original on-disk bytes. The selected resolver record is computed as entry address minus its masked relative value, then advanced eight bytes. The existing startup-asset fixture supplies the real authored tag and investment table through modeled pointers and one package mapping. It reaches the real method and verifies the fallback store for a known table key. This demonstrates the chain under a controlled setup. It leaves native context publication, the original startup asset view, and the slot's real query key unobserved. The evidence identifies shared investment lookup behavior within slot 7. Vault-specific gameplay logic remains unresolved.

The next step is to recover the protected continuation from the initializer to `0x16f65d799`, or observe both stores to the same owner in one isolated run with the original initialization prerequisites. This would close the remaining constructor-to-publisher edge without supplying a fabricated owner.

## Source of the initializer's owner argument

The preserved table at `0x172d88720` contains `0x16f2b4140` at +8. That qword matches the original PE. A bounded replay enters this method with RCX equal to the checkpoint's static tag-source holder at `0x174f6f238`. It stops before the preparatory call at `0x16f2b4176` with RBX equal to `0x174f6f240`. The original PE bytes at `0x14fb0f917..0x14fb0f94b` independently show `RBX = this + 8` and pass that address in the stack arguments to the preparatory call. REA disassembles the following sequence at its recovered addresses:

```c
prepare_at_170129750(/* includes &holder->pointer_at_08 */);
initialize_owner(holder->pointer_at_08);  // 0x16f2b417e
```

The load at `0x16f2b417b` is `mov rcx, [rbx]`, immediately before the call to `0x16f65d540`. This joins the constructor argument to the same holder field that method +0x48 reads later to obtain the asset tag. It does not verify what writes that field. The preparatory call was not allowed to return in the targeted register capture, and the earlier complete-method probe stopped in its protected code. Thus the data-flow is established for the decoded path, while the field's real contents and uninterrupted execution from initialization to publication remain open.

The continuation probe from `0x16f65d5d2` independently recovers the first two transfers, to `0x16f65d5de` and `0x16f65d61d`. The subsequent helper consumes state missing from the isolated mid-function frame. A separate probe from `0x16f65d622` also stops before publication. Neither used a replacement runtime object or a fabricated return from the preparatory helper. The useful next target is the write through the holder field's address during or before `0x170129750`, or a saved context that already contains that value.

Private evidence is `row7-owner-continuation-0x16f2b4140.json`, the other two `row7-owner-continuation-*.json` probes, and [REA instruction evidence](D:/Marathon-preservation/analysis/row7-rea-slices/row7-owner-caller-rea-evidence.json). The bounded caller probe uses the standard checkpoint overlay with `--start 0x16f2b4140 --target 0x16f2b4176 --rcx 0x174f6f238 --model-object --model-tls --model-tls-template --inline-dispatch --trace-dispatch`.

## Preparatory call contains the owner-pointer write

Two real saved checkpoint overlays take different branches in the preparatory helper. The later `checkpoint-parent-waits-empty` takes the nonzero branch at the byte read from `0x17541dc90` and reaches an unresolved protected target. The earlier `checkpoint-constructor-19000` contains zero at that byte. With the same holder argument and no allocation stub it reaches `0x1701297af`, then the original `_aligned_malloc` import at `0x17159232e` with size and alignment both 0x80. No allocation result was fabricated.

The recovered post-call block at `0x1701297b4` moves the returned pointer into R8. If it is nonzero it loads the output-field address into RDX from the stack and calls the protected thunk at `0x1599dc66b`. An isolated decode probe starting at that call, using the actual holder-field address as RDX and leaving R8 zero, identifies the target block at `0x148c6b6c8`. The probe executes the first zeroing store and stops at an unsupported vector store. Independent Capstone decoding of the preserved on-disk PE confirms every instruction through the pointer write at `0x148c6b6ed`, encoded as `4c 89 02` (`mov [rdx], r8`). The surrounding stores clear and initialize fields of the holder-side descriptor. This is the concrete indirect writer missed by the earlier RIP-relative xref search.

```c
allocation = allocate_aligned_through_helper(...);
if (allocation != NULL) {
    // 0x148c6b6ed, after descriptor initialization
    holder->pointer_at_08 = allocation;
}
// Back in the caller at 0x16f2b417b
initialize_owner(holder->pointer_at_08);
```

This verifies the write and its role in the allocation-success path at the instruction level. It leaves the live allocation, the later nonzero-byte path, and the uninterrupted transition from constructor to publication unobserved. The next narrow target is the constructor's protected continuation into publication after the preparatory path supplies an owner.

Private evidence is `row7-owner-prep-checkpoint-constructor-19000.json`, the parent-overlay counterpart, and `row7-owner-prep-success-fragment.json`. Reproduce the two caller probes using the prior command with `--target 0x16f2b417e` and the respective checkpoint overlay. The decode probe uses the constructor-19000 overlay and `--start 0x1701297c1 --rcx 0xffff --rdx 0x174f6f240 --count 400` with TLS and dispatch tracing. Compare 0x148c6b6c8 through the dispatch at 0x148c6b705 directly against the original PE.

## Recovered protected edges into publication

The initializer's existing replay reaches the nested call at `0x16f65d61d`, which stops at a CRT import. Starting at the instruction after that call, bounded fragment probes recover the protector's continuation setup without stubbing the CRT or supplying an owner. Each tested thunk subtracts five from its saved call return address, stores the resulting call-site address in the TLS continuation field, and adds a small constant. All eight subtract and add instruction sequences match the preserved on-disk executable. Their verified addresses and bytes are in private `row7-init-publication-protected-edges.json`.

| Protected call site | Continuation | Role |
| --- | --- | --- |
| `0x16f65d622` | `0x16f65d630` | Reads and tests owner +0x28 before dispatch. |
| `0x16f65d632` | `0x16f65d63f` | Uses owner +0x3c as an RVA for an indirect call. The returned value is XORed into RSI before the next block. |
| `0x16f65d644` | `0x16f65d660` | Writes a pointer and prepares fields in the object addressed by RSI. |
| `0x16f65d6d0` | `0x16f65d6db` | Advances the record pointer by 0xa0 and decrements the loop counter. |
| `0x16f65d6e0` | `0x16f65d700` | Prepares the second initialization loop. |
| `0x16f65d758` | `0x16f65d770` | Installs a pointer, then loads and tests owner +0x28 again. |
| `0x16f65d772` | `0x16f65d786` | Goes through an indirect call before rejoining the alternate branch at `0x16f65d78b`. |
| `0x16f65d78b` | `0x16f65d794` | Passes owner +0x10 in R8 and dispatches into the block that calls the helper and publishes owner +8. |

The last edge was also observed directly. The isolated probe from `0x16f65d78b` reached `0x16f65d794` in 56 instructions without calling the next helper. This gives a conditional control-flow path from the initializer's known frame into its publication block. The probes establish destinations and local data flow. They leave the actual indirect targets, branch outcomes with initialized objects, and a single uninterrupted run across the CRT and publication boundaries unverified.

Reproduce from the prior continuation command with `--start 0x16f65d78b --target 0x16f65d794 --count 600`. The private `row7-owner-continuation-*.json` reports also retain the other fragment probes. Several stop on object-dependent accesses after setting the continuation. For those fragments, the continuation is derived from the original return-address rewind and additive update, rather than from an executed dispatcher transition.

## Constructor callback RVAs come from three randomized tables

The allocator/setup call at `0x16f65d5cd` receives `&owner->field_28`, descriptor `0x174f6f250`, and size `0xd2f0`. The existing trace reaches `rand` at `0x1711a088a` with R15 still pointing to owner +0x28. A bounded probe starting at the instruction after the import reaches original-byte code at `0x160a033c2`. That block reduces the return value modulo 100, then uses the result as a common index into three contiguous DWORD tables at `0x1745263d0`, `0x174526560`, and `0x1745266f0`. It copies the first two RVAs to owner +0x38 and +0x3c. The third RVA is added to the image base and dispatched as a call with RCX equal to owner +0x28. No RNG value was substituted into the constructor.

The table bytes match between the transformed data image and the saved parent checkpoint. All 300 entries are distinct executable addresses. Every target begins with `push rbx; mov eax, imm32`, and the first eight bytes at all 300 addresses match the on-disk executable. For table index zero, the second target `0x155eb4746` returns XOR mask `0xbb9732a1d305d2fa` in an isolated probe. The third target `0x15927b454` reads the qword at RCX and writes an XOR-transformed value at RCX +8. Its first XOR mask matches the second target's return value, and the combined mask for the store is `0xa2ecb5800b66fd5a`. These constants are independently recoverable from its scalar immediates and packing instructions. The first target takes a pair of qwords through RDX, decodes them and compares the results. This identifies the sampled trio as pointer-management code and explains why the initializer uses an indirect call followed by XOR. It leaves the pointer contents and the index chosen in a genuine run open.

Private table evidence is `row7-owner-randomized-rva-tables.json`. The key writer instructions are `0x160a033e6` and `0x160a033f2`. The callback call sites are `0x1711a08d2` and `0x1711a0947`; the latter adds owner +0x3c to the image base, then XORs the return into the saved pointer. Private fragment probes are `row7-owner-continuation-0x1711a0890.json` and the three index-zero address reports with the same prefix. The next narrow question is where the helper first stores the qword at owner +0x28 that this trio consumes.

## Owner +0x28 receives a bucket-resolved, encoded value

The constructor helper has two stores to the output field addressed by R15. On the path following the third randomized callback, `0x15235569d` writes the previously loaded or decoded value from R14. Its bytes match the original PE. The helper then loads a saved entry index and bucket displacement from its frame and dispatches through `0x1711a08fa`. The resolver at `0x14ab8df03` reads the bucket stride and mask, computes the entry address, and subtracts the masked relative qword. The selected address is returned in R14 to continuation `0x1711a091e`.

For the saved parent overlay, the earlier CRT-boundary trace contains bucket displacement 0x40 and entry index 1 in the corresponding frame fields. Its RDI is already `0x7a010379b720`. A separate read-only calculation from the saved bucket directory yields that same address. A targeted execution of the resolver with those captured index values also reaches `0x1711a091e` with R14 equal to `0x7a010379b720`. This uses the original checkpoint bucket bytes and stops before the encoding path. The bucket stride is 32 and the selected entry's adjustment qword is zero. This is evidence for the modeled constructor's chosen bucket entry. Its native contents and semantic type remain unknown.

The nonzero-address branch calls the first randomized callback using the RVA at owner +0x38, the resolved address as RCX, and `&owner->field_28` as RDX. The recovered code at `0x1711a092f` XORs the return with the address and `0x1711a0932` writes the resulting qword at owner +0x28. It then calls through owner +0x3c before continuing. In shortened pseudocode:

```c
address = resolve_bucket_entry(saved_bucket, saved_index);
if (address != 0)
    address ^= call_rva(owner->callback_38, address, &owner->field_28);
owner->field_28 = address;
```

This identifies both the source and the encoding step for the replacement value. It does not establish that the value stored at +0x28 is a plain pointer or that the modeled call's key matches a real play session. No random number or encoded pointer was supplied to make the full constructor advance. The next step is to recover the remaining return and publication edges using the known callback contracts, or obtain a checkpoint that contains the initialized owner.

Private reports are `row7-owner-arg-checkpoint-parent-waits-empty-0x16f65d540.json`, `row7-owner-continuation-0x1711a08ee.json`, `row7-owner-continuation-0x1711a08fa.json`, and `row7-owner-continuation-0x1711a0920.json`. Reproduce the resolver probe with the checked parent overlay and `--start 0x1711a08fa --target 0x1711a091e --rdx 1 --r8 0x40 --registry-heap-pages --model-tls --model-tls-template --inline-dispatch --trace-dispatch`.

## Publication is followed by registration and a separate setup call

The first post-publication call at `0x16f65d7aa` enters `0x16f618140`. An isolated trace with RCX zero builds a 0x70-byte stack descriptor with callback `0x171a9e600` at +8 and passes index `0x2a` to `0x16f851690`. The native writer copies the descriptor to `0x17679cca0 + 0x2a * 0x70 = 0x17679df00`. A watched stack write captures the callback value, and the completed 185-instruction run records the copy at `0x1596e51e8`, `0x1596e51f2`, `0x1596e51fd`, and `0x1596e5208`. This targeted probe used the existing bounded AVX move support under `--stub-crt-basics` and executed no CRT import stub. The destination was all zero in the untouched parent checkpoint.

The callback has a separate object contract. Its protected body at `0x149a37c5b` loads `[argument + 0x10]`, reads a qword at that object's +0x218, and tests it. An isolated entry with RCX zero stops on the first read. The table xrefs show 0x70-byte indexed comparisons at other fields, including +0x10, +0x18, +0x30 and +0x38. Neither the original invocation of slot 0x2a nor its connection to the owner's asset tag is established.

The next post-publication call at `0x16f65d7af` enters `0x16f0620b0`. It invokes the already analyzed `0x1711a02c0` setup helper again at `0x16f062109`. The argument capture shows destination `0x1767f33c0`, descriptor `0x174e98958`, and size `0x48`. This is a second setup target distinct from owner +0x28. These two post-publication calls do not establish a write to owner +0x40. The next concrete target is the code that invokes callback slot 0x2a with its real argument or writes the owner's asset-tag field later in initialization.

Private traces are `row7-owner-continuation-0x16f618140-avx.json`, `row7-owner-continuation-0x16f618140-registration-input.json`, `row7-owner-continuation-0x16f0620b0-arg.json`, `row7-owner-continuation-0x171a9e600.json`, and `row7-post-publish-registry-xrefs.json`. Use the standard checked parent overlay and TLS/dispatch tracing. The registration input stop uses `--start 0x16f618140 --target 0x16f61817b --rcx 0 --stub-crt-basics --watch-stack-address 0x7000001fef88`. The second setup capture uses `--start 0x16f0620b0 --target 0x16f062109 --rcx 0`.

## Registered callback follows a relative array and a tag-index filter

The callback at `0x171a9e600` reads the nested object at argument +0x10, then uses its +0x218 field in `0x16f2efa50`. The nonzero path computes `nested + 0x218 + relative + 0x20 + 24 * index`; the index comes through a pointer to a signed DWORD. The arithmetic block at `0x148ee5026` matches the original PE. A separately traced reader associated with table base `0x17679cca0` also accesses a +0x218 field at `0x15f7b6f18`. This is a corroborating layout clue. The actual edge from that reader to callback slot 0x2a remains unverified.

A later callback fragment at `0x1559733bc` reads the object at argument +8 and its DWORD at +0x2c. It exits that path for `0xffffffff` or when the bit at `key & 0x1fff` is clear in the 8,192-bit array at `0x1767160e0`. It continues through the protected dispatcher when the bit is set. The complete filter block through `0x1559733ef` matches the original PE. The array is all zero in all 222 checkpoint regions checked. A full-text exact displacement scan decoded 777 address-taking sites for that array. No memory writer using the loaded base appeared before the first call, return or unconditional jump in the examined short windows. The bitset is shared by substantially more code than this callback, so finding its owner is more relevant than inventing a set bit in the callback.

The fragment probes use the existing parent overlay with null arguments and do not supply a callback object or a bitset value. Private reports include `row7-owner-continuation-0x16f2efa60.json`, `row7-owner-continuation-0x171a9e62b.json`, `row7-owner-continuation-0x16f495369.json`, `row7-post-publish-callback-incoming.json`, and `row7-post-publish-filter-xrefs.json`. The next useful evidence is the object that supplies the relative array and +0x2c key, or the initialization that marks those keys eligible. No asset-tag store was observed here.

## Eligible callback branch dispatches on the same published owner

The set-bit path at `0x1559733ef` transfers to `0x171a9e69a` through the recovered continuation. That block calls `0x16fc03b60`, passes its DWORD result in EDX to `0x1715ac0b0`, and supplies a stack result address in RCX. In a bounded entry probe the latter calls `0x170b705f0`, the same getter used by slot 7. It reaches `0x160daf7bd`, moves the getter result into RCX, loads its virtual table, and tail-jumps through table +0x30. The on-disk bytes of the tail-jump block match the reconstructed code. The probe stops before dereferencing the absent published owner and does not install a substitute owner or set a filter bit.

The verified table `0x172d886d0` has `0x170863c50` in both slots +0x28 and +0x30, and `0x16efee9b0` at +0x48. All three entries match the original PE. In the recovered +0x30 body, a helper produces a DWORD. A value of -1 takes the sentinel branch. Otherwise the method masks the key with 0x1fff, multiplies by the stride DWORD at `0x174534e60`, adds the table base from `0x174534e58`, and returns the qword at row +0x18. The two table fields are zero in the parent overlay. The code has now joined the registered callback to a second virtual operation on the same owner, independently of the fallback lookup. It does not establish what calls slot 0x2a in a real session or where the asset tag used by +0x48 is written.

Private traces are `row7-owner-continuation-0x171a9e69a.json`, `row7-owner-continuation-0x171a9e69a-dispatch-args.json`, and the earlier `row7-owner-continuation-0x170863c50.json`. The targeted stop uses `--start 0x171a9e69a --target 0x160daf7c0 --rcx 0` with the checked parent overlay and TLS/dispatch tracing. The next narrow target is the producer of the +0x30 method's key or strided table, which may supply the concrete runtime object this callback expects.

## The +0x30 key helper validates a candidate against its own table

The wrapper `0x170863c50` passes a stack DWORD by address to `0x16f6490e0`. Original PE bytes at `0x14988af5d..0x14988af67` show the helper saving the output pointer and initializing the DWORD to `0xffffffff`. A bounded replay from the wrapper reaches the helper's continuation at `0x16f6490f9`, which calls `0x1706459e0`. The latter follows a vtable dispatch through global `0x176520d10` and entry `0x172d99e18` (+0x130). The replay then reads global `0x178b44600` and stops at `0x1454bd700` on a field access at +0x31 through a null pointer. This identifies the first missing prerequisite in the candidate-key path for this checkpoint.

The continuation saves the candidate from EAX in ESI. Original PE instructions at `0x15045b051` reject `0xffffffff` and pass the low 16 bits to a membership helper at `0x16fd076a0`, with RCX set to `0x174534e50`. An isolated continuation probe reaches the helper and stops on a null nested pointer. The subsequent original PE bytes identify the bit test at `0x159677d54..0x159677d78`:

```c
// Selected operations from the membership helper
uint32_t *words = header->root->field_08->words_at_10;
return (words[index >> 5] >> (index & 31)) & 1;
```

The caller also checks the low 16 bits against `0xffff`. A separate entry probe at the branch's next call, `0x16f649126`, reaches original PE code at `0x157fb7119`. That code computes `table_base + (uint16_t)candidate * field_20 + field_1c`, reads and masks a DWORD there, and computes `candidate & 0x1fff`. Here `table_base`, `field_20`, and `field_1c` are at header offsets +8, +0x20, and +0x1c. The base is the same global used by the wrapper's final row read. This probe stops on the metadata dereference at `0x157fb7142`, with no replacement table or candidate supplied. The completed key calculation and its field semantics remain unresolved.

A distinct call at `0x170b58556` also receives the header. It reaches original PE code at `0x15516256a`, reads header +0x14 and follows the same two nested pointer offsets. It supplies a second direct consumer of the storage layout. The exact-displacement scan found 1,505 decoded references to the sampled header fields, with no direct RIP-relative store among them. An indirect initializer remains possible. The +0x48 fallback still uses the separate asset tag at owner +0x40. These findings establish the +0x30 key validation path and do not identify the writer of that asset tag.

Private reports are `row7-owner-key-wrapper-0x170863c50.json`, `row7-owner-continuation-0x16f649100.json`, `row7-owner-continuation-0x16f649126.json`, `row7-owner-continuation-0x170b5854f.json`, and `row7-owner-30-table-xrefs.json`. The wrapper capture uses the checked parent overlay with `--start 0x170863c50 --target 0x170863c5e --rcx 0` and the standard TLS and dispatch tracing. The next useful target is the initializer reached through an address-taking reference to `0x174534e50`, or a later checkpoint containing both its root pointer and table base.

## Holder cleanup reverses callback registration and context publication

The holder's +0x20 method `0x1706e8bb0` reads holder +8 at `0x1489aba69`. The checked parent overlay has a null owner and follows the empty branch to `0x1706e8c52`. The recovered nonempty cleanup block at `0x1706e8bf1..0x1706e8c3b` contains calls that reverse the constructor's setup. Three of those calls were independently executed against the unchanged parent overlay:

| Call site | Entry | Verified effect |
| --- | --- | --- |
| `0x1706e8bf1` | `0x16f705ac0` | Invokes the pointer cleanup for `0x1767f33c0`. The zero store at `0x16f3f4cae` clears the global initialized by the second post-publication setup call. The input pointer was already null in this overlay. |
| `0x1706e8bf6` | `0x17038eb40` | Loads index `0x2a` at `0x15ee50526` and clears the entire 0x70-byte callback record at `0x17679df00`. The index instruction and four vector stores at `0x14ebb91a2..0x14ebb91b0` match the original PE. The completed replay uses the existing bounded AVX support and makes no CRT import calls. |
| `0x1706e8bff` | `0x1714b05e0` | Clears the published context global `0x1767f3338`. The store at `0x155aeca17` matches the original PE, and the entry replay records the zero write before returning. |

The recovered caller passes owner +8 to the last call. The clear helper itself ignores that argument. The following code examines owner +0x28, runs the conditional pointer-decoding path, and calls the pointer cleanup helper with owner +0x28 and owner +0x10. In abbreviated pseudocode, omitting intervening calls:

```c
// Selected calls in the holder's nonempty cleanup block
clear_pointer_at_1767f33c0();
clear_callback_record(0x2a);
clear_published_context(owner + 8);
// Further cleanup of owner +0x28 and owner +0x10 follows.
```

The inverse operations establish the lifecycle relationship among the holder, callback slot 0x2a, and the context used by the slot 7 fallback. The whole nonempty branch was not run with an initialized owner. Its opening block reads another global at `0x174ecc440` before the protected transfer, and the call at `0x1706e8bec` separately reaches a missing object before these clears. No owner was inserted to bypass either dependency.

A separate original-byte fragment at `0x156843f74` reads the adjacent DWORD at owner +0x44 through the same holder field. The tested wrapper at `0x1708a8e20` dispatches past that fragment, so its live caller and meaning are unresolved. When looking for the asset-tag writer, the constructor's single 64-bit sentinel store makes packed writes covering both +0x40 and +0x44 worth checking. The startup asset's adjacent tag and DWORD remain a layout clue.

Private evidence is `row7-source-owner-method-0x1706e8bb0.json`, `row7-tag-writer-entry-0x16f705ac0.json`, `row7-tag-writer-entry-0x1714b05e0.json`, `row7-tag-writer-avx-0x17038eb40.json`, and `row7-tag-field44-*.json`. Reproduce the three cleanup calls as independent entries using the checked parent overlay, standard TLS/dispatch tracing, and `--rcx 0 --target 0x730000000000`. Add `--stub-crt-basics` only to the vector-clear probe. The asset-tag writer is still open. Trace the object-dependent holder callbacks that read holder +8, or capture the first post-constructor write overlapping owner +0x40 in an initialized checkpoint.

## Holder callback writes the asset tag selected by reference

The holder's vtable at `0x172d88720` points to `0x16f9300f0` at +0x40. Its opening block at `0x158a3bd6f` loads RSI from holder +8. The decoded callback includes a direct store of the package lookup result to that object's +0x40 at `0x16f930180`. This is the same field the owner's +0x48 method `0x16efee9b0` reads through the holder. An independent original-PE fragment for the other selection path contains the same source and destination at `0x1617f175a..0x1617f175f`.

The default-selection continuation at `0x16f930160` reaches the call at `0x16f930179` with RCX = `0x1745269e0`, RDX = the stack output address, and R8D = `0x8080a1f5`. This was captured from the unmodified parent overlay with a null entry argument. The reference is the exact one carried by both independently extracted 1,914-row investment assets, startup `80A6A004` and retail `80AA2163`. The call to `0x1709929e0` initializes the output to -1, walks bucket-resolved packages, tests 24-byte candidate records, and returns the first selected record's leading DWORD through the output. The match path calls `0x16f471d60` with the resolved candidate and the reference. The candidate loop and assignment to the selected DWORD are visible at `0x170992b5d..0x170992b83`. For the current snapshot the lookup exits with the sentinel and the probe stops at the owner store with RSI zero and ECX = `0xffffffff`.

```c
// Selected path of holder vtable +0x40, 0x16f9300f0
owner = holder->pointer_at_08;
tag = find_asset_by_reference(default_asset_context, 0x8080a1f5);
owner->asset_tag_at_40 = tag;                 // 0x16f930180
// Later, method 0x16efee9b0 resolves this tag for slot 7.
```

The other branch reads a lookup result into owner +0x44, resets +0x40 to -1 at `0x1486a6872..0x1486a687c`, and tests the optional context at `0x17679c568` before deciding between another lookup and the default context. The +0x48 method of the *holder* vtable is a distinct callback at `0x170ff3620`. It loads the same holder +8 pointer into RBX and contains a paired reset of +0x40 and +0x44 at `0x15ffc84ea`. This should be kept separate from the +0x48 method of the *published owner* vtable, which resolves the selected tag.

Across all 222 saved synthetic checkpoints covering the two addresses, holder +8 at `0x174f6f240` and published context at `0x1767f3338` are zero. Five earlier partial checkpoints lack the requested regions. Consequently the saved states verify the search path and sentinel but do not contain a successful tag selection or a watchable owner allocation. The native callback can select by the reference of the preserved tables. Which concrete asset tag it selects in a populated client context, and which startup or mode transition calls the holder method with a live owner, remain open.

Reproduce the comparison with `scripts/compare_bitset_context_checkpoints.py <analysis> --address 0x174f6f238 --size 18` and `--address 0x1767f3338 --size 8`. Its previous bucket-selector output was checked against the existing report and has identical byte groups and counts. Reproduce the lookup argument capture with the checked parent overlay, standard TLS/dispatch tracing and `--start 0x16f930160 --target 0x16f930179 --rcx 0`. Continue past the call without seeding the owner to reproduce the sentinel stop. Private evidence is `row7-saved-globals-*.json`, `row7-holder-query-args-0x16f930160.json`, and `row7-holder-callback-*.json`. The next narrow target is how the default context at `0x1745269e0` acquires its package list, or a captured context containing either reference-matched asset.

## Default-context initialization subscribes to startup globals

The default context begins with original vtable `0x172d41af0`. Its +8 entry is `0x1715a8710`. A targeted entry with RCX equal to the actual static context `0x1745269e0` reaches original PE code at `0x1472f815d`, which zeroes the count at context +8. The same block clears +0x1410 and the byte at +0x14d8. All 222 covering checkpoints have the same first 32 bytes, including zero count. This gives a concrete reason why the previously traced default lookup has no active package candidates in these states.

The initializer proceeds through registration helper `0x1715a7d30`. Its bounded replay writes callback `0x17188b7a0` at `0x178f77ad0` and registration flags `0x3098` at `0x178f1a260`. The writer at `0x149008298` indexes callbacks by the schema discriminator in ECX. Here ECX is `0xb61c`, the low 16 bits of the independently extracted startup-globals reference `8080B61C`. The path is observed through the registration stores, then reaches `GetCurrentProcess` in protected code. The import was left unresolved. The original-byte index and store instructions independently corroborate the recorded registration.

The callback itself dispatches on EDX at `0x160c8fa7d..0x160c8fa92`. Targeted entries with operation values 3, 4, and 7 and null object arguments establish three local branches. Operation 3 bucket-resolves the asset identifier passed in R8D, reads the resolved object's count at +8, and loops over 24-byte relative entries from +0x10. For each entry it calls `0x170bcb530` with EDX = -1. Operation 4 resolves the same R8D identifier and uses an additional relative field at +0x20. Operation 7 examines the default-context count. The supplied operation constants are branch-selection probes, not captured event calls. Their event names and real invocation arguments remain unknown.

```c
// Selected operations of 0x17188b7a0, operation 3
startup = resolve_asset(asset_tag_in_r8d);
for (int index = 0; index < startup->count_at_08; ++index) {
    entry = relative_entry(startup, 0x10, index, 24);
    process_reference_at_170bcb530(entry, -1);
}
```

Two independently decoded native blocks maintain the context's count directly. `0x15b687083` stores a new count and writes an identifier at context +0xc + 4 * index, with additional parallel bookkeeping. `0x15b7c5abd` decrements the count. The insertion block's original-byte contract is established, but its calling path from this callback is still open. The callback's reference helper accesses entry +8 before proceeding into other object-dependent code. Its full relation to the insertion block has not been observed.

The recovered path now connects the default context's own initialization to startup-globals schema registration and identifies a callback that consumes that asset's relative array. This supports investigating startup asset `80A6A052` as the context source. It does not yet prove that its authored investment reference at +0x60 becomes a specific context entry. The next narrow step is to map operation 3's entry layout against the extracted startup bytes and recover how `0x170bcb530` registers or loads each referenced asset.

Private evidence is `row7-default-context-xrefs.json`, `row7-default-context-checkpoints.json`, `row7-default-context-bounded-0x1715a8710.json`, `row7-default-context-entry-*.json`, and `row7-default-callback-op{3,4,7}-0x17188b7a0.json`. Reproduce the initializer with the checked parent overlay, standard TLS/dispatch tracing and `--start 0x1715a8710 --rcx 0x1745269e0 --count 12000 --target 0x730000000000`. This is an isolated call on a copy of checkpoint memory. No allocator result, asset mapping, or callback object was fabricated.

## Startup operation 3 reaches the authored investment reference

The exact original-PE address calculation at `0x15d063889..0x15d06389b` is `base + relative_at_10 + (3 * index + 5) * 8`. Applying it to the digest-verified 676-byte startup asset `80A6A052` gives 24 entries starting at file offset 0x48, with a 24-byte stride and end 0x288. Entry 1 is the tag `80A6A004` at offset 0x60. This independently joins the previously discovered literal reference to the array the registered native callback enumerates. All 24 entries have flag DWORD 1 at +4 and a zero qword at +8 in the extracted bytes.

The reference helper `0x170bcb530` reads that +8 qword at `0x150a47ff8`. When it is zero, the native continuation `0x170bcb5bd` compares the entry's tag with -1. Its protected return fragment at `0x1466a53c5` returns the comparison as `setne al`. Thus the verified zero-qword path only reports whether the reference tag is present:

```c
// Selected original-byte path of 0x170bcb530
if (entry->field_08 == 0)
    return entry->tag != UINT32_MAX;
// The nonzero branch examines additional runtime objects.
```

This path supplies no insertion into the context array. It changes the next target to callback operation 4, whose loop and extra relative field at +0x20 have already been located, or the nonzero +8 reference path in a captured runtime context. The operation-3 entry enumeration is established from the original native arithmetic and the authored asset. A loaded runtime version of the asset, the operation's event name, and which event actually grows the context remain unknown.

The read-only inspector `scripts/inspect_row7_startup_references.py` requires the exact preserved asset digest, validates the array bounds, emits every entry offset and tag, and checks the investment entry against the independently extracted offset. Reproduce with `python scripts/inspect_row7_startup_references.py D:/Marathon-preservation/analysis/row7-service-table-assets/80A6A052.bin`. Its result is saved privately as `row7-startup-native-reference-layout.json`. A control run with the investment-table file is rejected by the digest gate. Private helper probes are `row7-startup-reference-fragment-0x170bcb5c0.json`, `row7-startup-reference-fragment-0x170bcb5b3.json`, and `row7-startup-reference-fragment-0x170bcb5a0.json`. The last two stop at object accesses and establish only their local instruction contracts.

## Startup operation 4 marks reference eligibility in the asset's tail

Operation 4 continues at `0x17188b8b3` after resolving its R8D asset identifier. It obtains a relative qword from asset +0x20 at original-PE instruction `0x14f8cef65`. For a nonzero value it sets the mask base to `asset + 0x30 + relative`. The loop at `0x17188b8d4..0x17188b951` processes the same 24-byte references used by operation 3. It checks each reference and calls `0x16fec2410`, `0x16efd1d80`, and `0x1708d04e0` along the eligible path. These helper names remain analyst-neutral because the event and state meanings are unresolved.

The last helper reads the bucket record's DWORD at +4. The original-PE continuation at `0x15b90da5e` masks its result with 0xf000 and compares it with 0x2000. The matching branch reaches the original-PE bit writer at `0x14dcf7122..0x14dcf7137`. ESI is the reference index and EBP was initialized to 1 in the loop setup. Its local behavior is:

```c
// Selected operation-4 mask update
if ((read_bucket_record_flags(reference.tag) & 0xf000) == 0x2000)
    mask[index >> 5] |= 1u << (index & 31);
```

Other reference and state predicates precede this update. Isolated fragment probes reach their actual object accesses and stop when the reference object is absent. No ready state or mask value was supplied. The bit-update semantics are established by original-byte disassembly and arithmetic, not by a completed runtime callback.

For preserved startup asset `80A6A052`, the +0x20 relative value is 0x270, placing the mask at file offset 0x2a0. One DWORD covers all 24 references and ends exactly at the 676-byte asset's boundary. That DWORD is zero in the extracted asset. Investment reference `80A6A004` corresponds to bit 1. The inspector now bounds-checks this mask and emits its words and each entry's bit. The checked result has no set bits.

The initializer also registers callback `0x17188ba00` for discriminator 0x890b, observed in `row7-default-context-entry-0x1715a8763.json`. Its body resolves the incoming R8D asset identifier and tests the operation against 3. Its operation-3 branch at `0x17188ba53` calls the same reference helper on resolved asset +8. The later branch accesses a separate object-dependent field. Neither branch has yet been joined to the default-context count writer. Thus operation 4 explains the startup asset's trailing bitmask, while the context insertion path remains a distinct open edge.

Private evidence includes `row7-startup-op4-fragment-*.json`, `row7-startup-op4-original-disassembly.txt`, `row7-context890b-entry-0x17188ba00.json`, and `row7-context890b-fragment-*.json`. Re-run the startup inspector with the prior command to verify the mask offset, zero words, and investment bit. The next useful target is the caller that reaches insertion block `0x15b687083`, or the nonzero runtime reference object consumed by the registered schema callbacks.

## An explicit input list enables a second context mode

A full-text scan finds 106 direct-call candidates for the default-context getter `0x16fc2ae60`. The caller at `0x17123f0dc` passes the getter result to `0x16f704a90` with a stack input address in RDX. Later in the same decoded caller, `0x17123f0f9` obtains the default context again and calls `0x16ff1ddb0`. The latter clears byte context +0x14d8.

An isolated entry into `0x16f704a90` with the real static context address observes the corresponding byte set to 1 at original-PE instruction `0x15f2d01a6`. The function then consumes the input list addressed by RDX. It sets up a loop with constant 6 and destination context +0x14ec. The recovered continuation at `0x16f704b00` copies an input DWORD into context +0x14dc and writes -1 at +0x14e0 before bucket-related work. With RDX zero the probe stops at that first input read. The input tags, full six-item transformation, and later helper calls remain unverified.

```c
// Verified selected operations
begin_at_16f704a90(context, input) {
    context->mode_at_14d8 = 1;
    // Reads input and starts filling fields at +0x14dc.
}
end_at_16ff1ddb0(context) {
    context->mode_at_14d8 = 0;
}
```

The asset-reference lookup `0x1709929e0` already tests this exact byte at original-PE instruction `0x15a23b42f`. The zero branch at `0x170992a18` enters the previously recovered count/bucket search. A nonzero byte instead selects the separate path at `0x1709929fd`. The flag therefore distinguishes lookup paths. It is not sufficient to treat it as a completed-initialization flag. This provides a second concrete route to recover meaningful asset selection using supplied runtime inputs, alongside finding who populates the default list.

Private reports are `row7-default-context-getter-callers.json` and `row7-context-mutation-candidate-{0x16f704a90,0x16ff1ddb0,0x17123f0dc}.json`. The observed byte writes target `0x174527eb8`. No input tags or mode byte were substituted to force the reference lookup.

The direct reverse search for insertion block `0x15b687083` remains incomplete. The new read-only `scripts/find_protected_return_callers.py` evaluates one exact push/stack/EAX return-adjustment template against the digest-checked reconstructed text. For payload entry `0x15b687025`, it finds 1,849,267 signature candidates and decodes 1,101,256 stubs with the supported operations. None provides a matching direct call to the arithmetic stub. Allowing an unverified wrapper produces 7,893 candidates, which are not treated as control-flow edges. Private results are `row7-insertion-computed-callers.json` and `row7-insertion-wrapper-candidates.json`. This rules out the supported direct template as the complete incoming edge. Following all wrapper candidates would require a broader control-flow investigation, so the stronger next target is the nonzero-mode lookup and the concrete input-list caller.

## REA recovers the alternate lookup's 24 type-to-tag pairs

The actual PE unwind row covering `0x17123f0dc` begins at `0x17123efa0` and ends at `0x17123f11b`. Entering at that function's start recovers its real frame and input preparation, avoiding the absent frame of the earlier mid-function probe. Original PE code at `0x14de79934` onward reads schema identifiers through existing globals into the stack array passed to `0x16f704a90`. No identifiers were supplied as arguments. A bounded replay reaches `0x17123f0ed`, immediately after the helper returns, with all 48 DWORD writes to the alternate table recorded.

The input consists of **24 schema references**, not six asset tags. The earlier constant-six setup is a loop unrolled four times. The native loop stores 24 eight-byte pairs at context +0x14dc. Each pair has a schema reference at +0 and a selected asset tag at +4. The captured pair at index 14 is `8080A1F5, FFFFFFFF`, at globals `0x174527f2c` and `0x174527f30`. Every selected-tag field is -1 in this run. After initializing the pairs, the helper inspects the default context's candidate count and takes the zero-count path.

The nonzero-mode reference lookup uses these pairs directly. Original PE code at `0x15603161d` compares the requested reference with context +0x14dc + 8 * index and bounds the index at 0x18. The match continuation `0x170992b0f` reaches original PE code at `0x14b32ab58`, which copies the paired DWORD from context +0x14e0 + 8 * index to the caller's output. The output was initialized to -1 by the lookup entry. Selected reconstructed pseudocode is:

```c
// 0x1709929e0, alternate-mode path
*output = UINT32_MAX;
if (context->mode_at_14d8) {
    for (int index = 0; index < 24; ++index) {
        if (context->pairs_at_14dc[index].reference == requested_reference) {
            *output = context->pairs_at_14dc[index].asset_tag;
            break;
        }
    }
    return output;
}
// The existing default candidate/bucket search follows when the mode is zero.
```

REA with Ghidra 12.1.4 decompiled four selected fragments from a new static sparse PE view containing the existing recovered pages at their original addresses. Its output independently confirms the paired-result read, mode clear, and the four-way initialization loop. The compare fragment truncates on its protected nonmatch edge. The pseudocode above therefore combines REA's fragment results with the original instructions and bounded continuation evidence, rather than claiming whole-function decompilation.

The private view is `row7-rea-slices/row7-mode-analysis-view.exe`. Its page manifest preserves source filenames, page digests, and the analyst export labels. Complete REA output is `row7-mode-rea-evidence.json`, with snapshot `row7-mode-rea-snapshot.json` in the same directory. The existing images were reused without applying any new transformation. The view was analyzed statically.

Reproduce the decisive capture with the checked parent overlay, standard TLS/dispatch tracing, and `--start 0x17123efa0 --target 0x17123f0ed --rcx 0 --count 2000`. Evidence is `row7-context-mode-pre-body-0x17123efa0.json`. Inspect the 48 four-byte writes in `0x174527ebc..0x174527f78`. The caller's next operation at `0x17123f0f4` enters `0x170af6e20`, then its decoded path clears the mode at `0x17123f101`. A longer capture stops later on a missing object in that operation, so the complete caller is not verified through return. The next narrow target is how the nonempty default candidate list fills the paired tags after initialization, or which runtime activity supplies that list. This is the remaining prerequisite for an actual `8080A1F5` asset selection.
