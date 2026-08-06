# FCMP value balance — design

Status: **design, not implemented.** Written 2026-08-04 on branch
`fcmp-amount-layer-ed25519` (head `c4945579`), before any spend-path code.

This document defines how value is conserved across the WATTx shielded (FCMP)
set: what the ledger invariant is, where transparent coin and shielded notes
meet, what consensus must check, and what the wallet must construct. It exists
because `sendfcmp` currently emits a transaction with no inputs, and fixing that
by "attaching the payload somewhere" without first settling the accounting model
is how a chain ships silent inflation.

Scope: the amount/value layer only. Membership (curve tree), spend authorization
(SA+L), and key-image double-spend rules are treated as dependencies with stated
requirements, not redesigned here.

---

## 1. Where things actually stand

Verified by reading the tree at `c4945579`.

**Works.** `shieldfcmp` confirms a note into the curve tree (`tree_size 0 -> 1`).
The ed25519 amount layer (`src/privacy/confidential_ed25519.cpp`) is written and
unit-tested: 33-byte tagged commitments (`0x0E` + compressed point), audited
Bulletproofs+ via `bpplus_api.h`, real single-group balance, blinding
balancing.

**Does not work.** Everything that would let value leave the shielded set. The
defects below are all live in the tree today; the design in §3–§6 is what
replaces them.

| # | Defect | Location |
|---|---|---|
| D1 | `ToTransaction()` walks `privacyInputs` (the *RingCT* vector) and ignores `fcmpInputs` entirely — an FCMP tx therefore serializes with `vin: []` and no witness payload. `DecodeFcmpTransaction` looks for the `FCMP` tag in a witness, finds nothing, and **every** FCMP consensus check is skipped. | `privacy.cpp:495-527`, `fcmp_consensus.cpp:739` |
| D2 | **The shielded set has no backing.** `shieldfcmp` pays the value to an ordinary wallet-controlled bech32 address and *additionally* publishes an `OP_RETURN` note (`rpc/privacy.cpp:708-713`). The transparent coin is still spendable. Separately, `ConnectBlock` adds a tree leaf for *any* `OP_RETURN` carrying the `FCMP` marker, with no value check and no cost (`fcmp_consensus.cpp:240-258`, `ExtractFcmpOutputs` at `:608`). Anyone can mint a note committing to any amount. | `rpc/privacy.cpp`, `fcmp_consensus.cpp` |
| D3 | The wallet tags commitments `0x02` (`fcmp_wallet.cpp:161, 212, 1212`); the ed25519 layer requires `0x0E` and deliberately rejects `0x02` as a legacy secp256k1 commitment (`confidential_ed25519.cpp:55, 82-88`). Nothing the wallet builds can pass consensus. | both |
| D4 | The wallet never balances blindings (every output gets `Scalar::Random()`) and never produces a range proof. Because `CConfidentialOutput::IsValid()` requires a non-empty `rangeProof` (`confidential.h:153`), `VerifyFcmpSelfCheck` collects **zero** output commitments and the balance check it claims to perform is skipped — it passes vacuously. That is why `sendfcmp` returns a txid at all. | `fcmp_wallet.cpp:154-220, 249`; `privacy.cpp:477-489` |
| D5 | Rerandomization is wrong twice. `C_tilde = C + r*H` adds to the **value** generator, changing the committed amount by `r`; and the same scalar `r` rerandomizes `O`. Then the published `pseudoOutput` is the **un-rerandomized** `C` (`fcmp_wallet.cpp:1206-1217`), which is a byte-for-byte copy of a public tree leaf — it identifies the note being spent and destroys the anonymity the membership proof provides. | `fcmp_wallet.cpp:1160-1217` |
| D6 | Two different balance checks disagree. `VerifyFcmpBalance` (`fcmp_tx.cpp:334`) blindly strips a prefix byte with no tag or curve-point validation and adds `fee*H` unconditionally; `VerifyCommitmentBalance` (`confidential_ed25519.cpp:183`) validates the tag and the point and takes the fee as an optional commitment. `CheckFcmpTransaction` calls the second, `CheckFcmpInputs` calls the first. | both |
| D7 | The SA+L message differs between signer and verifier: the wallet signs `ComputeMessageHash(inputs, recipients, fee)` (`fcmp_wallet.cpp:1222`), consensus verifies against `Hash(tx.GetHash())` (`fcmp_consensus.cpp:527-530`). No wallet-built input can ever verify. | both |
| D8 | `CheckFcmpInputs` step 4 (`fcmp_consensus.cpp:563-581`) demands a per-output BP+ proof on **every** `privacyOutput`, including transparent/deshield outputs that carry no commitment, and passes the proof blob *including* its `0x02` version byte to `wattx_bpplus::verify`, which `VerifyAggregatedRangeProof` strips. Correctly-formed proofs fail; transparent outputs are impossible. | `fcmp_consensus.cpp` |

D2 is the one that matters most. D1 is a blocker; D2 is a bug that *only becomes
exploitable once D1 is fixed*, and it is unlimited-inflation class. The spend
path must not be finished before the accounting model below is in place.

---

## 2. Notation and invariant

All amount-layer arithmetic is ed25519, Monero convention, as already
implemented in `src/privacy/ed25519/pedersen.cpp:108`:

```
C = v·H + b·G        v = amount (satoshi), b = blinding scalar
                     H = Monero value generator, G = ed25519 base point
```

Definitions for one transaction:

- `C_out,j` — commitment of shielded output *j* (a new tree leaf).
- `C~_in,i` — the **rerandomized** commitment published for shielded input *i*
  (§4). This, not the leaf's `C`, is the pseudo-output.
- `Δ` — the **pool delta**: the net transparent value the shielded set gained in
  this transaction, a signed integer computable by every verifier from the UTXO
  view (§3).

**Ledger invariant.**

```
Σ C~_in,i  +  Δ·H  ==  Σ C_out,j                          (VB)
```

with `Δ` signed: `Δ > 0` for a shield, `Δ < 0` for an unshield or for a
shielded-paid fee, `Δ = 0` for a pure shielded transfer whose fee is paid
transparently.

(VB) holds on the curve exactly when **both** the values conserve and the
blindings conserve. `Δ·H` carries zero blinding by construction, so the sender is
required to arrange `Σ b_out = Σ b~_in`; that is the wallet's job (§5), not a
consensus concession.

Total supply is then conserved by two independent mechanisms that never have to
trust each other:

1. the transparent layer, unchanged, via `Consensus::CheckTxInputs`;
2. (VB), which pins the shielded set's value change to exactly the transparent
   value that moved into or out of the pool.

No consensus rule anywhere is permitted to create coin.

---

## 3. Where transparent coin and shielded notes meet

This is the decision the rest of the design hangs on. Two models were
considered.

### Model B — burn and mint (Zcash `valueBalance` shape)

Shielding burns transparent value (an `OP_RETURN` output whose `nValue` is
counted by `GetValueOut` but which is unspendable); unshielding *mints* it back
by letting an FCMP transaction's outputs exceed its inputs by the unshielded
amount.

This is the model the shielded **coinbase** already uses today:
`CreateFcmpRewardOutput` (`src/node/miner.cpp:192`) emits an `OP_RETURN` with
`nValue = reward` — burned at the UTXO level, recreated as a note.

- **Against:** the mint requires an exemption inside `Consensus::CheckTxInputs`,
  the single most safety-critical function in the codebase. Any bug there is
  direct supply inflation. It also breaks `gettxoutsetinfo` as a supply audit —
  total supply becomes "UTXO set + a counter maintained by the FCMP subsystem",
  and the counter is exactly the thing an attacker attacks.

### Model P — the pool as a real UTXO (**recommended**)

The shielded set is backed by ordinary UTXOs paying to a single reserved
**pool script**. Shielding pays into it; unshielding spends it; a pure shielded
transfer spends a pool UTXO and pays the same value (less fee) straight back.

```
Δ  =  Σ value(pool outputs created)  −  Σ value(pool UTXOs spent)
```

Both terms are read from the transaction and the coins view. Nothing is
declared by the sender, so nothing about `Δ` can be lied about.

- **For:** `CheckTxInputs` is untouched — the transparent layer already forbids
  outputs exceeding inputs, so no consensus path can ever create coin. The worst
  case for a bug in the FCMP logic becomes *theft from the pool*, bounded by the
  pool's balance, instead of unbounded inflation. `gettxoutsetinfo` stays honest:
  the pool UTXOs' total value **is** the shielded supply, publicly auditable
  against the tree at all times.
- **For:** it fixes D1 structurally rather than by patching. The transaction now
  has real `vin` (the pool UTXOs it spends), which gives it a witness to carry
  the FCMP payload and a txid that commits to every input and output.
- **Against:** the shielded coinbase must change from burn to pay-to-pool
  (`miner.cpp:192, 286, 413`).
- **Against:** concurrent FCMP transactions contend for pool UTXOs (§7).

**Decision: Model P.** The failure-mode argument is decisive for a chain whose
whole shielded story is currently gated behind a fail-closed anti-inflation
guard.

### Pool script and its rule

- One reserved scriptPubKey form, `POOL_SCRIPT`, height-gated at FCMP
  activation. It must be a **native witness program with an empty scriptSig**,
  so the txid is not scriptSig-malleable and the FCMP payload lives in a witness
  that the txid excludes (§4).
- Script-level, `POOL_SCRIPT` is anyone-can-spend. Its security comes from a
  consensus rule, exactly as segwit's did:

  > **Rule P1.** A transaction that spends any `POOL_SCRIPT` output MUST carry a
  > valid FCMP payload and satisfy every check in §6. A transaction that creates
  > a `POOL_SCRIPT` output MUST carry a valid FCMP payload.

  Enforced in `CheckFcmpInputs`, fail-closed: a pool-spending transaction whose
  payload fails to decode is invalid, never "not an FCMP transaction". This is
  the inverse of today's `DecodeFcmpTransaction` returning false and everything
  being skipped.
- Rule P1 also removes the free-leaf hole (D2): `ExtractFcmpOutputs` must stop
  adding leaves from bare `OP_RETURN`s. **New leaves come only from a
  transaction that satisfies (VB).** Note-bearing `OP_RETURN` outputs remain the
  *encoding* of a leaf, but a leaf is only added when the containing transaction
  passed the FCMP checks in the same block-connect pass.

### The four transaction shapes

`U` = ordinary user transparent value, `P` = pool value, `F` = fee.

| Shape | vin | vout | Δ |
|---|---|---|---|
| Shield (T→S) | user UTXOs | `POOL_SCRIPT` (V), note `OP_RETURN`s, change | `+V` |
| Transfer (S→S) | pool UTXO(s) (X) | `POOL_SCRIPT` (X−F), note `OP_RETURN`s | `−F` |
| Unshield (S→T) | pool UTXO(s) (X) | recipient (V), `POOL_SCRIPT` (X−V−F), note `OP_RETURN`s for change notes | `−(V+F)` |
| Shielded coinbase | — | `POOL_SCRIPT` (reward), note `OP_RETURN` | `+reward` |

The fee never needs its own term in (VB): a fee paid from the pool simply
shrinks `Δ`, and the miner collects it through the ordinary
`Σ vin − Σ vout` path. This deletes the whole `CreatePublicValueCommitment` /
zero-fee-identity-point special case from the consensus path (it stays useful in
tests).

**Implemented** as `GetShieldedPoolScript` / `IsPoolScript` / `ComputePoolDelta`
/ `SpendsPool` / `CreatesPool` in `fcmp_consensus.{h,cpp}`. The script is a
version-16 witness program over a fixed 32-byte domain-separated constant —
unassigned witness versions are anyone-can-spend to nodes that do not know the
rule, which is the softfork path segwit and taproot used.

### A consequence worth knowing before "improving" it

`Δ·H` carries no blinding. A **pure shield** has no shielded inputs to
contribute one, so its output commitments' blindings must sum to zero — for a
single output, exactly zero. Giving that output a random blinding, which looks
like an obvious privacy improvement, makes (VB) unsatisfiable and every shield
invalid.

This is not a privacy loss. A shield's amount is already public from the
transparent input funding it. The note becomes unlinkable when it is **spent**,
via `C~ = C + r_c·G`, and the membership proof is what hides which leaf that was.
If hidden shield amounts are ever wanted, the fix is a Zcash-style **binding
signature** proving knowledge of the blinding sum — not a random blinding here.
Pinned by `pool_balance_shield_output_must_have_zero_blinding`.

Transparent conservation `Σ P_in + Σ U_in = Σ P_out + Σ U_out + F` is enforced by
existing code and is not restated in FCMP logic.

---

## 4. Wire format and binding

**Payload location.** One item in the witness stack of `vin[0]` (which must be a
pool input for any shielded-spending shape): `"FCMP"` marker (`46 43 4D 50`)
followed by the serialized `CPrivacyTransaction`. This keeps
`DecodeFcmpTransaction`'s existing shape (`fcmp_consensus.cpp:739`) and, because
witness data is excluded from the txid, lets the SA+L signature commit to the
txid without circularity.

**Anti-malleability.** `POOL_SCRIPT` being anyone-can-spend means a third party
could try to rewrite a pool-spending transaction's outputs. That changes the
txid; the SA+L signature commits to the txid; the rewrite fails Rule P1. Hence:

> **Rule P2.** The SA+L message is exactly `tx.GetHash()` (the txid), computed
> identically by wallet and consensus.

This is the fix for D7, and it is load-bearing for pool security, not a
cosmetic cleanup. `ComputeMessageHash` (`fcmp_wallet.cpp:1222`) is deleted.

**Commitment encoding.** 33 bytes, `data[0] = 0x0E`, per
`confidential_ed25519.cpp`. Every wallet site currently writing `0x02` (D3) is
changed to go through `privacy::CreateCommitment` rather than hand-rolling the
buffer. `VerifyFcmpBalance` (D6) is deleted in favour of the tag-validating
`VerifyCommitmentBalance`.

**Range proof.** One aggregated BP+ proof over all shielded outputs, in
`CPrivacyTransaction::aggregatedRangeProof`, tagged `0x02`, verified only
through `VerifyAggregatedRangeProof` (which strips the tag). Per-output proofs
stay optional; the D8 loop that demands one per output and mishandles the tag is
replaced.

**Note encoding.** Unchanged `OP_RETURN` `FCMP` + `O` + `I` + `C` (+ `R` for the
coinbase form). `C` here MUST be the same commitment covered by the aggregated
range proof and counted in (VB) — one commitment, one place.

---

## 5. Wallet construction

For a spend of notes `{(v_i, b_i, leaf_i)}` to shielded outputs `{v_j}` with
pool delta `Δ`:

1. **Select pool UTXOs** covering the transparent leg (§7), and select the
   shielded notes to spend.
2. **Rerandomize each input.** Draw *independent* scalars `r_o,i` and `r_c,i`:

   ```
   O~_i = O_i + r_o,i·G
   C~_i = C_i + r_c,i·G          ← G, the blinding generator, NOT H (fixes D5)
   b~_i = b_i + r_c,i
   ```

   `C~_i` is the pseudo-output. It commits to the same value `v_i` under a fresh
   blinding, so it is unlinkable to the leaf. Publishing `C_i` itself, as the
   code does today, is a privacy break, not a stylistic issue.
3. **Assign output blindings** so that `Σ b_out = Σ b~_in`: draw all but the last
   at random, then set the last via `BalanceBlindingFactors`
   (`confidential_ed25519.cpp:135`) using `{b~_i}` — the rerandomized blindings,
   which is why step 2 must hand them back.
4. **Build final commitments** with `CreateCommitment` (tag `0x0E`) — including
   recomputing the last output after its blinding was fixed.
5. **Prove range** over the FINAL commitments with `CreateAggregatedRangeProof`.
   Proving before step 4 produces a proof bound to a commitment the transaction
   does not carry.
6. **Assemble the transaction**: pool inputs, pool output, note `OP_RETURN`s,
   transparent recipient/change outputs. The txid is now fixed.
7. **Sign SA+L** over `tx.GetHash()` (Rule P2), and generate the membership
   proofs, passing `r_o,i` and `r_c,i`.
8. **Attach** marker + serialized payload to `vin[0]`'s witness.
9. **Self-check** by running the §6 verifier — the real one, not a weaker
   variant. `VerifyFcmpSelfCheck`'s current "collect commitments, find none,
   pass" behaviour (D4) is what let a broken transaction reach the wire; the
   self-check must fail closed on an empty commitment set whenever shielded
   outputs exist.

`ToTransaction()` (D1) is rewritten around this: for `PrivacyType::FCMP` it
emits the pool inputs and the transparent/note outputs above. Today it reads
`privacyInputs`, which FCMP never populates.

**Wallet state.** `sendfcmp` currently marks notes spent and adds change notes
even when the transaction never entered the mempool (`rpc/privacy.cpp:497-515`).
Wallet FCMP state must be mutated only after `CommitTransaction` succeeds, and
reverted on rejection.

---

## 6. Consensus verification

One function, one order, fail-closed at every step. It replaces the split
between `CheckFcmpTransaction` (context-free) and `CheckFcmpInputs` (contextual)
only in so far as `Δ` needs the coins view; the context-free half keeps the
structural checks.

Given `tx`, coins view, tree root:

1. **Classify.** `spendsPool = any input spends POOL_SCRIPT`;
   `createsPool = any output is POOL_SCRIPT`; `hasPayload = DecodeFcmpTransaction`.
   If `(spendsPool || createsPool) != hasPayload` → **reject** (Rule P1). A
   decode failure on a pool-touching transaction is a rejection, never a skip.
2. **Structure.** Every input: key image non-null and unspent, tuple points on
   curve, membership proof non-empty, `C~` a valid `0x0E` commitment. No
   duplicate key images. (Largely today's checks.)
3. **Membership + authorization.** For each input, membership proof verifies
   against the current tree root and the SA+L signature verifies over
   `tx.GetHash()`.
4. **Range.** `VerifyAggregatedRangeProof(outputCommitments, aggregatedRangeProof)`
   over exactly the shielded outputs. Missing or wrong-tag proof → reject.
   Transparent outputs inside an FCMP transaction contribute no commitment and
   require no proof (fixes D8).
5. **Compute Δ** from the coins view: pool value created minus pool value spent.
   Reject if `|Δ| > MAX_MONEY`.
6. **Balance (VB).** With `L = Σ C~_in`, `R = Σ C_out`, and `|Δ|·H` added to
   whichever side `Δ`'s sign dictates, require `L − R == identity`. Use
   `Point::IsIdentity()` rather than a byte compare, and branch explicitly on the
   sign of `Δ` rather than relying on signed-scalar arithmetic.
7. **No shielded outputs, no shielded inputs** in a pool-touching transaction →
   reject (nothing to balance).

`Δ = 0` with no shielded inputs and no shielded outputs is not a valid FCMP
transaction; it is a transparent one and must not carry a payload.

### Soundness dependency — RESOLVED 2026-08-04, with two prerequisites

(VB) proves nothing unless the membership proof **binds `C~_i` to the leaf's
`C_i` under the published rerandomizer**. If an attacker can present any `C~` of
their choosing alongside a valid membership proof for some leaf, they can commit
to any value they like and (VB) balances trivially — unlimited inflation with
every check green.

**The binding holds — in `fcmp_prove_full`.** That function
(`rust/src/lib.rs:901`) is the real Monero pipeline:
`RerandomizedOutput::new` draws the four blinds, `CBlind::new(g_pt, …)` commits
`r_c` *inside* the Generalized-Bulletproofs FCMP, and the `C~` it returns
(`monero_input.C_tilde()`, `:1067`) is the value `fcmp_verify_full` checks
against the tree root. `CBlind` over `g_pt` also confirms §5.2 independently:
rerandomization is on **G**, so `C~ = C + r_c·G` and the value is preserved.
The four blinds are independent, so the D5 scalar reuse has no counterpart here.

Two prerequisites follow, and both must land before the balance code:

- **P-a. The wallet does not call it.** `FcmpProver::GenerateProof`
  (`fcmp_wrapper.cpp:12`) calls the *old* `fcmp_prove` — the Schnorr-sigma
  scaffold at `rust/src/lib.rs:581` — and `BuildFcmpInput` computes its own
  `O~`/`C~` from its own single rerandomizer. The tuple the transaction
  publishes is one the real prover never saw, so nothing about it is bound to
  anything. The wallet must be moved onto `fcmp_prove_full` / `fcmp_verify_full`
  first; without that, every check in §6 verifies a proof about a different
  object than the one being balanced.
- **P-b. `r_c` is not exported.** `fcmp_prove_full` generates all four blinds
  internally from `OsRng` and returns only `key_image` and `c_tilde`. The wallet
  needs `r_c` to form `b~_i = b_i + r_c,i` and balance the output blindings
  (§5.3) — without it, (VB) is unsatisfiable by an honest sender. Add a
  `c_blind_out` (32 bytes) out-param to `fcmp_prove_full` and to
  `fcmp_ffi.h:273`, or have it accept a caller-supplied `c_blind`. Small change,
  hard prerequisite.

Note also that `fcmp_prove_full` takes the whole leaf set (`num_leaves`, capped
at 38) rather than a tree branch — it is a **one-layer** tree today. The
anonymity set is therefore ≤38 outputs, not the full chain, until
`curve_1_layers`/`curve_2_layers` are populated. That is an anonymity limit, not
a value-balance one, and does not block this design.

### P-c. The consensus curve tree is on the wrong curve — BLOCKER

Found 2026-08-04 while implementing P-a. This is larger than P-a and P-b and
gates both.

`fcmp_verify_full` needs the tree root as a compressed **Selene** point
(`TreeRoot::C1`, `rust/src/lib.rs:1120-1129`); `fcmp_compute_leaf_root` builds
one as `SELENE_HASH_INIT() + multiexp(…)` over the ed25519 points' **(x, y)
coordinates** against `SELENE_GENERATORS`.

The C++ tree produces an **ed25519** point. `CurveTree::ComputeNodeHash`
(`curve_tree.cpp:432`) takes child ed25519 points, reduces their compressed
bytes mod the ed25519 group order into ed25519 scalars, and Pedersen-hashes them
back to an ed25519 point. `CFcmpProof::treeRoot` is an `ed25519::Point`
(`fcmp_tx.h:112`) and consensus compares against `m_curveTree->GetRoot()`
(`fcmp_consensus.cpp:542`), also ed25519.

These cannot be reconciled by patching call sites. The Selene/Helios 2-cycle is
load-bearing: a statement about one curve's coordinates is only efficiently
provable in a circuit over the *other* curve's scalar field, which is the entire
reason FCMP++ alternates them. Hashing ed25519 → ed25519 by reducing compressed
bytes mod order is not a curve-tree hash — it is not injective (distinct points
collide after reduction) and cannot be opened inside the Generalized
Bulletproofs circuit at all. **The C++ curvetree is a Merkle-ish Pedersen tree,
not an FCMP++ curve tree.** No amount of wallet-side change makes the real
prover and this tree agree.

Consequence: `fcmp_prove` (the Schnorr scaffold) is the *only* prover that can
talk to the current tree, and it proves nothing about `C`. Until this is fixed
the membership layer provides **no binding at all**, so (VB) rests on nothing —
which is precisely why Model P's bounded failure mode (§3) matters more, not
less.

Options, in increasing order of work:

- **C1 — port the tree.** The crate already exposes the needed primitives:
  `hash_grow` / `hash_trim` in `crypto/fcmps/src/tree.rs`, generic over
  `Ciphersuite`. Expose them over FFI for Selene and Helios and rebuild the
  node-hashing layer to alternate curves; tree storage must then hold both point
  types. The C++ `PedersenHash` already mirrors this API shape (`HashGrow`,
  `HashTrim`) — the interface was modelled on it and implemented on the wrong
  curve — so the surgery is porting, not research. Also lifts the ≤38 cap by
  populating `curve_1_layers` / `curve_2_layers`.
- **C2 — own the tree in Rust entirely.** Move tree state behind the FFI and let
  the C++ side keep only an index. Cleaner, larger, and changes the LevelDB
  layout.
- **C3 — ship shielded-in-only.** Keep the current tree, never enable spends.
  Not viable as privacy (§ the shield-only note in the memory file) and leaves
  the free-leaf hole live.

Either C1 or C2 must land before the amount layer can be sound. **Neither is
required for §3's pool backing**, which is independent of the membership layer
and remains the correct next change.

---

## 7. Pool UTXO policy

Model P's one real cost. Two FCMP transactions that pick the same pool UTXO
conflict, and the loser cannot simply be rebroadcast — its SA+L commits to a
txid that names that outpoint, so it must be rebuilt from scratch.

- Maintain **several** pool UTXOs rather than one. Every FCMP transaction
  already creates a pool output; a policy of splitting the pool output in two
  whenever the pool has fewer than *N* UTXOs (`N` ≈ 16) keeps parallelism up.
- Wallets must exclude pool outpoints already spent by a mempool transaction.
- Consolidation is free: any FCMP transaction may spend several pool UTXOs and
  create one.

This is a policy layer, not consensus. Consensus only cares about `Δ`.

---

## 8. Activation and rollout

- The window is still open: `getfcmpinfo` reports `tree_size: 0` on mainnet, so
  the format can change with no migration and no trapped funds. It closes the
  moment a real shielded user exists.
- `-fcmpamountlayer` (default off) stays the development switch. It must be
  replaced by a **height gate** before mainnet — a runtime flag means two nodes
  on the same height disagree on validity, which is a chain split by
  configuration.
- Pool script recognition, Rule P1, and the removal of free `OP_RETURN` leaves
  are all part of the same activation height.

---

## 9. Implementation status (2026-08-04)

| Step | State |
|---|---|
| Export `r_c` from the real prover (P-b) | **done** — `100c4a15`, 9/9 Rust tests |
| Pool script, Rule P1, `Δ`, free-leaf fix | **done** — `68603c31` |
| Transaction assembly, self-check, D3/D4/D6/D8 | **done** — `0b70f953` |
| Wallet onto the real prover (P-a) | **blocked on P-c** |
| Curve tree on the right curve (P-c) | **not started — decision needed (C1 vs C2)** |
| Pool UTXO selection in the wallet | not started |
| Height gate replacing `-fcmpamountlayer` | not started |

27 tests green (15 C++ `fcmp_pool_tests`, 12 Rust). The 19 failures in
`privacy_tests` are pre-existing and unrelated — they parse commitments as
secp256k1; verified identical before and after these changes.

**Still not spendable end-to-end**, by design rather than omission:
`CreateFcmpTransaction` returns `standardTx = nullptr` and an explicit error
instead of a txid for something that cannot confirm. Two things are missing —
pool UTXO selection (§7), and a membership proof that verifies against a real
tree root (P-c). The inflation hole is closed regardless: notes can no longer
enter the tree without pool backing.

### P-d. Blocks do not validate FCMP at all — PARTIALLY FIXED

Found 2026-08-05 while auditing for double-spends.

`CheckFcmpTransaction` and `CheckFcmpInputs` are called **only** from
`MemPoolAccept::PreChecks`. `Chainstate::ConnectBlock`'s sole FCMP call is
`GetFcmpState().ConnectBlock()`, which marked key images spent **without
validating them**. The per-transaction privacy hook in `ConnectBlock` covers the
older RingCT path, not FCMP.

So a transaction mined straight into a block — never entering any mempool —
faced no key-image check, no membership proof, no range proof and no balance
check. Two transactions in the *same* block could also carry the same key image,
since duplicates were rejected only within a single transaction and the mempool
check queries a database that does not yet contain the block's own spends.

`CFcmpConsensusState::ConnectBlock` now rejects a block that repeats a key image
or reuses one already recorded as spent. **That is only the double-spend half.**
Blocks still do not re-verify membership proofs, range proofs, or value balance,
because `ConnectBlock` has no coins view to compute Δ from. Full block-level
validation needs the coins view threaded through — design work, not a patch, and
a hard blocker alongside P-c.

### An outside data point

A Salvium developer reports a double-spend bug found in Monero's own FCMP++ work
in early August 2026, in migration-period code, and advises against independent
FCMP++ implementations: fork Monero classic, wait for FCMP++ on Monero mainnet,
let it settle, then hard-fork it in.

WATTx has no RingCT→FCMP migration, so that specific bug likely does not apply.
The general point does, and this document is evidence for it: a single session's
audit found an unbacked shielded set, a curve tree on the wrong curve that makes
membership proofs bind nothing, a vacuous self-check, a balance helper on the
wrong curve, a spend path that never worked, and the double-spend gap above.
Six critical defects, in code that looked finished.

## 10. Acceptance criteria

Design is not done until these pass; implementation lands in this order.

1. **Unit** — move the scratchpad suites (`ct_ed25519_test` 33 cases,
   `ct_flow_test` 11 cases) into `src/test/` as real unit tests, extended with:
   rerandomized-input balance, `Δ` of each sign, `Δ` mismatched against the
   transparent leg, a pool-spending transaction with a stripped witness, a
   replayed SA+L on a modified output set, and a note leaf offered by a bare
   `OP_RETURN`.
2. **Regtest E2E** — shield → transfer → unshield, each confirmed in a block,
   `tree_size` and pool UTXO value tracking each other at every step, and
   `gettxoutsetinfo` total supply unchanged across all three.
3. **Adversarial regtest** — each of the unit-test attacks above replayed
   against a live node, expecting a specific rejection reason string.
4. **Split test** — a node with the amount layer on and one with it off must
   split on the same FCMP block, deliberately and visibly. Then the same test
   against the height gate must **not** split.
5. **Second reviewer** on the balance and `Δ` code paths before the gate opens.
   The failure mode is silent, and it is unbounded.

---

## 11. Open questions

1. ~~**Membership proof binds `C`?**~~ Resolved 2026-08-04: yes, in
   `fcmp_prove_full`, which the wallet does not yet call. See §6 — prerequisites
   P-a (move the wallet onto the real prover) and P-b (export `r_c`) are now the
   first implementation steps.
2. **Shielded coinbase.** Model P requires it to pay into `POOL_SCRIPT` instead
   of burning into an `OP_RETURN` (`miner.cpp:192`). Do shielded coinbase
   outputs stay a feature at all, or does the miner pay transparently and let
   the user shield? Dropping it removes a whole class of consensus surface.
3. **Pool UTXO count `N`.** 16 is a guess; it trades mempool parallelism for
   UTXO-set noise.
4. **Deshield privacy.** An unshield reveals value and recipient. Denominated
   unshields would help, and would also make pool UTXO selection uniform. Out of
   scope here, but it interacts with §7.
