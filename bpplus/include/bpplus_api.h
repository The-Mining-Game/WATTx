// Clean, collision-free public API for libwattx_bpplus.
//
// This header exposes ONLY plain byte buffers — it does NOT pull in any Monero
// rct:: types, span.h, or crypto-ops headers — so WATTx consensus code (which has
// its own colliding span.h / crypto headers) can include it safely and link the
// isolated wattx_bpplus static library.
//
// Commitment convention (must match the wallet's fcmp_pedersen_commit): each
// commitment C is a 32-byte compressed ed25519 point equal to  v*H + b*G , where
// H is Monero's value generator and G the ed25519 basepoint. Monero's BP+ stores
// its proof commitment as V = C * inv8, so verification checks  C == 8*V .
#ifndef WATTX_BPPLUS_API_H
#define WATTX_BPPLUS_API_H

#include <cstddef>
#include <cstdint>

namespace wattx_bpplus {

// Produce a serialized Bulletproofs+ aggregate range proof for `n` values.
//   amounts[i]        : uint64 value in [0, 2^64)
//   blindings[i]      : 32-byte scalar (the Pedersen blinding / mask, on G)
//   out / out_cap     : caller buffer for the serialized proof; *out_len set on success
// Returns 0 on success, negative on error (e.g. buffer too small).
int prove(const uint64_t* amounts, const uint8_t (*blindings)[32], size_t n,
          uint8_t* out, size_t out_cap, size_t* out_len);

// Verify a serialized range proof AND that it commits to exactly the given
// output commitments. `commitments` is `n` contiguous 32-byte compressed points
// (the C values from fcmp_pedersen_commit). Returns true iff:
//   - the proof deserializes and has exactly n embedded commitments,
//   - 8*V[i] == commitments[i] for all i (cofactor-corrected match), and
//   - the Bulletproofs+ proof itself verifies.
// Never throws; any malformed input returns false.
bool verify(const uint8_t* commitments, size_t n,
            const uint8_t* proof_bytes, size_t proof_len);

} // namespace wattx_bpplus

#endif // WATTX_BPPLUS_API_H
