// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>
#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <span.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {
bool SpanEqual(Span<const std::byte> a, Span<const std::byte> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}
} // namespace

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bip324_tests, BasicTestingSetup)

// WATTx uses a different HKDF salt ("qtum_v2_shared_secret" + WATTx magic bytes),
// so upstream Bitcoin BIP324 test vectors are not applicable. Instead we verify
// the cipher implementation via round-trip encryption/decryption tests.

BOOST_AUTO_TEST_CASE(bip324_cipher_roundtrip)
{
    // Use mainnet params (the HKDF salt includes network magic)
    SelectParams(ChainType::MAIN);

    // Generate two key pairs (initiator and responder)
    CKey key_init;
    key_init.MakeNewKey(true);
    CKey key_resp;
    key_resp.MakeNewKey(true);

    // Create EllSwift public keys
    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));

    // Initialize ciphers for both directions
    BIP324Cipher cipher_init(key_init, ellswift_init);
    BOOST_CHECK(!cipher_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);
    BOOST_CHECK(cipher_init);

    BIP324Cipher cipher_resp(key_resp, ellswift_resp);
    BOOST_CHECK(!cipher_resp);
    cipher_resp.Initialize(ellswift_init, /*initiator=*/false);
    BOOST_CHECK(cipher_resp);

    // Session IDs must match
    BOOST_CHECK(SpanEqual(cipher_init.GetSessionID(), cipher_resp.GetSessionID()));

    // Garbage terminators: initiator's send == responder's recv and vice versa
    BOOST_CHECK(SpanEqual(cipher_init.GetSendGarbageTerminator(), cipher_resp.GetReceiveGarbageTerminator()));
    BOOST_CHECK(SpanEqual(cipher_init.GetReceiveGarbageTerminator(), cipher_resp.GetSendGarbageTerminator()));

    // Test round-trip with various message sizes
    for (size_t msg_len : {0, 1, 13, 255, 1024, 4096}) {
        // Create a random message
        std::vector<std::byte> plaintext(msg_len);
        for (size_t i = 0; i < msg_len; ++i) {
            plaintext[i] = static_cast<std::byte>(m_rng.rand32() & 0xFF);
        }

        // Create random AAD
        std::vector<std::byte> aad(m_rng.rand32() % 32);
        for (size_t i = 0; i < aad.size(); ++i) {
            aad[i] = static_cast<std::byte>(m_rng.rand32() & 0xFF);
        }

        bool ignore = (msg_len == 1); // Test ignore flag for one case

        // Encrypt with initiator's cipher
        std::vector<std::byte> ciphertext(plaintext.size() + cipher_init.EXPANSION);
        cipher_init.Encrypt(plaintext, aad, ignore, ciphertext);

        // Decrypt with responder's cipher
        uint32_t dec_len = cipher_resp.DecryptLength(MakeByteSpan(ciphertext).first(cipher_resp.LENGTH_LEN));
        BOOST_CHECK_EQUAL(dec_len, plaintext.size());

        std::vector<std::byte> decrypted(dec_len);
        bool dec_ignore{false};
        bool ok = cipher_resp.Decrypt(
            Span{ciphertext}.subspan(cipher_resp.LENGTH_LEN),
            aad, dec_ignore, decrypted);

        BOOST_CHECK(ok);
        BOOST_CHECK(decrypted == plaintext);
        BOOST_CHECK(dec_ignore == ignore);
    }
}

BOOST_AUTO_TEST_CASE(bip324_cipher_responder_to_initiator)
{
    // Test the reverse direction: responder encrypts, initiator decrypts
    SelectParams(ChainType::MAIN);

    CKey key_init;
    key_init.MakeNewKey(true);
    CKey key_resp;
    key_resp.MakeNewKey(true);

    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));

    BIP324Cipher cipher_init(key_init, ellswift_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);

    BIP324Cipher cipher_resp(key_resp, ellswift_resp);
    cipher_resp.Initialize(ellswift_init, /*initiator=*/false);

    // Responder encrypts, initiator decrypts
    std::vector<std::byte> plaintext(128);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::byte>(i & 0xFF);
    }

    std::vector<std::byte> ciphertext(plaintext.size() + cipher_resp.EXPANSION);
    cipher_resp.Encrypt(plaintext, {}, false, ciphertext);

    uint32_t dec_len = cipher_init.DecryptLength(MakeByteSpan(ciphertext).first(cipher_init.LENGTH_LEN));
    BOOST_CHECK_EQUAL(dec_len, plaintext.size());

    std::vector<std::byte> decrypted(dec_len);
    bool dec_ignore{false};
    bool ok = cipher_init.Decrypt(
        Span{ciphertext}.subspan(cipher_init.LENGTH_LEN),
        {}, dec_ignore, decrypted);

    BOOST_CHECK(ok);
    BOOST_CHECK(decrypted == plaintext);
    BOOST_CHECK(!dec_ignore);
}

BOOST_AUTO_TEST_CASE(bip324_cipher_wrong_key)
{
    // Verify that decryption fails with wrong key
    SelectParams(ChainType::MAIN);

    CKey key_init, key_resp, key_wrong;
    key_init.MakeNewKey(true);
    key_resp.MakeNewKey(true);
    key_wrong.MakeNewKey(true);

    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    uint256 ent_wrong = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));
    auto ellswift_wrong = key_wrong.EllSwiftCreate(AsBytes(Span{ent_wrong}));

    // Correct pair
    BIP324Cipher cipher_init(key_init, ellswift_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);

    // Wrong responder key
    BIP324Cipher cipher_wrong(key_wrong, ellswift_wrong);
    cipher_wrong.Initialize(ellswift_init, /*initiator=*/false);

    // Session IDs should differ
    BOOST_CHECK(!SpanEqual(cipher_init.GetSessionID(), cipher_wrong.GetSessionID()));

    // Encrypt with correct initiator
    std::vector<std::byte> plaintext{std::byte{0x42}, std::byte{0x43}};
    std::vector<std::byte> ciphertext(plaintext.size() + cipher_init.EXPANSION);
    cipher_init.Encrypt(plaintext, {}, false, ciphertext);

    // With wrong key, DecryptLength will produce a bogus value (different from plaintext.size())
    // because the length is encrypted with a different key.
    // We can't safely call Decrypt if dec_len doesn't match because of an internal assert.
    uint32_t dec_len = cipher_wrong.DecryptLength(MakeByteSpan(ciphertext).first(cipher_wrong.LENGTH_LEN));

    // The decrypted length with wrong key should almost certainly differ from the actual length
    // (probability of match is 1/2^24 since length field is 3 bytes)
    if (dec_len == plaintext.size()) {
        // Extremely unlikely but possible - try Decrypt which should fail AEAD auth
        std::vector<std::byte> decrypted(dec_len);
        bool dec_ignore{false};
        bool ok = cipher_wrong.Decrypt(
            Span{ciphertext}.subspan(cipher_wrong.LENGTH_LEN),
            {}, dec_ignore, decrypted);
        BOOST_CHECK(!ok);
    } else {
        // Length mismatch confirms wrong key - can't call Decrypt due to size assert
        BOOST_CHECK(dec_len != plaintext.size());
    }
}

BOOST_AUTO_TEST_CASE(bip324_cipher_corrupted_ciphertext)
{
    // Verify that corrupted ciphertext fails authentication
    SelectParams(ChainType::MAIN);

    CKey key_init, key_resp;
    key_init.MakeNewKey(true);
    key_resp.MakeNewKey(true);

    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));

    BIP324Cipher cipher_init(key_init, ellswift_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);

    BIP324Cipher cipher_resp(key_resp, ellswift_resp);
    cipher_resp.Initialize(ellswift_init, /*initiator=*/false);

    // Encrypt a message
    std::vector<std::byte> plaintext(64);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::byte>(i);
    }

    std::vector<std::byte> ciphertext(plaintext.size() + cipher_init.EXPANSION);
    cipher_init.Encrypt(plaintext, {}, false, ciphertext);

    // Corrupt a byte in the ciphertext (after the length field)
    size_t corrupt_pos = cipher_resp.LENGTH_LEN + (m_rng.rand32() % (ciphertext.size() - cipher_resp.LENGTH_LEN));
    ciphertext[corrupt_pos] ^= std::byte{0x01};

    // Decrypt should fail
    uint32_t dec_len = cipher_resp.DecryptLength(MakeByteSpan(ciphertext).first(cipher_resp.LENGTH_LEN));
    std::vector<std::byte> decrypted(dec_len);
    bool dec_ignore{false};
    bool ok = cipher_resp.Decrypt(
        Span{ciphertext}.subspan(cipher_resp.LENGTH_LEN),
        {}, dec_ignore, decrypted);

    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(bip324_cipher_aad_mismatch)
{
    // Verify that AAD mismatch fails authentication
    SelectParams(ChainType::MAIN);

    CKey key_init, key_resp;
    key_init.MakeNewKey(true);
    key_resp.MakeNewKey(true);

    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));

    BIP324Cipher cipher_init(key_init, ellswift_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);

    BIP324Cipher cipher_resp(key_resp, ellswift_resp);
    cipher_resp.Initialize(ellswift_init, /*initiator=*/false);

    // Encrypt with AAD
    std::vector<std::byte> plaintext{std::byte{0xAA}, std::byte{0xBB}};
    std::vector<std::byte> aad{std::byte{0x01}, std::byte{0x02}};
    std::vector<std::byte> ciphertext(plaintext.size() + cipher_init.EXPANSION);
    cipher_init.Encrypt(plaintext, aad, false, ciphertext);

    // Decrypt with different AAD - should fail
    std::vector<std::byte> wrong_aad{std::byte{0x01}, std::byte{0x03}};
    uint32_t dec_len = cipher_resp.DecryptLength(MakeByteSpan(ciphertext).first(cipher_resp.LENGTH_LEN));
    std::vector<std::byte> decrypted(dec_len);
    bool dec_ignore{false};
    bool ok = cipher_resp.Decrypt(
        Span{ciphertext}.subspan(cipher_resp.LENGTH_LEN),
        wrong_aad, dec_ignore, decrypted);

    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(bip324_cipher_multiple_packets)
{
    // Verify that packet sequencing works correctly (cipher state advances per packet)
    SelectParams(ChainType::MAIN);

    CKey key_init, key_resp;
    key_init.MakeNewKey(true);
    key_resp.MakeNewKey(true);

    uint256 ent_init = m_rng.rand256();
    uint256 ent_resp = m_rng.rand256();
    auto ellswift_init = key_init.EllSwiftCreate(AsBytes(Span{ent_init}));
    auto ellswift_resp = key_resp.EllSwiftCreate(AsBytes(Span{ent_resp}));

    BIP324Cipher cipher_init(key_init, ellswift_init);
    cipher_init.Initialize(ellswift_resp, /*initiator=*/true);

    BIP324Cipher cipher_resp(key_resp, ellswift_resp);
    cipher_resp.Initialize(ellswift_init, /*initiator=*/false);

    // Encrypt and decrypt 10 packets in sequence
    for (int i = 0; i < 10; ++i) {
        std::vector<std::byte> plaintext(16);
        for (size_t j = 0; j < plaintext.size(); ++j) {
            plaintext[j] = static_cast<std::byte>((i * 16 + j) & 0xFF);
        }

        std::vector<std::byte> ciphertext(plaintext.size() + cipher_init.EXPANSION);
        cipher_init.Encrypt(plaintext, {}, false, ciphertext);

        uint32_t dec_len = cipher_resp.DecryptLength(MakeByteSpan(ciphertext).first(cipher_resp.LENGTH_LEN));
        BOOST_CHECK_EQUAL(dec_len, plaintext.size());

        std::vector<std::byte> decrypted(dec_len);
        bool dec_ignore{false};
        bool ok = cipher_resp.Decrypt(
            Span{ciphertext}.subspan(cipher_resp.LENGTH_LEN),
            {}, dec_ignore, decrypted);

        BOOST_CHECK(ok);
        BOOST_CHECK(decrypted == plaintext);
    }
}

BOOST_AUTO_TEST_SUITE_END()
