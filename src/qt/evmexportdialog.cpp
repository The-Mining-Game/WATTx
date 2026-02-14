// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/evmexportdialog.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <util/strencodings.h>
#include <crypto/sha256.h>
#include <secp256k1/include/secp256k1.h>
#include <pubkey.h>
#include <univalue.h>

#include <QFont>

// Keccak-256 implementation for Ethereum address derivation
#include <array>
#include <cstring>

namespace {

// Simple Keccak-256 implementation for address derivation
class Keccak256 {
public:
    static constexpr size_t HASH_SIZE = 32;

    static std::array<uint8_t, HASH_SIZE> hash(const uint8_t* data, size_t len) {
        std::array<uint8_t, HASH_SIZE> result;
        keccak256(data, len, result.data());
        return result;
    }

private:
    static constexpr uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static void keccak256(const uint8_t* input, size_t len, uint8_t* output) {
        uint64_t state[25] = {0};
        size_t rate = 136; // (1600 - 256*2) / 8

        // Absorb
        size_t offset = 0;
        while (len >= rate) {
            for (size_t i = 0; i < rate / 8; i++) {
                uint64_t t = 0;
                for (size_t j = 0; j < 8; j++) {
                    t |= static_cast<uint64_t>(input[offset + i * 8 + j]) << (8 * j);
                }
                state[i] ^= t;
            }
            keccakf(state);
            offset += rate;
            len -= rate;
        }

        // Pad
        uint8_t padded[136] = {0};
        std::memcpy(padded, input + offset, len);
        padded[len] = 0x01;
        padded[rate - 1] |= 0x80;

        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t t = 0;
            for (size_t j = 0; j < 8; j++) {
                t |= static_cast<uint64_t>(padded[i * 8 + j]) << (8 * j);
            }
            state[i] ^= t;
        }
        keccakf(state);

        // Squeeze
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 8; j++) {
                output[i * 8 + j] = static_cast<uint8_t>(state[i] >> (8 * j));
            }
        }
    }

    static void keccakf(uint64_t* state) {
        for (int round = 0; round < 24; round++) {
            // Theta
            uint64_t C[5], D[5];
            for (int x = 0; x < 5; x++) {
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x + 5 * y] ^= D[x];
                }
            }

            // Rho and Pi
            uint64_t B[25];
            static const int rho[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
            static const int pi[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
            B[0] = state[0];
            uint64_t t = state[1];
            for (int i = 0; i < 24; i++) {
                int j = pi[i];
                B[j] = (t << rho[i]) | (t >> (64 - rho[i]));
                t = state[j];
            }
            std::memcpy(state, B, sizeof(B));

            // Chi
            for (int y = 0; y < 5; y++) {
                uint64_t T[5];
                for (int x = 0; x < 5; x++) {
                    T[x] = state[x + 5 * y];
                }
                for (int x = 0; x < 5; x++) {
                    state[x + 5 * y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
                }
            }

            // Iota
            state[0] ^= RC[round];
        }
    }
};

} // namespace

EvmExportDialog::EvmExportDialog(QWidget *parent)
    : QDialog(parent)
{
    setupUI();
}

EvmExportDialog::~EvmExportDialog()
{
}

void EvmExportDialog::setupUI()
{
    setWindowTitle(tr("Export EVM Address & Key"));
    setMinimumWidth(550);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Info label
    QLabel *infoLabel = new QLabel(tr(
        "Export your WATTx address as an Ethereum-compatible address for use with\n"
        "wallets like Rabby or MetaMask. The private key will work with both formats."));
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    // Address selection
    QGroupBox *selectGroup = new QGroupBox(tr("Select Address"));
    QVBoxLayout *selectLayout = new QVBoxLayout(selectGroup);

    addressComboBox = new QComboBox();
    addressComboBox->setMinimumWidth(400);
    connect(addressComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &EvmExportDialog::onAddressSelected);
    selectLayout->addWidget(addressComboBox);

    mainLayout->addWidget(selectGroup);

    // Address display
    QGroupBox *addressGroup = new QGroupBox(tr("Addresses"));
    QVBoxLayout *addressLayout = new QVBoxLayout(addressGroup);

    // WATTx address
    QHBoxLayout *wattxLayout = new QHBoxLayout();
    wattxLayout->addWidget(new QLabel(tr("WATTx Address:")));
    wattxAddressEdit = new QLineEdit();
    wattxAddressEdit->setReadOnly(true);
    wattxAddressEdit->setFont(QFont("Monospace"));
    wattxLayout->addWidget(wattxAddressEdit);
    addressLayout->addLayout(wattxLayout);

    // EVM address
    QHBoxLayout *evmLayout = new QHBoxLayout();
    evmLayout->addWidget(new QLabel(tr("EVM Address:")));
    evmAddressEdit = new QLineEdit();
    evmAddressEdit->setReadOnly(true);
    evmAddressEdit->setFont(QFont("Monospace"));
    evmAddressEdit->setStyleSheet("QLineEdit { color: #2196F3; font-weight: bold; }");
    evmLayout->addWidget(evmAddressEdit);
    copyEvmButton = new QPushButton(tr("Copy"));
    connect(copyEvmButton, &QPushButton::clicked, this, &EvmExportDialog::onCopyEvmAddress);
    evmLayout->addWidget(copyEvmButton);
    addressLayout->addLayout(evmLayout);

    mainLayout->addWidget(addressGroup);

    // Private key section
    QGroupBox *keyGroup = new QGroupBox(tr("Private Key (for Rabby/MetaMask import)"));
    QVBoxLayout *keyLayout = new QVBoxLayout(keyGroup);

    warningLabel = new QLabel(tr(
        "⚠️ WARNING: Never share your private key! Anyone with this key can steal your funds."));
    warningLabel->setStyleSheet("QLabel { color: #FF5722; font-weight: bold; }");
    warningLabel->setWordWrap(true);
    keyLayout->addWidget(warningLabel);

    QHBoxLayout *keyInputLayout = new QHBoxLayout();
    privateKeyEdit = new QLineEdit();
    privateKeyEdit->setReadOnly(true);
    privateKeyEdit->setEchoMode(QLineEdit::Password);
    privateKeyEdit->setFont(QFont("Monospace"));
    privateKeyEdit->setPlaceholderText(tr("Click 'Show Key' to reveal"));
    keyInputLayout->addWidget(privateKeyEdit);

    showKeyButton = new QPushButton(tr("Show Key"));
    connect(showKeyButton, &QPushButton::clicked, this, &EvmExportDialog::onShowPrivateKey);
    keyInputLayout->addWidget(showKeyButton);

    copyKeyButton = new QPushButton(tr("Copy Key"));
    copyKeyButton->setEnabled(false);
    connect(copyKeyButton, &QPushButton::clicked, this, &EvmExportDialog::onCopyPrivateKey);
    keyInputLayout->addWidget(copyKeyButton);

    keyLayout->addLayout(keyInputLayout);
    mainLayout->addWidget(keyGroup);

    // Close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);
}

void EvmExportDialog::setModel(WalletModel *_model)
{
    model = _model;
    if (model) {
        populateAddresses();
    }
}

void EvmExportDialog::populateAddresses()
{
    if (!model) return;

    addressComboBox->clear();

    // Get addresses from wallet model
    for (const auto& dest : model->wallet().getAddresses()) {
        QString address = QString::fromStdString(EncodeDestination(dest.dest));
        QString label = QString::fromStdString(dest.name);

        QString displayText = address;
        if (!label.isEmpty()) {
            displayText = label + " (" + address + ")";
        }

        addressComboBox->addItem(displayText, address);
    }

    if (addressComboBox->count() > 0) {
        onAddressSelected(0);
    }
}

void EvmExportDialog::onAddressSelected(int index)
{
    if (index < 0 || !model) return;

    QString address = addressComboBox->itemData(index).toString();
    wattxAddressEdit->setText(address);

    // Get the public key for this address
    CTxDestination dest = DecodeDestination(address.toStdString());

    // Get pubkey via address
    CPubKey pubkey;
    if (auto* pk_dest = std::get_if<PKHash>(&dest)) {
        CKeyID keyid = ToKeyID(*pk_dest);
        CScript script = GetScriptForDestination(dest);
        if (model->wallet().getPubKey(script, keyid, pubkey)) {
            QString evmAddr = deriveEvmAddress(QString::fromStdString(HexStr(pubkey)));
            evmAddressEdit->setText(evmAddr);
        } else {
            evmAddressEdit->setText(tr("Unable to get public key"));
        }
    } else {
        evmAddressEdit->setText(tr("Unsupported address type"));
    }

    // Clear private key display
    privateKeyEdit->clear();
    privateKeyEdit->setEchoMode(QLineEdit::Password);
    showKeyButton->setText(tr("Show Key"));
    copyKeyButton->setEnabled(false);
    privateKeyVisible = false;
    currentPrivateKey.clear();
}

QString EvmExportDialog::deriveEvmAddress(const QString &pubkeyHex)
{
    // Parse the compressed public key
    std::vector<unsigned char> pubkeyData = ParseHex(pubkeyHex.toStdString());
    if (pubkeyData.size() != 33) {
        return tr("Invalid public key");
    }

    CPubKey compressedPubkey(pubkeyData);
    if (!compressedPubkey.IsValid()) {
        return tr("Invalid public key");
    }

    // Decompress the public key
    CPubKey uncompressedPubkey = compressedPubkey.IsCompressed() ?
        CPubKey(compressedPubkey.IsValid() ? compressedPubkey : CPubKey()) : compressedPubkey;

    // Get uncompressed pubkey bytes (65 bytes: 04 + x + y)
    // We need to use secp256k1 to decompress
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyData.data(), pubkeyData.size())) {
        secp256k1_context_destroy(ctx);
        return tr("Failed to parse public key");
    }

    // Serialize as uncompressed (65 bytes)
    std::array<unsigned char, 65> uncompressed;
    size_t outputLen = 65;
    secp256k1_ec_pubkey_serialize(ctx, uncompressed.data(), &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);

    // Keccak256 hash of the public key (without the 0x04 prefix)
    auto hash = Keccak256::hash(uncompressed.data() + 1, 64);

    // Take last 20 bytes as the address
    QString evmAddress = "0x";
    for (size_t i = 12; i < 32; i++) {
        evmAddress += QString("%1").arg(hash[i], 2, 16, QChar('0'));
    }

    return evmAddress;
}

void EvmExportDialog::onShowPrivateKey()
{
    if (!model) return;

    if (privateKeyVisible) {
        // Hide the key
        privateKeyEdit->setEchoMode(QLineEdit::Password);
        showKeyButton->setText(tr("Show Key"));
        copyKeyButton->setEnabled(false);
        privateKeyVisible = false;
        return;
    }

    // Confirm with user
    QMessageBox::StandardButton reply = QMessageBox::warning(this,
        tr("Security Warning"),
        tr("You are about to reveal your private key.\n\n"
           "Never share this key with anyone. Anyone with this key can steal all your funds.\n\n"
           "Are you sure you want to continue?"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    // Get the private key
    QString address = addressComboBox->currentData().toString();
    currentPrivateKey = getPrivateKeyForAddress(address);

    if (currentPrivateKey.isEmpty()) {
        QMessageBox::warning(this, tr("Error"),
            tr("Could not retrieve private key. Make sure the wallet is unlocked."));
        return;
    }

    privateKeyEdit->setText(currentPrivateKey);
    privateKeyEdit->setEchoMode(QLineEdit::Normal);
    showKeyButton->setText(tr("Hide Key"));
    copyKeyButton->setEnabled(true);
    privateKeyVisible = true;
}

QString EvmExportDialog::getPrivateKeyForAddress(const QString &address)
{
    if (!model) return QString();

    std::string walletName = model->wallet().getWalletName();
    std::string uri = "/wallet/" + walletName;

    // Try dumpprivkey first (legacy wallets)
    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());

        UniValue result = model->node().executeRpc("dumpprivkey", params, uri);

        if (result.isStr()) {
            std::string wifKey = result.get_str();
            CKey key = DecodeSecret(wifKey);
            if (key.IsValid()) {
                return QString("0x") + QString::fromStdString(HexStr(key));
            }
        }
    } catch (...) {
        // dumpprivkey not available (descriptor wallet) - try exportevmkey
    }

    // Try exportevmkey RPC (works with both legacy and descriptor wallets)
    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());

        UniValue result = model->node().executeRpc("exportevmkey", params, uri);

        if (result.isObject()) {
            const UniValue& privKey = result.find_value("private_key");
            if (privKey.isStr()) {
                return QString::fromStdString(privKey.get_str());
            }
        }
    } catch (...) {
        // exportevmkey also failed
    }

    return QString();
}

void EvmExportDialog::onCopyEvmAddress()
{
    QApplication::clipboard()->setText(evmAddressEdit->text());
    QMessageBox::information(this, tr("Copied"),
        tr("EVM address copied to clipboard."));
}

void EvmExportDialog::onCopyPrivateKey()
{
    if (currentPrivateKey.isEmpty()) return;

    QMessageBox::StandardButton reply = QMessageBox::warning(this,
        tr("Copy Private Key"),
        tr("Your private key will be copied to the clipboard.\n\n"
           "Make sure no one is watching your screen and clear your clipboard after use.\n\n"
           "Continue?"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        QApplication::clipboard()->setText(currentPrivateKey);
        QMessageBox::information(this, tr("Copied"),
            tr("Private key copied to clipboard.\n\nRemember to clear your clipboard after pasting!"));
    }
}
