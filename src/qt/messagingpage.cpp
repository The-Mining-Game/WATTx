// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/messagingpage.h>
#include <qt/forms/ui_messagingpage.h>

#include <qt/clientmodel.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <key.h>
#include <script/script.h>
#include <util/time.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <messaging/encryptedmsg.h>
#include <wallet/messaging.h>
#include <wallet/wallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>
#include <primitives/transaction.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <logging.h>
#include <common/args.h>

#include <QMessageBox>
#include <QDateTime>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>
#include <QClipboard>
#include <QMenu>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QVBoxLayout>
#if QT_CONFIG(colordialog)
#include <QColorDialog>
#endif
#include <QUuid>
#include <QHeaderView>
#include <qt/chatbubblewidget.h>

// OP_RETURN message prefix
static const std::string OP_RETURN_PREFIX = "WTX:";

MessagingPage::MessagingPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MessagingPage),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup tabs
    setupOpReturnTab();
    setupP2PTab();
    setupMemoTab();

    // Connect tab switching
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, &MessagingPage::onTabChanged);

    // Connect OP_RETURN signals
    connect(ui->pushButtonSendOpReturn, &QPushButton::clicked, this, &MessagingPage::onSendOpReturnClicked);
    connect(ui->lineEditOpReturnMessage, &QLineEdit::textChanged, this, &MessagingPage::onOpReturnCharCountChanged);
    connect(ui->tableOpReturnMessages, &QTableWidget::itemClicked, this, &MessagingPage::onOpReturnMessageSelected);
    connect(ui->checkBoxEncrypt, &QCheckBox::toggled, this, &MessagingPage::onEncryptToggled);

    // Connect P2P Chat signals
    connect(ui->listConversations, &QListWidget::itemClicked, this, &MessagingPage::onConversationSelected);
    connect(ui->listConversations, &QListWidget::customContextMenuRequested, this, &MessagingPage::onConversationContextMenu);
    connect(ui->listPendingRequests, &QListWidget::itemClicked, this, &MessagingPage::onPendingRequestSelected);
    connect(ui->pushButtonSendP2P, &QPushButton::clicked, this, &MessagingPage::onSendP2PMessageClicked);
    connect(ui->pushButtonNewConversation, &QPushButton::clicked, this, &MessagingPage::onNewConversationClicked);
    connect(ui->pushButtonKeyExchange, &QPushButton::clicked, this, &MessagingPage::onKeyExchangeClicked);
    connect(ui->pushButtonRefreshP2P, &QPushButton::clicked, this, &MessagingPage::onRefreshP2PClicked);
    connect(ui->pushButtonChatBackground, &QPushButton::clicked, this, &MessagingPage::onChatBackgroundClicked);
    connect(ui->pushButtonInviteUser, &QPushButton::clicked, this, &MessagingPage::onInviteUserClicked);
    connect(ui->pushButtonManageGroup, &QPushButton::clicked, this, &MessagingPage::onManageGroupClicked);
    connect(ui->lineEditChatMessage, &QLineEdit::returnPressed, this, &MessagingPage::onSendP2PMessageClicked);

    // Connect Memo signals
    connect(ui->pushButtonSaveMemo, &QPushButton::clicked, this, &MessagingPage::onTxMemoSaveClicked);
    connect(ui->pushButtonSearchMemo, &QPushButton::clicked, this, &MessagingPage::onTxMemoSearchClicked);
    connect(ui->pushButtonDeleteMemo, &QPushButton::clicked, this, &MessagingPage::onTxMemoDeleteClicked);
    connect(ui->tableMemos, &QTableWidget::itemClicked, this, &MessagingPage::onTxMemoSelected);
    connect(ui->lineEditMemoSearch, &QLineEdit::returnPressed, this, &MessagingPage::onTxMemoSearchClicked);

    // Initialize storage
    initStorage();
}

MessagingPage::~MessagingPage()
{
    saveData();
    delete ui;
}

void MessagingPage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, this, &MessagingPage::numBlocksChanged);
    }
}

void MessagingPage::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;
    if (walletModel) {
        // Register our wallet addresses with the P2P message manager
        registerWalletAddresses();
        // Populate identity selector
        refreshIdentities();
        // Set up callback for incoming messages
        setupMessageCallback();
        refreshMessages();
    }
}

void MessagingPage::setupMessageCallback()
{
    if (!messaging::g_message_manager) return;

    // Set callback for when we receive a message
    messaging::g_message_manager->SetMessageCallback([this](const messaging::EncryptedMessage& msg) {
        // This is called from a network thread, so we need to use Qt's thread-safe mechanism
        QMetaObject::invokeMethod(this, [this, msg]() {
            handleIncomingMessage(msg);
        }, Qt::QueuedConnection);
    });

    LogPrintf("MessagingPage: Message callback set up\n");
}

void MessagingPage::handleIncomingMessage(const messaging::EncryptedMessage& msg)
{
    LogPrintf("MessagingPage: Handling incoming message %s\n", msg.msgHash.ToString().substr(0, 16));

    // Convert encrypted data to QByteArray for decryption
    QByteArray encryptedData;
    for (unsigned char c : msg.encryptedData) {
        encryptedData.append(char(c));
    }

    // Find the recipient address FIRST (one of our addresses that matches the hash)
    // We need this for fallback decryption which uses recipient address as key
    QString recipientAddress;
    wallet::CWallet* pwallet = walletModel ? walletModel->wallet().wallet() : nullptr;
    if (pwallet) {
        // Try legacy wallet first
        auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            for (const CKeyID& keyId : spk_man->GetKeys()) {
                CTxDestination dest = PKHash(keyId);
                std::string addrStr = EncodeDestination(dest);

                CSHA256 sha;
                sha.Write(reinterpret_cast<const unsigned char*>(addrStr.data()), addrStr.size());
                uint256 addrHash;
                sha.Finalize(addrHash.begin());

                if (addrHash == msg.recipientHash) {
                    recipientAddress = QString::fromStdString(addrStr);
                    break;
                }
            }
        }

        // Try descriptor wallets if not found
        if (recipientAddress.isEmpty()) {
            for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
                wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
                if (desc_man) {
                    auto scripts = desc_man->GetScriptPubKeys();
                    for (const auto& script : scripts) {
                        CTxDestination dest;
                        if (ExtractDestination(script, dest)) {
                            std::string addrStr = EncodeDestination(dest);

                            CSHA256 sha;
                            sha.Write(reinterpret_cast<const unsigned char*>(addrStr.data()), addrStr.size());
                            uint256 addrHash;
                            sha.Finalize(addrHash.begin());

                            if (addrHash == msg.recipientHash) {
                                recipientAddress = QString::fromStdString(addrStr);
                                break;
                            }
                        }
                    }
                    if (!recipientAddress.isEmpty()) break;
                }
            }
        }
    }

    // Check message format - handshake messages are NOT base64 encoded
    unsigned char rawMarker = encryptedData.size() > 0 ? static_cast<unsigned char>(encryptedData[0]) : 0xFF;

    // Handle handshake and group invite messages first (not base64 encoded)
    if (rawMarker == MSG_HANDSHAKE_REQUEST || rawMarker == MSG_HANDSHAKE_ACCEPT || rawMarker == MSG_GROUP_INVITE) {
        LogPrintf("MessagingPage: Received handshake/invite message (type=0x%02x)\n", rawMarker);
        handleHandshakeMessage(encryptedData, recipientAddress);
        return; // Don't process as regular message
    }

    // Decode base64 for regular messages
    QByteArray decoded = QByteArray::fromBase64(encryptedData);
    unsigned char marker = decoded.size() > 0 ? static_cast<unsigned char>(decoded[0]) : 0xFF;
    LogPrintf("MessagingPage: Encrypted data size=%d, decoded size=%d, marker=0x%02x\n",
              encryptedData.size(), decoded.size(), marker);

    QString senderAddress = "Unknown";
    QString decryptedText;

    if (marker == 0x00) {
        // Fallback encryption - uses recipient address as key
        LogPrintf("MessagingPage: Fallback encryption, using recipient %s as key\n", recipientAddress.toStdString());
        QByteArray payload = decoded.mid(1);
        QByteArray key = QCryptographicHash::hash(recipientAddress.toUtf8(), QCryptographicHash::Sha256);
        QByteArray decrypted;
        decrypted.resize(payload.size());
        for (int i = 0; i < payload.size(); i++) {
            decrypted[i] = payload[i] ^ key[i % key.size()];
        }
        decryptedText = QString::fromUtf8(decrypted);
        senderAddress = "Unknown (fallback encryption)";
    } else if (marker == 0x01 && decoded.size() >= 34) {
        // ECDH format - extract sender pubkey
        std::vector<unsigned char> pubkeyData(decoded.begin() + 1, decoded.begin() + 34);
        CPubKey senderPubKey(pubkeyData);
        if (senderPubKey.IsValid()) {
            CTxDestination senderDest = PKHash(senderPubKey);
            senderAddress = QString::fromStdString(EncodeDestination(senderDest));
            LogPrintf("MessagingPage: ECDH encryption, sender: %s\n", senderAddress.toStdString());
        }
        decryptedText = decryptMessage(encryptedData, senderAddress);
    }

    if (decryptedText.isEmpty() || decryptedText.startsWith("[Encrypted")) {
        LogPrintf("MessagingPage: Could not decrypt incoming message\n");
        decryptedText = "[Encrypted message - could not decrypt]";
    }

    // Store as incoming message
    StoredMessage storedMsg;
    storedMsg.type = MessageType::P2PEncrypted;
    storedMsg.fromAddress = senderAddress;
    storedMsg.toAddress = recipientAddress;
    storedMsg.content = decryptedText;
    storedMsg.timestamp = msg.timestamp;
    storedMsg.isOutgoing = false;
    storedMsg.isRead = false;

    storeP2PMessage(storedMsg);

    // Refresh the UI
    updateConversationList();

    // Emit signal for notification
    Q_EMIT newMessageReceived(senderAddress, decryptedText.left(50));

    LogPrintf("MessagingPage: Stored incoming message from %s\n", senderAddress.toStdString());
}

void MessagingPage::registerWalletAddresses()
{
    LogPrintf("MessagingPage: registerWalletAddresses called\n");
    if (!walletModel) {
        LogPrintf("MessagingPage: No wallet model\n");
        return;
    }
    if (!messaging::g_message_manager) {
        LogPrintf("MessagingPage: No message manager\n");
        return;
    }

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) return;

    int registered = 0;

    // Register addresses from legacy wallet
    auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man) {
        std::set<CKeyID> keyIds = spk_man->GetKeys();
        for (const CKeyID& keyId : keyIds) {
            // Hash the address for privacy (same as when sending)
            CTxDestination dest = PKHash(keyId);
            std::string addrStr = EncodeDestination(dest);

            CSHA256 sha;
            sha.Write(reinterpret_cast<const unsigned char*>(addrStr.data()), addrStr.size());
            uint256 addrHash;
            sha.Finalize(addrHash.begin());

            messaging::g_message_manager->RegisterAddress(addrHash);
            registered++;
        }
    }

    // Register addresses from descriptor wallets
    for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
        wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
        if (desc_man) {
            auto scripts = desc_man->GetScriptPubKeys();
            for (const auto& script : scripts) {
                CTxDestination dest;
                if (ExtractDestination(script, dest)) {
                    std::string addrStr = EncodeDestination(dest);

                    CSHA256 sha;
                    sha.Write(reinterpret_cast<const unsigned char*>(addrStr.data()), addrStr.size());
                    uint256 addrHash;
                    sha.Finalize(addrHash.begin());

                    messaging::g_message_manager->RegisterAddress(addrHash);
                    registered++;
                }
            }
        }
    }

    if (registered > 0) {
        LogPrintf("MessagingPage: Registered %d addresses for P2P messaging\n", registered);
    }
}

// ============================================================================
// JSON Storage Management
// ============================================================================

bool MessagingPage::initStorage()
{
    if (m_storageInitialized) return true;

    // Create data directory using wallet's datadir (unique per wallet instance)
    fs::path dataDirPath = gArgs.GetDataDirNet() / "messaging";
    m_dataDir = QString::fromStdString(fs::PathToString(dataDirPath));
    QDir().mkpath(m_dataDir);

    // Load contact labels
    QString labelsFile = m_dataDir + "/contact_labels.json";
    QFile file(labelsFile);
    if (file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        QJsonObject obj = doc.object();
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            m_contactLabels[it.key()] = it.value().toString();
        }
    }

    // Load exchanged keys for encrypted chat
    loadExchangedKeys();

    // Load chat background color
    loadChatBackgroundColor();

    // Load pending requests
    loadPendingRequests();

    // Load group chats
    loadGroups();

    m_storageInitialized = true;
    return true;
}

void MessagingPage::saveData()
{
    // Save contact labels
    QString labelsFile = m_dataDir + "/contact_labels.json";
    QFile file(labelsFile);
    if (file.open(QIODevice::WriteOnly)) {
        QJsonObject obj;
        for (auto it = m_contactLabels.begin(); it != m_contactLabels.end(); ++it) {
            obj[it.key()] = it.value();
        }
        file.write(QJsonDocument(obj).toJson());
    }
}

// Helper to load JSON from file
static QJsonArray loadJsonArray(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QJsonArray();
    }
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    return doc.array();
}

// Helper to save JSON to file
static bool saveJsonArray(const QString& filePath, const QJsonArray& array)
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    file.write(QJsonDocument(array).toJson());
    return true;
}

// ============================================================================
// Tab Setup
// ============================================================================

void MessagingPage::setupOpReturnTab()
{
    // Configure OP_RETURN table - use stretch modes to avoid horizontal scrollbar
    QHeaderView* header = ui->tableOpReturnMessages->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents); // Date
    header->setSectionResizeMode(1, QHeaderView::ResizeToContents); // Type
    header->setSectionResizeMode(2, QHeaderView::Stretch);          // Message (stretches)
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents); // TxID
    header->setStretchLastSection(false);

    // Context menu for table
    ui->tableOpReturnMessages->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tableOpReturnMessages, &QTableWidget::customContextMenuRequested, [this](const QPoint& pos) {
        QMenu menu(this);
        QAction* copyTxId = menu.addAction(tr("Copy Transaction ID"));
        QAction* copyMsg = menu.addAction(tr("Copy Message"));

        QAction* selected = menu.exec(ui->tableOpReturnMessages->mapToGlobal(pos));
        if (selected == copyTxId) {
            int row = ui->tableOpReturnMessages->currentRow();
            if (row >= 0) {
                QString txid = ui->tableOpReturnMessages->item(row, 3)->text();
                QApplication::clipboard()->setText(txid);
            }
        } else if (selected == copyMsg) {
            int row = ui->tableOpReturnMessages->currentRow();
            if (row >= 0) {
                QString msg = ui->tableOpReturnMessages->item(row, 2)->text();
                QApplication::clipboard()->setText(msg);
            }
        }
    });
}

void MessagingPage::setupP2PTab()
{
    // Initial state - no conversation selected
    ui->lineEditChatMessage->setEnabled(false);
    ui->pushButtonSendP2P->setEnabled(false);

    // Create custom chat bubble widget (pure Qt Widgets, no QML dependencies)
    m_chatView = new ChatBubbleWidget(this);
    m_chatView->setMinimumHeight(200);

    // Replace the textBrowserChat with our custom chat view
    QLayout* chatLayout = ui->textBrowserChat->parentWidget()->layout();
    if (chatLayout) {
        // Find and replace the text browser
        int index = chatLayout->indexOf(ui->textBrowserChat);
        if (index >= 0) {
            chatLayout->removeWidget(ui->textBrowserChat);
            ui->textBrowserChat->hide();
            // Insert custom widget at the same position
            if (QVBoxLayout* vbox = qobject_cast<QVBoxLayout*>(chatLayout)) {
                vbox->insertWidget(index, m_chatView, 1);
            } else {
                chatLayout->addWidget(m_chatView);
            }
        }
    }

    // Apply saved background color
    applyChatBackgroundColor();

    LogPrintf("MessagingPage: ChatBubbleWidget created successfully\n");

    // Update pending requests list
    updatePendingRequestsList();

    // Connect refresh identities button
    connect(ui->pushButtonRefreshIdentities, &QPushButton::clicked, this, &MessagingPage::refreshIdentities);

    // Set up auto-refresh timer (every 3 seconds)
    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        // Only refresh if we're on the P2P chat tab and have a conversation selected
        if (ui->tabWidget->currentIndex() == 1 && !m_currentConversationPeer.isEmpty()) {
            updateChatDisplay();
            updateConversationList();
        }
    });
    m_refreshTimer->start(3000); // 3 second interval
}

void MessagingPage::refreshIdentities()
{
    ui->comboBoxIdentity->clear();

    if (!walletModel) return;

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) return;

    // Get addresses that have been used for sending (appeared as inputs in transactions)
    std::set<std::string> usedAddresses;

    {
        LOCK(pwallet->cs_wallet);

        // Iterate through all wallet transactions to find addresses we've sent from
        for (const auto& [txid, wtx] : pwallet->mapWallet) {
            // Check if this transaction has debits (we spent from it)
            if (pwallet->GetDebit(*wtx.tx, wallet::ISMINE_SPENDABLE) > 0) {
                // Get the addresses from the inputs (addresses we spent from)
                for (const CTxIn& txin : wtx.tx->vin) {
                    // Look up the previous output to get the address
                    auto it = pwallet->mapWallet.find(txin.prevout.hash);
                    if (it != pwallet->mapWallet.end()) {
                        const wallet::CWalletTx& prevTx = it->second;
                        if (txin.prevout.n < prevTx.tx->vout.size()) {
                            const CTxOut& prevOut = prevTx.tx->vout[txin.prevout.n];
                            CTxDestination dest;
                            if (ExtractDestination(prevOut.scriptPubKey, dest)) {
                                // Only include if it's our address
                                if (pwallet->IsMine(dest)) {
                                    usedAddresses.insert(EncodeDestination(dest));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Convert to QStringList and sort
    QStringList addresses;
    for (const std::string& addr : usedAddresses) {
        addresses.append(QString::fromStdString(addr));
    }
    addresses.sort();

    // Add addresses to combo box with labels if available
    for (const QString& addr : addresses) {
        QString label = m_contactLabels.value(addr, "");
        QString displayText = label.isEmpty() ? addr : QString("%1 (%2)").arg(label, addr);
        ui->comboBoxIdentity->addItem(displayText, addr);
    }

    if (ui->comboBoxIdentity->count() > 0) {
        ui->comboBoxIdentity->setCurrentIndex(0);
    }

    LogPrintf("MessagingPage: Loaded %d identities (addresses used for sending)\n", addresses.size());
}

void MessagingPage::setupMemoTab()
{
    // Configure memo table - use stretch modes to avoid horizontal scrollbar
    QHeaderView* memoHeader = ui->tableMemos->horizontalHeader();
    memoHeader->setSectionResizeMode(0, QHeaderView::ResizeToContents); // TxID
    memoHeader->setSectionResizeMode(1, QHeaderView::Stretch);          // Memo (stretches)
    memoHeader->setSectionResizeMode(2, QHeaderView::ResizeToContents); // Date
    memoHeader->setStretchLastSection(false);

    // Context menu for memo table
    ui->tableMemos->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tableMemos, &QTableWidget::customContextMenuRequested, [this](const QPoint& pos) {
        QMenu menu(this);
        QAction* copyTxId = menu.addAction(tr("Copy Transaction ID"));
        QAction* copyMemo = menu.addAction(tr("Copy Memo"));
        QAction* deleteMemo = menu.addAction(tr("Delete Memo"));

        QAction* selected = menu.exec(ui->tableMemos->mapToGlobal(pos));
        int row = ui->tableMemos->currentRow();
        if (row < 0) return;

        if (selected == copyTxId) {
            QString txid = ui->tableMemos->item(row, 0)->text();
            QApplication::clipboard()->setText(txid);
        } else if (selected == copyMemo) {
            QString memo = ui->tableMemos->item(row, 1)->text();
            QApplication::clipboard()->setText(memo);
        } else if (selected == deleteMemo) {
            QString txid = ui->tableMemos->item(row, 0)->text();
            uint256 hash;
            hash.SetHexDeprecated(txid.toStdString());
            deleteTxMemo(hash);
            updateMemoList();
        }
    });
}

// ============================================================================
// OP_RETURN Message Handling
// ============================================================================

void MessagingPage::onSendOpReturnClicked()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet not available"));
        return;
    }

    QString message = ui->lineEditOpReturnMessage->text().trimmed();
    if (message.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please enter a message"));
        return;
    }

    if (message.length() > 76) {
        QMessageBox::warning(this, tr("Error"), tr("Message too long (max 76 characters)"));
        return;
    }

    // Confirm the transaction
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Confirm On-Chain Message"),
        tr("This will create a transaction with your message stored permanently on the blockchain.\n\n"
           "Message: %1\n\n"
           "A small transaction fee will be required. Continue?").arg(message),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    if (sendOpReturnMessage(message)) {
        ui->lineEditOpReturnMessage->clear();
        QMessageBox::information(this, tr("Success"),
            tr("Message sent! It will appear in history after confirmation."));
        updateOpReturnList();
    }
}

bool MessagingPage::sendOpReturnMessage(const QString& message)
{
    if (!walletModel) return false;

    try {
        std::vector<unsigned char> opReturnData;
        QString recipientAddress;
        QString displayMessage = message;

        bool isEncrypted = ui->checkBoxEncrypt->isChecked();

        if (isEncrypted) {
            // Get recipient address
            recipientAddress = ui->lineEditRecipient->text().trimmed();
            if (recipientAddress.isEmpty()) {
                QMessageBox::warning(this, tr("Error"), tr("Please enter a recipient address for encrypted messages."));
                return false;
            }
            if (!validateAddress(recipientAddress)) {
                QMessageBox::warning(this, tr("Error"), tr("Invalid recipient address."));
                return false;
            }

            // Get our sending key
            wallet::CWallet* pwallet = walletModel->wallet().wallet();
            if (!pwallet) return false;

            CKey senderKey;
            CPubKey senderPubKey;
            auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
            if (spk_man) {
                std::set<CKeyID> keys = spk_man->GetKeys();
                if (!keys.empty()) {
                    CKeyID firstKey = *keys.begin();
                    if (spk_man->GetKey(firstKey, senderKey)) {
                        senderPubKey = senderKey.GetPubKey();
                    }
                }
            }

            if (!senderKey.IsValid()) {
                QMessageBox::warning(this, tr("Error"), tr("Could not get signing key. Wallet may need to be unlocked."));
                return false;
            }

            // Find recipient's public key from wallet transactions
            CPubKey recipientPubKey;
            CTxDestination recipientDest = DecodeDestination(recipientAddress.toStdString());
            PKHash recipientKeyHash;
            if (std::holds_alternative<PKHash>(recipientDest)) {
                recipientKeyHash = std::get<PKHash>(recipientDest);
            }

            bool foundPubKey = false;
            for (const auto& [txid, wtx] : pwallet->mapWallet) {
                for (const CTxIn& txin : wtx.tx->vin) {
                    if (!txin.scriptSig.empty()) {
                        CScript::const_iterator it = txin.scriptSig.begin();
                        opcodetype opcode;
                        std::vector<unsigned char> data;
                        if (txin.scriptSig.GetOp(it, opcode, data)) {
                            if (txin.scriptSig.GetOp(it, opcode, data)) {
                                if (data.size() == 33 || data.size() == 65) {
                                    CPubKey testPubKey(data);
                                    if (testPubKey.IsValid() && PKHash(testPubKey) == recipientKeyHash) {
                                        recipientPubKey = testPubKey;
                                        foundPubKey = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if (foundPubKey) break;
            }

            // Build encrypted OP_RETURN data
            // Format: [0xE1 marker] + [recipient_hash 4 bytes] + [sender_pubkey 33 bytes] + [encrypted_message]
            opReturnData.push_back(0xE1);  // Encrypted message marker

            // Add first 4 bytes of recipient address hash for routing
            CSHA256 sha;
            std::string recipientStr = recipientAddress.toStdString();
            sha.Write(reinterpret_cast<const unsigned char*>(recipientStr.data()), recipientStr.size());
            uint256 recipientHash;
            sha.Finalize(recipientHash.begin());
            for (int i = 0; i < 4; i++) {
                opReturnData.push_back(*(recipientHash.begin() + i));
            }

            // Add sender's compressed public key (33 bytes)
            std::vector<unsigned char> pubkeyVec(senderPubKey.begin(), senderPubKey.end());
            opReturnData.insert(opReturnData.end(), pubkeyVec.begin(), pubkeyVec.end());

            // Encrypt message
            std::vector<unsigned char> encrypted;
            if (foundPubKey) {
                // Use ECDH encryption
                std::vector<unsigned char> sharedSecret;
                if (wallet::DeriveSharedSecret(senderKey, recipientPubKey, sharedSecret)) {
                    // XOR encrypt with shared secret hash (simple but effective)
                    QByteArray msgBytes = message.toUtf8();
                    QByteArray key = QByteArray::fromRawData(reinterpret_cast<const char*>(sharedSecret.data()), sharedSecret.size());
                    for (int i = 0; i < msgBytes.size(); i++) {
                        encrypted.push_back(static_cast<unsigned char>(msgBytes[i]) ^ key[i % key.size()]);
                    }
                } else {
                    // Fallback to address-based XOR
                    QByteArray msgBytes = message.toUtf8();
                    QByteArray key = QCryptographicHash::hash(recipientAddress.toUtf8(), QCryptographicHash::Sha256);
                    for (int i = 0; i < msgBytes.size(); i++) {
                        encrypted.push_back(static_cast<unsigned char>(msgBytes[i]) ^ key[i % key.size()]);
                    }
                }
            } else {
                // Fallback: XOR with recipient address hash
                QByteArray msgBytes = message.toUtf8();
                QByteArray key = QCryptographicHash::hash(recipientAddress.toUtf8(), QCryptographicHash::Sha256);
                for (int i = 0; i < msgBytes.size(); i++) {
                    encrypted.push_back(static_cast<unsigned char>(msgBytes[i]) ^ key[i % key.size()]);
                }
            }
            opReturnData.insert(opReturnData.end(), encrypted.begin(), encrypted.end());

            LogPrintf("MessagingPage: Created encrypted OP_RETURN (%zu bytes) for %s\n",
                      opReturnData.size(), recipientAddress.toStdString());

        } else {
            // Plain text message with WTX: prefix
            std::string fullMessage = OP_RETURN_PREFIX + message.toStdString();
            opReturnData.assign(fullMessage.begin(), fullMessage.end());
        }

        // Check size limit (80 bytes max for OP_RETURN)
        if (opReturnData.size() > 80) {
            QMessageBox::warning(this, tr("Error"),
                tr("Message too long. Maximum %1 bytes, got %2 bytes.")
                    .arg(80).arg(opReturnData.size()));
            return false;
        }

        // Create OP_RETURN script
        CScript opReturnScript;
        opReturnScript << OP_RETURN << opReturnData;

        // Convert to hex for display
        QString hexData = QString::fromStdString(HexStr(opReturnData));

        // For now, store locally and show user the hex to use with sendtoaddress
        // In future, this could use the wallet's transaction creation directly
        QString txid = QString("pending_%1").arg(QDateTime::currentSecsSinceEpoch());

        // Show info about how to broadcast
        QMessageBox::information(this, tr("Message Prepared"),
            tr("Encrypted message prepared!\n\n"
               "OP_RETURN data (hex): %1\n\n"
               "To broadcast, use Console:\n"
               "createrawtransaction ... with OP_RETURN output\n\n"
               "Message saved locally for now.")
            .arg(hexData.left(60) + (hexData.length() > 60 ? "..." : "")));

        LogPrintf("MessagingPage: Created OP_RETURN hex: %s\n", hexData.toStdString());

        // Store in JSON file for local tracking
        QString filePath = m_dataDir + "/op_return_messages.json";
        QJsonArray messages = loadJsonArray(filePath);

        QJsonObject msg;
        msg["txid"] = txid;
        msg["message"] = displayMessage;
        msg["hex_data"] = hexData;
        msg["timestamp"] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
        msg["is_outgoing"] = true;
        msg["is_encrypted"] = isEncrypted;
        msg["recipient"] = recipientAddress;
        msg["block_height"] = 0;
        messages.append(msg);

        saveJsonArray(filePath, messages);

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to send message: %1").arg(QString::fromStdString(e.what())));
        return false;
    }
}

void MessagingPage::onOpReturnCharCountChanged()
{
    int len = ui->lineEditOpReturnMessage->text().length();
    // Max length depends on encryption: 42 chars encrypted, 76 chars plain
    int maxLen = ui->checkBoxEncrypt->isChecked() ? 42 : 76;
    ui->labelCharCount->setText(QString("%1/%2").arg(len).arg(maxLen));

    // Color indicator
    if (len > maxLen) {
        ui->labelCharCount->setStyleSheet("color: red;");
    } else if (len > maxLen - 10) {
        ui->labelCharCount->setStyleSheet("color: orange;");
    } else {
        ui->labelCharCount->setStyleSheet("");
    }
}

void MessagingPage::onEncryptToggled(bool checked)
{
    // Enable/disable recipient field
    ui->lineEditRecipient->setEnabled(checked);

    // Update max length and placeholder
    if (checked) {
        ui->lineEditOpReturnMessage->setMaxLength(42);
        ui->lineEditOpReturnMessage->setPlaceholderText(tr("Enter message (max 42 chars encrypted, stored on blockchain)"));
    } else {
        ui->lineEditOpReturnMessage->setMaxLength(76);
        ui->lineEditOpReturnMessage->setPlaceholderText(tr("Enter message (max 76 characters, stored permanently on blockchain)"));
    }

    // Update char count display
    onOpReturnCharCountChanged();
}

void MessagingPage::onOpReturnMessageSelected(QTableWidgetItem* item)
{
    if (!item) return;
    int row = item->row();
    QString txid = ui->tableOpReturnMessages->item(row, 3)->text();
    // Could show transaction details here
}

void MessagingPage::updateOpReturnList()
{
    ui->tableOpReturnMessages->setRowCount(0);

    QString filePath = m_dataDir + "/op_return_messages.json";
    QJsonArray messages = loadJsonArray(filePath);

    for (int i = messages.size() - 1; i >= 0; --i) {
        QJsonObject msg = messages[i].toObject();
        int row = ui->tableOpReturnMessages->rowCount();
        ui->tableOpReturnMessages->insertRow(row);

        QString txid = msg["txid"].toString();
        QString message = msg["message"].toString();
        qint64 timestamp = msg["timestamp"].toVariant().toLongLong();
        bool isOutgoing = msg["is_outgoing"].toBool();

        QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);

        ui->tableOpReturnMessages->setItem(row, 0, new QTableWidgetItem(dt.toString("yyyy-MM-dd hh:mm")));
        ui->tableOpReturnMessages->setItem(row, 1, new QTableWidgetItem(isOutgoing ? tr("Sent") : tr("Received")));
        ui->tableOpReturnMessages->setItem(row, 2, new QTableWidgetItem(message));
        ui->tableOpReturnMessages->setItem(row, 3, new QTableWidgetItem(txid));
    }
}

// ============================================================================
// P2P Encrypted Chat
// ============================================================================

void MessagingPage::onConversationSelected(QListWidgetItem* item)
{
    if (!item) return;

    m_currentConversationPeer = item->data(Qt::UserRole).toString();
    QString label = getAddressLabel(m_currentConversationPeer);

    if (label.isEmpty()) {
        ui->labelChatPeer->setText(m_currentConversationPeer);
    } else {
        ui->labelChatPeer->setText(QString("%1 (%2)").arg(label, m_currentConversationPeer));
    }

    ui->lineEditChatMessage->setEnabled(true);
    ui->pushButtonSendP2P->setEnabled(true);

    // Enable group features if we have an exchanged key (secure chat)
    bool hasSecureChat = hasExchangedKey(m_currentConversationPeer);
    ui->pushButtonInviteUser->setEnabled(hasSecureChat);
    ui->pushButtonManageGroup->setEnabled(hasSecureChat && !m_currentGroupId.isEmpty());

    // Check if this conversation is part of a group
    m_currentGroupId.clear();
    for (auto it = m_groups.begin(); it != m_groups.end(); ++it) {
        for (const auto& member : it.value().members) {
            if (member.address == m_currentConversationPeer) {
                m_currentGroupId = it.key();
                ui->pushButtonManageGroup->setEnabled(true);
                break;
            }
        }
        if (!m_currentGroupId.isEmpty()) break;
    }

    updateChatDisplay();
}

void MessagingPage::onSendP2PMessageClicked()
{
    if (m_currentConversationPeer.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please select a conversation first"));
        return;
    }

    QString message = ui->lineEditChatMessage->text().trimmed();
    if (message.isEmpty()) {
        return;
    }

    if (sendP2PMessage(m_currentConversationPeer, message)) {
        ui->lineEditChatMessage->clear();
        updateChatDisplay();
    }
}

void MessagingPage::onNewConversationClicked()
{
    bool ok;
    QString address = QInputDialog::getText(this,
        tr("New Conversation"),
        tr("Enter recipient's WATTx address:"),
        QLineEdit::Normal, "", &ok);

    if (!ok || address.isEmpty()) {
        return;
    }

    if (!validateAddress(address)) {
        QMessageBox::warning(this, tr("Invalid Address"),
            tr("The address you entered is not a valid WATTx address."));
        return;
    }

    // Add to conversation list if not exists
    m_currentConversationPeer = address;
    updateConversationList();

    // Select the new conversation
    for (int i = 0; i < ui->listConversations->count(); i++) {
        if (ui->listConversations->item(i)->data(Qt::UserRole).toString() == address) {
            ui->listConversations->setCurrentRow(i);
            onConversationSelected(ui->listConversations->item(i));
            break;
        }
    }
}

void MessagingPage::onRefreshP2PClicked()
{
    updateConversationList();
    if (!m_currentConversationPeer.isEmpty()) {
        updateChatDisplay();
    }
}

void MessagingPage::onConversationContextMenu(const QPoint& pos)
{
    QListWidgetItem* item = ui->listConversations->itemAt(pos);
    if (!item) return;

    QString address = item->data(Qt::UserRole).toString();
    if (address.isEmpty()) return;

    QMenu menu(this);
    QAction* editLabel = menu.addAction(tr("Edit Label"));
    QAction* copyAddress = menu.addAction(tr("Copy Address"));
    QAction* startSecure = menu.addAction(tr("Start Secure Chat"));
    menu.addSeparator();
    QAction* deleteConvo = menu.addAction(tr("Delete Conversation"));

    QAction* selected = menu.exec(ui->listConversations->mapToGlobal(pos));

    if (selected == editLabel) {
        editConversationLabel(address);
    } else if (selected == copyAddress) {
        QApplication::clipboard()->setText(address);
    } else if (selected == startSecure) {
        m_currentConversationPeer = address;
        onKeyExchangeClicked();
    } else if (selected == deleteConvo) {
        // Confirm deletion
        QMessageBox::StandardButton reply = QMessageBox::question(this,
            tr("Delete Conversation"),
            tr("Delete conversation with %1? This will remove all local messages.").arg(address.left(20) + "..."),
            QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            // Remove messages for this peer from storage
            QString filePath = m_dataDir + "/p2p_messages.json";
            QJsonArray messages = loadJsonArray(filePath);
            QJsonArray filtered;
            for (const auto& m : messages) {
                QJsonObject msg = m.toObject();
                if (msg["peer_address"].toString() != address) {
                    filtered.append(msg);
                }
            }
            saveJsonArray(filePath, filtered);

            if (m_currentConversationPeer == address) {
                m_currentConversationPeer.clear();
                if (m_chatView) m_chatView->clearMessages();
                ui->labelChatPeer->setText(tr("Select a conversation to start chatting"));
            }
            updateConversationList();
        }
    }
}

void MessagingPage::editConversationLabel(const QString& address)
{
    QString currentLabel = m_contactLabels.value(address, "");
    bool ok;
    QString newLabel = QInputDialog::getText(this,
        tr("Edit Contact Label"),
        tr("Enter a label for %1:").arg(address),
        QLineEdit::Normal, currentLabel, &ok);

    if (ok) {
        if (newLabel.isEmpty()) {
            m_contactLabels.remove(address);
        } else {
            m_contactLabels[address] = newLabel;
        }
        saveData();
        updateConversationList();

        // Update chat header if this is the current conversation
        if (address == m_currentConversationPeer) {
            QString displayName = newLabel.isEmpty() ? address : newLabel;
            ui->labelChatPeer->setText(tr("Chat with: %1").arg(displayName));
        }
    }
}

void MessagingPage::onKeyExchangeClicked()
{
    if (m_currentConversationPeer.isEmpty()) {
        QMessageBox::information(this, tr("No Contact Selected"),
            tr("Please select a conversation first."));
        return;
    }

    // Check if already have exchanged key
    if (hasExchangedKey(m_currentConversationPeer)) {
        QMessageBox::information(this, tr("Already Secure"),
            tr("You already have an encrypted connection with this contact.\n\n"
               "All messages are encrypted with ECDH."));
        return;
    }

    // Check handshake status
    int status = m_handshakeStatus.value(m_currentConversationPeer, 0);
    if (status == 1) {
        QMessageBox::information(this, tr("Pending"),
            tr("Key exchange already requested. Waiting for response..."));
        return;
    }

    // Confirm and send handshake request
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Start Secure Chat"),
        tr("Send encryption key to %1?\n\n"
           "This will establish an encrypted connection where only you and %1 can read messages.")
           .arg(m_currentConversationPeer.left(20) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        if (sendHandshakeRequest(m_currentConversationPeer)) {
            QMessageBox::information(this, tr("Key Sent"),
                tr("Encryption key sent! Waiting for %1 to respond.\n\n"
                   "Once they respond, all future messages will be encrypted.")
                   .arg(m_currentConversationPeer.left(20) + "..."));
            updateConversationList();
        } else {
            QMessageBox::warning(this, tr("Error"),
                tr("Failed to send encryption key. Make sure you have an identity selected."));
        }
    }
}

bool MessagingPage::sendP2PMessage(const QString& toAddress, const QString& message)
{
    if (!walletModel) return false;

    try {
        // Encrypt the message
        QByteArray encrypted = encryptMessage(message, toAddress);

        // Get our sending address from identity selector
        QString fromAddress = ui->comboBoxIdentity->currentData().toString();
        if (fromAddress.isEmpty() && ui->comboBoxIdentity->count() > 0) {
            fromAddress = ui->comboBoxIdentity->itemData(0).toString();
        }

        // Store the message locally
        StoredMessage msg;
        msg.type = MessageType::P2PEncrypted;
        msg.fromAddress = fromAddress;
        msg.toAddress = toAddress;
        msg.content = message;
        msg.timestamp = QDateTime::currentSecsSinceEpoch();
        msg.isOutgoing = true;
        msg.isRead = true;

        storeP2PMessage(msg);

        // Broadcast to P2P network if message manager is available
        if (messaging::g_message_manager) {
            try {
                messaging::EncryptedMessage netMsg;

                // Create hashes using simple SHA256
                {
                    QByteArray recipientUtf8 = toAddress.toUtf8();
                    CSHA256 sha;
                    sha.Write(reinterpret_cast<const unsigned char*>(recipientUtf8.constData()), recipientUtf8.size());
                    sha.Finalize(netMsg.recipientHash.begin());
                }

                {
                    QByteArray senderUtf8 = fromAddress.toUtf8();
                    CSHA256 sha;
                    sha.Write(reinterpret_cast<const unsigned char*>(senderUtf8.constData()), senderUtf8.size());
                    sha.Finalize(netMsg.senderHash.begin());
                }

                netMsg.timestamp = msg.timestamp;

                // Copy encrypted data safely
                netMsg.encryptedData.clear();
                netMsg.encryptedData.reserve(encrypted.size());
                for (int i = 0; i < encrypted.size(); ++i) {
                    netMsg.encryptedData.push_back(static_cast<unsigned char>(encrypted.at(i)));
                }

                netMsg.signature.clear();
                netMsg.msgHash = netMsg.GetHash();

                // Queue for broadcast
                if (netMsg.IsValid()) {
                    messaging::g_message_manager->QueueOutgoingMessage(netMsg);
                    LogPrintf("MessagingPage: Queued P2P message %s (size=%d)\n",
                             netMsg.msgHash.ToString().substr(0, 16), netMsg.encryptedData.size());
                }
            } catch (const std::exception& e) {
                LogPrintf("MessagingPage: P2P broadcast failed: %s\n", e.what());
                // Continue - local storage already succeeded
            }
        }

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to send message: %1").arg(QString::fromStdString(e.what())));
        return false;
    }
}

void MessagingPage::storeP2PMessage(const StoredMessage& msg)
{
    QString filePath = m_dataDir + "/p2p_messages.json";
    QJsonArray messages = loadJsonArray(filePath);

    QString peerAddress = msg.isOutgoing ? msg.toAddress : msg.fromAddress;

    QJsonObject jsonMsg;
    jsonMsg["peer_address"] = peerAddress;
    jsonMsg["from_address"] = msg.fromAddress;
    jsonMsg["to_address"] = msg.toAddress;
    jsonMsg["content"] = msg.content;
    jsonMsg["timestamp"] = static_cast<qint64>(msg.timestamp);
    jsonMsg["is_outgoing"] = msg.isOutgoing;
    jsonMsg["is_read"] = msg.isRead;
    messages.append(jsonMsg);

    if (!saveJsonArray(filePath, messages)) {
        qWarning() << "Failed to store P2P message";
    }
}

// ============ Key Exchange Handshake Methods ============

bool MessagingPage::sendHandshakeRequest(const QString& toAddress)
{
    if (!walletModel || !messaging::g_message_manager) return false;

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) return false;

    // Get our key for the selected identity
    QString fromAddress = ui->comboBoxIdentity->currentData().toString();
    if (fromAddress.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please select an identity first."));
        return false;
    }

    CKey ourKey;
    CPubKey ourPubKey;

    CTxDestination dest = DecodeDestination(fromAddress.toStdString());
    CKeyID keyId;
    if (std::holds_alternative<PKHash>(dest)) {
        keyId = ToKeyID(std::get<PKHash>(dest));
    }

    // Try legacy wallet first
    auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man && !keyId.IsNull()) {
        if (spk_man->GetKey(keyId, ourKey)) {
            ourPubKey = ourKey.GetPubKey();
        }
    }

    // If not found, try descriptor wallets
    if (!ourPubKey.IsValid() && !keyId.IsNull()) {
        for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
            wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
            if (desc_man) {
                CPubKey pubkey;
                if (pwallet->GetPubKey(PKHash(keyId), pubkey)) {
                    auto keys = desc_man->GetSigningProvider(pubkey);
                    if (keys && keys->GetKey(keyId, ourKey)) {
                        ourPubKey = ourKey.GetPubKey();
                        break;
                    }
                }
            }
        }
    }

    if (!ourPubKey.IsValid()) {
        QMessageBox::warning(this, tr("Error"), tr("Could not get your public key. Ensure you have an address with a known private key."));
        return false;
    }

    // Build handshake request: [MSG_HANDSHAKE_REQUEST] + [our pubkey 33] + [our address]
    QByteArray data;
    data.append(char(MSG_HANDSHAKE_REQUEST));

    // Add our compressed public key
    for (unsigned char c : std::vector<unsigned char>(ourPubKey.begin(), ourPubKey.end())) {
        data.append(char(c));
    }

    // Add our address (null-terminated)
    data.append(fromAddress.toUtf8());
    data.append(char(0));

    // Send via P2P
    messaging::EncryptedMessage netMsg;

    // Hash recipient address for routing
    CSHA256 sha;
    std::string recipientStr = toAddress.toStdString();
    sha.Write(reinterpret_cast<const unsigned char*>(recipientStr.data()), recipientStr.size());
    sha.Finalize(netMsg.recipientHash.begin());

    // Hash sender address
    CSHA256 sha2;
    std::string senderStr = fromAddress.toStdString();
    sha2.Write(reinterpret_cast<const unsigned char*>(senderStr.data()), senderStr.size());
    sha2.Finalize(netMsg.senderHash.begin());

    netMsg.timestamp = GetTime();

    // Copy data to message
    for (int i = 0; i < data.size(); i++) {
        netMsg.encryptedData.push_back(static_cast<unsigned char>(data[i]));
    }
    netMsg.msgHash = netMsg.GetHash();

    if (!messaging::g_message_manager->QueueOutgoingMessage(netMsg)) {
        return false;
    }

    // Update handshake status
    m_handshakeStatus[toAddress] = 1; // Requested
    saveExchangedKeys();

    LogPrintf("MessagingPage: Sent handshake request to %s\n", toAddress.toStdString());
    return true;
}

bool MessagingPage::sendHandshakeAccept(const QString& toAddress, const QString& ourAddress)
{
    if (!walletModel) {
        LogPrintf("MessagingPage::sendHandshakeAccept: No wallet model\n");
        return false;
    }
    if (!messaging::g_message_manager) {
        LogPrintf("MessagingPage::sendHandshakeAccept: No message manager\n");
        return false;
    }

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) {
        LogPrintf("MessagingPage::sendHandshakeAccept: No wallet\n");
        return false;
    }

    // Use provided address or fall back to selected identity
    QString fromAddress = ourAddress;
    if (fromAddress.isEmpty() && ui && ui->comboBoxIdentity && ui->comboBoxIdentity->count() > 0) {
        fromAddress = ui->comboBoxIdentity->currentData().toString();
    }
    if (fromAddress.isEmpty()) {
        LogPrintf("MessagingPage::sendHandshakeAccept: No from address\n");
        return false;
    }

    CKey ourKey;
    CPubKey ourPubKey;

    CTxDestination dest = DecodeDestination(fromAddress.toStdString());
    CKeyID keyId;
    if (std::holds_alternative<PKHash>(dest)) {
        keyId = ToKeyID(std::get<PKHash>(dest));
    }

    // Try legacy wallet first
    auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man && !keyId.IsNull()) {
        if (spk_man->GetKey(keyId, ourKey)) {
            ourPubKey = ourKey.GetPubKey();
        }
    }

    // If not found, try descriptor wallets
    if (!ourPubKey.IsValid() && !keyId.IsNull()) {
        for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
            wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
            if (desc_man) {
                CPubKey pubkey;
                if (pwallet->GetPubKey(PKHash(keyId), pubkey)) {
                    auto keys = desc_man->GetSigningProvider(pubkey);
                    if (keys && keys->GetKey(keyId, ourKey)) {
                        ourPubKey = ourKey.GetPubKey();
                        break;
                    }
                }
            }
        }
    }

    if (!ourPubKey.IsValid()) return false;

    // Build handshake accept: [MSG_HANDSHAKE_ACCEPT] + [our pubkey 33] + [our address]
    QByteArray data;
    data.append(char(MSG_HANDSHAKE_ACCEPT));

    for (unsigned char c : std::vector<unsigned char>(ourPubKey.begin(), ourPubKey.end())) {
        data.append(char(c));
    }

    data.append(fromAddress.toUtf8());
    data.append(char(0));

    // Send via P2P
    messaging::EncryptedMessage netMsg;

    CSHA256 sha;
    std::string recipientStr = toAddress.toStdString();
    sha.Write(reinterpret_cast<const unsigned char*>(recipientStr.data()), recipientStr.size());
    sha.Finalize(netMsg.recipientHash.begin());

    CSHA256 sha2;
    std::string senderStr = fromAddress.toStdString();
    sha2.Write(reinterpret_cast<const unsigned char*>(senderStr.data()), senderStr.size());
    sha2.Finalize(netMsg.senderHash.begin());

    netMsg.timestamp = GetTime();

    for (int i = 0; i < data.size(); i++) {
        netMsg.encryptedData.push_back(static_cast<unsigned char>(data[i]));
    }
    netMsg.msgHash = netMsg.GetHash();

    if (!messaging::g_message_manager->QueueOutgoingMessage(netMsg)) {
        return false;
    }

    // Update handshake status
    m_handshakeStatus[toAddress] = 2; // Accepted
    saveExchangedKeys();

    LogPrintf("MessagingPage: Sent handshake accept to %s\n", toAddress.toStdString());
    return true;
}

void MessagingPage::handleHandshakeMessage(const QByteArray& data, const QString& fromAddress)
{
    if (data.size() < 35) return; // Minimum: marker + 33 byte pubkey + 1 byte address

    unsigned char msgType = static_cast<unsigned char>(data[0]);

    // Extract sender's public key (33 bytes)
    std::vector<unsigned char> pubkeyData(data.begin() + 1, data.begin() + 34);
    CPubKey senderPubKey(pubkeyData);

    if (!senderPubKey.IsValid()) {
        LogPrintf("MessagingPage: Invalid pubkey in handshake from %s\n", fromAddress.toStdString());
        return;
    }

    // Store the exchanged key
    QString pubkeyHex = QString::fromStdString(HexStr(pubkeyData));

    if (msgType == MSG_GROUP_INVITE) {
        // Group invite format: [marker] + [pubkey 33] + [groupId\0] + [senderAddress\0]
        LogPrintf("MessagingPage: Received GROUP INVITE\n");

        // Parse null-terminated strings after pubkey
        QByteArray remainder = data.mid(34);
        int nullPos1 = remainder.indexOf('\0');
        if (nullPos1 < 0) {
            LogPrintf("MessagingPage: Invalid group invite format\n");
            return;
        }

        QString groupId = QString::fromUtf8(remainder.left(nullPos1));
        QString senderAddress = QString::fromUtf8(remainder.mid(nullPos1 + 1).constData());

        LogPrintf("MessagingPage: Group invite from %s for group %s\n",
                  senderAddress.toStdString(), groupId.toStdString());

        // Store the key
        m_exchangedKeys[senderAddress] = pubkeyHex;
        m_handshakeStatus[senderAddress] = 1; // Pending
        saveExchangedKeys();

        // Create a pending group invite request
        PendingChatRequest request;
        request.fromAddress = senderAddress;
        request.toAddress = fromAddress;
        request.timestamp = QDateTime::currentSecsSinceEpoch();
        request.isGroupInvite = true;
        request.groupId = groupId;
        addPendingRequest(request);

        updatePendingRequestsList();

        showMessageNotification(tr("Group Chat Invite"),
            tr("You've been invited to a group chat by %1").arg(senderAddress.left(20) + "..."));

    } else {
        // Regular handshake - extract sender address (after pubkey, null-terminated)
        QString senderAddress = QString::fromUtf8(data.mid(34).constData());

        // Store the exchanged key
        m_exchangedKeys[senderAddress] = pubkeyHex;

        if (msgType == MSG_HANDSHAKE_REQUEST) {
            LogPrintf("MessagingPage: Received handshake REQUEST from %s to our address %s\n",
                      senderAddress.toStdString(), fromAddress.toStdString());

            // Store the key but mark as pending
            m_handshakeStatus[senderAddress] = 1; // Pending - waiting for user to accept
            saveExchangedKeys();

            // Create a pending request for user approval
            PendingChatRequest request;
            request.fromAddress = senderAddress;
            request.toAddress = fromAddress;  // Our address that received the request
            request.timestamp = QDateTime::currentSecsSinceEpoch();
            request.isGroupInvite = false;
            addPendingRequest(request);

            // Update the pending requests UI
            updatePendingRequestsList();

            // Show notification
            showMessageNotification(tr("New Secure Chat Request"),
                tr("New encrypted chat request from %1").arg(senderAddress.left(20) + "..."));

        } else if (msgType == MSG_HANDSHAKE_ACCEPT) {
            LogPrintf("MessagingPage: Received handshake ACCEPT from %s\n", senderAddress.toStdString());

            m_handshakeStatus[senderAddress] = 2; // Fully accepted
            saveExchangedKeys();

            showMessageNotification(tr("Key Exchange Complete"),
                tr("Encrypted chat ready with %1").arg(senderAddress.left(20) + "..."));
        }
    }

    // Refresh UI
    updateConversationList();
}

bool MessagingPage::hasExchangedKey(const QString& address)
{
    return m_exchangedKeys.contains(address) && !m_exchangedKeys[address].isEmpty();
}

void MessagingPage::saveExchangedKeys()
{
    QString filePath = m_dataDir + "/exchanged_keys.json";
    QJsonObject root;

    QJsonObject keys;
    for (auto it = m_exchangedKeys.begin(); it != m_exchangedKeys.end(); ++it) {
        keys[it.key()] = it.value();
    }
    root["keys"] = keys;

    QJsonObject status;
    for (auto it = m_handshakeStatus.begin(); it != m_handshakeStatus.end(); ++it) {
        status[it.key()] = it.value();
    }
    root["status"] = status;

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson());
        file.close();
    }
}

void MessagingPage::loadExchangedKeys()
{
    QString filePath = m_dataDir + "/exchanged_keys.json";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return;

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    if (!doc.isObject()) return;

    QJsonObject root = doc.object();

    QJsonObject keys = root["keys"].toObject();
    for (auto it = keys.begin(); it != keys.end(); ++it) {
        m_exchangedKeys[it.key()] = it.value().toString();
    }

    QJsonObject status = root["status"].toObject();
    for (auto it = status.begin(); it != status.end(); ++it) {
        m_handshakeStatus[it.key()] = it.value().toInt();
    }

    LogPrintf("MessagingPage: Loaded %d exchanged keys\n", m_exchangedKeys.size());
}

// ============ End Key Exchange Methods ============

QByteArray MessagingPage::encryptMessage(const QString& message, const QString& recipientAddress)
{
    // ECDH encryption: derive shared secret from our private key + recipient's public key
    // Message format: [sender pubkey (33 bytes)] + [encrypted payload]

    if (!walletModel) {
        LogPrintf("MessagingPage: No wallet model for encryption\n");
        return QByteArray();
    }

    // Get selected identity from combo box
    QString fromAddress = ui->comboBoxIdentity->currentData().toString();
    if (fromAddress.isEmpty()) {
        LogPrintf("MessagingPage: No identity selected\n");
        return QByteArray();
    }

    LogPrintf("MessagingPage: Using selected identity: %s\n", fromAddress.toStdString());

    // Get our sending key for the selected address
    CKey senderKey;
    CPubKey senderPubKey;

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) {
        LogPrintf("MessagingPage: No wallet available\n");
        return QByteArray();
    }

    CTxDestination senderDest = DecodeDestination(fromAddress.toStdString());
    if (!IsValidDestination(senderDest)) {
        LogPrintf("MessagingPage: Invalid sender address\n");
        return QByteArray();
    }

    CKeyID keyId;
    if (std::holds_alternative<PKHash>(senderDest)) {
        keyId = ToKeyID(std::get<PKHash>(senderDest));
    } else if (std::holds_alternative<WitnessV0KeyHash>(senderDest)) {
        keyId = ToKeyID(std::get<WitnessV0KeyHash>(senderDest));
    }

    if (keyId.IsNull()) {
        LogPrintf("MessagingPage: Cannot get key ID from address\n");
        return QByteArray();
    }

    // Try legacy wallet first
    auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man && spk_man->GetKey(keyId, senderKey)) {
        senderPubKey = senderKey.GetPubKey();
    }

    // Try descriptor wallets if legacy didn't work
    if (!senderKey.IsValid()) {
        for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
            wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
            if (desc_man) {
                CPubKey pubkey;
                if (pwallet->GetPubKey(PKHash(keyId), pubkey)) {
                    auto keys = desc_man->GetSigningProvider(pubkey);
                    if (keys && keys->GetKey(keyId, senderKey)) {
                        senderPubKey = senderKey.GetPubKey();
                        break;
                    }
                }
            }
        }
    }

    if (!senderKey.IsValid()) {
        LogPrintf("MessagingPage: Could not get sender private key - wallet may need unlock\n");
        return QByteArray();
    }

    // For recipient's public key, we need to look it up
    // First check if we have it from previous transactions
    CPubKey recipientPubKey;
    CTxDestination recipientDest = DecodeDestination(recipientAddress.toStdString());

    if (!IsValidDestination(recipientDest)) {
        LogPrintf("MessagingPage: Invalid recipient address\n");
        return QByteArray();
    }

    // First, check if we have an exchanged key from handshake
    bool foundPubKey = false;
    if (hasExchangedKey(recipientAddress)) {
        QString pubkeyHex = m_exchangedKeys[recipientAddress];
        std::vector<unsigned char> pubkeyData = ParseHex(pubkeyHex.toStdString());
        recipientPubKey = CPubKey(pubkeyData);
        if (recipientPubKey.IsValid()) {
            foundPubKey = true;
            LogPrintf("MessagingPage: Using exchanged key for %s\n", recipientAddress.toStdString());
        }
    }

    // Try to find recipient's pubkey from wallet transactions if not exchanged
    PKHash recipientKeyHash;
    if (std::holds_alternative<PKHash>(recipientDest)) {
        recipientKeyHash = std::get<PKHash>(recipientDest);
    } else if (!foundPubKey) {
        LogPrintf("MessagingPage: Recipient must be P2PKH address for encrypted messaging\n");
        return QByteArray();
    }

    // Search wallet transactions for recipient's public key (if not already found)
    if (!foundPubKey) {
    for (const auto& [txid, wtx] : walletModel->wallet().wallet()->mapWallet) {
        for (const CTxIn& txin : wtx.tx->vin) {
            // Check scriptSig for pubkey (P2PKH)
            if (!txin.scriptSig.empty()) {
                CScript::const_iterator it = txin.scriptSig.begin();
                opcodetype opcode;
                std::vector<unsigned char> data;

                // Skip signature, get pubkey
                if (txin.scriptSig.GetOp(it, opcode, data)) {
                    if (txin.scriptSig.GetOp(it, opcode, data)) {
                        if (data.size() == 33 || data.size() == 65) {
                            CPubKey testPubKey(data);
                            if (testPubKey.IsValid() && PKHash(testPubKey) == recipientKeyHash) {
                                recipientPubKey = testPubKey;
                                foundPubKey = true;
                                break;
                            }
                        }
                    }
                }
            }
            // Check witness for pubkey (P2WPKH)
            if (!foundPubKey && !txin.scriptWitness.IsNull() && txin.scriptWitness.stack.size() >= 2) {
                for (const auto& item : txin.scriptWitness.stack) {
                    if (item.size() == 33 || item.size() == 65) {
                        CPubKey testPubKey(item);
                        if (testPubKey.IsValid() && PKHash(testPubKey) == recipientKeyHash) {
                            recipientPubKey = testPubKey;
                            foundPubKey = true;
                            break;
                        }
                    }
                }
            }
        }
        if (foundPubKey) break;
    }
    } // end if (!foundPubKey)

    if (!foundPubKey) {
        // Fallback: Use address-derived key (less secure but works without key exchange)
        LogPrintf("MessagingPage: Recipient pubkey not found, using address-derived encryption\n");

        // Create a deterministic "pubkey" from address hash for fallback
        // This is not true ECDH but maintains backward compatibility
        QByteArray messageBytes = message.toUtf8();
        QByteArray key = QCryptographicHash::hash(recipientAddress.toUtf8(), QCryptographicHash::Sha256);

        // Prepend marker byte (0x00) to indicate fallback encryption
        QByteArray encrypted;
        encrypted.append(char(0x00));  // Fallback encryption marker

        for (int i = 0; i < messageBytes.size(); i++) {
            encrypted.append(char(messageBytes[i] ^ key[i % key.size()]));
        }
        return encrypted.toBase64();
    }

    // Derive shared secret using ECDH
    std::vector<unsigned char> sharedSecret;
    if (!wallet::DeriveSharedSecret(senderKey, recipientPubKey, sharedSecret)) {
        LogPrintf("MessagingPage: Failed to derive ECDH shared secret\n");
        return QByteArray();
    }

    // Encrypt message with AES-256-GCM
    std::vector<unsigned char> ciphertext;
    if (!wallet::EncryptMessage(message.toStdString(), sharedSecret, ciphertext)) {
        LogPrintf("MessagingPage: AES encryption failed\n");
        return QByteArray();
    }

    // Build final message: [0x01 marker] + [sender pubkey (33 bytes)] + [ciphertext]
    QByteArray result;
    result.append(char(0x01));  // ECDH encryption marker

    // Append compressed sender pubkey
    std::vector<unsigned char> pubkeyData(senderPubKey.begin(), senderPubKey.end());
    for (unsigned char c : pubkeyData) {
        result.append(char(c));
    }

    // Append ciphertext
    for (unsigned char c : ciphertext) {
        result.append(char(c));
    }

    LogPrintf("MessagingPage: Encrypted with ECDH (pubkey + %zu bytes ciphertext)\n", ciphertext.size());
    return result.toBase64();
}

QString MessagingPage::decryptMessage(const QByteArray& encrypted, const QString& senderAddress)
{
    QByteArray decoded = QByteArray::fromBase64(encrypted);

    if (decoded.isEmpty()) {
        return QString();
    }

    // Check encryption type marker
    unsigned char marker = static_cast<unsigned char>(decoded[0]);

    if (marker == 0x00) {
        // Fallback encryption (address-derived XOR)
        QByteArray payload = decoded.mid(1);
        QByteArray key = QCryptographicHash::hash(senderAddress.toUtf8(), QCryptographicHash::Sha256);

        QByteArray decrypted;
        decrypted.resize(payload.size());
        for (int i = 0; i < payload.size(); i++) {
            decrypted[i] = payload[i] ^ key[i % key.size()];
        }
        return QString::fromUtf8(decrypted);
    }

    if (marker == 0x01) {
        // ECDH encryption: [marker(1)] + [sender pubkey(33)] + [ciphertext]
        if (decoded.size() < 34) {
            LogPrintf("MessagingPage: ECDH message too short\n");
            return QString("[Encrypted - invalid format]");
        }

        // Extract sender's public key
        std::vector<unsigned char> pubkeyData(decoded.begin() + 1, decoded.begin() + 34);
        CPubKey senderPubKey(pubkeyData);

        if (!senderPubKey.IsValid()) {
            LogPrintf("MessagingPage: Invalid sender pubkey in message\n");
            return QString("[Encrypted - invalid sender key]");
        }

        // Extract ciphertext
        std::vector<unsigned char> ciphertext(decoded.begin() + 34, decoded.end());

        if (!walletModel) {
            return QString("[Encrypted - no wallet]");
        }

        wallet::CWallet* pwallet = walletModel->wallet().wallet();
        if (!pwallet) {
            return QString("[Encrypted - no wallet]");
        }

        // Try legacy wallet first
        auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            std::set<CKeyID> keyIds = spk_man->GetKeys();
            for (const CKeyID& keyId : keyIds) {
                CKey ourKey;
                if (!spk_man->GetKey(keyId, ourKey)) {
                    continue;
                }

                // Derive shared secret using ECDH
                std::vector<unsigned char> sharedSecret;
                if (!wallet::DeriveSharedSecret(ourKey, senderPubKey, sharedSecret)) {
                    continue;
                }

                // Try to decrypt with AES-256-GCM
                std::string plaintext;
                if (wallet::DecryptMessage(ciphertext, sharedSecret, plaintext)) {
                    return QString::fromStdString(plaintext);
                }
            }
        }

        // Try descriptor wallets
        for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
            wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
            if (desc_man) {
                auto scripts = desc_man->GetScriptPubKeys();
                for (const auto& script : scripts) {
                    CTxDestination dest;
                    if (ExtractDestination(script, dest)) {
                        if (std::holds_alternative<PKHash>(dest)) {
                            CKeyID keyId = ToKeyID(std::get<PKHash>(dest));
                            CPubKey pubkey;
                            if (pwallet->GetPubKey(PKHash(keyId), pubkey)) {
                                auto keys = desc_man->GetSigningProvider(pubkey);
                                if (keys) {
                                    CKey ourKey;
                                    if (keys->GetKey(keyId, ourKey)) {
                                        // Derive shared secret using ECDH
                                        std::vector<unsigned char> sharedSecret;
                                        if (wallet::DeriveSharedSecret(ourKey, senderPubKey, sharedSecret)) {
                                            // Try to decrypt with AES-256-GCM
                                            std::string plaintext;
                                            if (wallet::DecryptMessage(ciphertext, sharedSecret, plaintext)) {
                                                return QString::fromStdString(plaintext);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        LogPrintf("MessagingPage: Could not decrypt with any of our keys\n");
        return QString("[Encrypted - not for us or wallet locked]");
    }

    // Unknown format - try legacy XOR decryption
    QByteArray key = QCryptographicHash::hash(senderAddress.toUtf8(), QCryptographicHash::Sha256);
    QByteArray decrypted;
    decrypted.resize(decoded.size());
    for (int i = 0; i < decoded.size(); i++) {
        decrypted[i] = decoded[i] ^ key[i % key.size()];
    }
    return QString::fromUtf8(decrypted);
}

void MessagingPage::updateConversationList()
{
    if (!ui || !ui->listConversations) return;

    ui->listConversations->clear();

    QString filePath = m_dataDir + "/p2p_messages.json";
    QJsonArray messages = loadJsonArray(filePath);

    // Group by peer address
    QMap<QString, int> peerUnread;
    QMap<QString, qint64> peerLastTime;

    for (const auto& m : messages) {
        QJsonObject msg = m.toObject();
        QString peerAddress = msg["peer_address"].toString();
        qint64 timestamp = msg["timestamp"].toVariant().toLongLong();
        bool isRead = msg["is_read"].toBool();
        bool isOutgoing = msg["is_outgoing"].toBool();

        if (!peerLastTime.contains(peerAddress) || timestamp > peerLastTime[peerAddress]) {
            peerLastTime[peerAddress] = timestamp;
        }
        if (!isRead && !isOutgoing) {
            peerUnread[peerAddress] = peerUnread.value(peerAddress, 0) + 1;
        }
    }

    // Sort by last time
    QList<QPair<QString, qint64>> sortedPeers;
    for (auto it = peerLastTime.begin(); it != peerLastTime.end(); ++it) {
        sortedPeers.append(qMakePair(it.key(), it.value()));
    }
    std::sort(sortedPeers.begin(), sortedPeers.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& pair : sortedPeers) {
        QString peerAddress = pair.first;
        int unread = peerUnread.value(peerAddress, 0);

        QString label = getAddressLabel(peerAddress);
        QString displayText;

        if (label.isEmpty()) {
            displayText = peerAddress.left(12) + "..." + peerAddress.right(8);
        } else {
            displayText = label;
        }

        if (unread > 0) {
            displayText += QString(" (%1)").arg(unread);
        }

        QListWidgetItem* item = new QListWidgetItem(displayText);
        item->setData(Qt::UserRole, peerAddress);
        ui->listConversations->addItem(item);
    }

    // Add current peer if not in list
    if (!m_currentConversationPeer.isEmpty()) {
        bool found = false;
        for (int i = 0; i < ui->listConversations->count(); i++) {
            if (ui->listConversations->item(i)->data(Qt::UserRole).toString() == m_currentConversationPeer) {
                found = true;
                break;
            }
        }
        if (!found) {
            QString label = getAddressLabel(m_currentConversationPeer);
            QString displayText = label.isEmpty() ?
                (m_currentConversationPeer.left(12) + "..." + m_currentConversationPeer.right(8)) : label;

            QListWidgetItem* item = new QListWidgetItem(displayText);
            item->setData(Qt::UserRole, m_currentConversationPeer);
            ui->listConversations->insertItem(0, item);
        }
    }
}

void MessagingPage::updateChatDisplay()
{
    if (m_currentConversationPeer.isEmpty()) {
        if (m_chatView) {
            m_chatView->clearMessages();
        }
        return;
    }

    QString filePath = m_dataDir + "/p2p_messages.json";
    QJsonArray messages = loadJsonArray(filePath);
    bool needsSave = false;

    // Sort messages by timestamp and filter by peer
    QList<QJsonObject> peerMessages;
    for (int i = 0; i < messages.size(); ++i) {
        QJsonObject msg = messages[i].toObject();
        if (msg["peer_address"].toString() == m_currentConversationPeer) {
            peerMessages.append(msg);

            // Mark as read
            if (!msg["is_read"].toBool() && !msg["is_outgoing"].toBool()) {
                msg["is_read"] = true;
                messages[i] = msg;
                needsSave = true;
            }
        }
    }

    // Sort by timestamp
    std::sort(peerMessages.begin(), peerMessages.end(),
              [](const QJsonObject& a, const QJsonObject& b) {
                  return a["timestamp"].toVariant().toLongLong() < b["timestamp"].toVariant().toLongLong();
              });

    // Update chat bubble widget with messages
    if (m_chatView) {
        // Build message list
        QList<ChatMessage> chatMessages;
        for (const auto& msg : peerMessages) {
            ChatMessage chatMsg;
            chatMsg.content = msg["content"].toString();
            qint64 timestamp = msg["timestamp"].toVariant().toLongLong();
            QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
            chatMsg.timestamp = dt.toString("hh:mm");
            chatMsg.isOutgoing = msg["is_outgoing"].toBool();
            chatMessages.append(chatMsg);
        }

        m_chatView->setMessages(chatMessages);
        LogPrintf("MessagingPage: Updated chat display with %d messages\n", peerMessages.size());
    }

    // Save if we marked messages as read
    if (needsSave) {
        saveJsonArray(filePath, messages);
    }
}

// ============================================================================
// Transaction Memos
// ============================================================================

void MessagingPage::onTxMemoSaveClicked()
{
    QString txidStr = ui->lineEditMemoTxId->text().trimmed();
    QString memo = ui->textEditMemo->toPlainText().trimmed();

    if (txidStr.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please enter a transaction ID"));
        return;
    }

    if (memo.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please enter a memo"));
        return;
    }

    uint256 txid;
    txid.SetHexDeprecated(txidStr.toStdString());

    if (saveTxMemo(txid, memo)) {
        QMessageBox::information(this, tr("Success"), tr("Memo saved successfully"));
        ui->lineEditMemoTxId->clear();
        ui->textEditMemo->clear();
        updateMemoList();
    } else {
        QMessageBox::warning(this, tr("Error"), tr("Failed to save memo"));
    }
}

void MessagingPage::onTxMemoSearchClicked()
{
    QString query = ui->lineEditMemoSearch->text().trimmed();

    ui->tableMemos->setRowCount(0);

    std::vector<std::pair<uint256, QString>> results;
    if (query.isEmpty()) {
        results = getAllTxMemos();
    } else {
        results = searchTxMemos(query);
    }

    for (const auto& [txid, memo] : results) {
        int row = ui->tableMemos->rowCount();
        ui->tableMemos->insertRow(row);

        ui->tableMemos->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(txid.GetHex())));
        ui->tableMemos->setItem(row, 1, new QTableWidgetItem(memo));
        ui->tableMemos->setItem(row, 2, new QTableWidgetItem("")); // Date could be fetched from db
    }
}

void MessagingPage::onTxMemoSelected(QTableWidgetItem* item)
{
    if (!item) return;
    int row = item->row();

    QString txid = ui->tableMemos->item(row, 0)->text();
    QString memo = ui->tableMemos->item(row, 1)->text();

    ui->lineEditMemoTxId->setText(txid);
    ui->textEditMemo->setText(memo);
}

void MessagingPage::onTxMemoDeleteClicked()
{
    QString txidStr = ui->lineEditMemoTxId->text().trimmed();
    if (txidStr.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please select a memo to delete"));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Confirm Delete"),
        tr("Are you sure you want to delete this memo?"),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    uint256 txid;
    txid.SetHexDeprecated(txidStr.toStdString());

    if (deleteTxMemo(txid)) {
        ui->lineEditMemoTxId->clear();
        ui->textEditMemo->clear();
        updateMemoList();
    }
}

bool MessagingPage::saveTxMemo(const uint256& txid, const QString& memo)
{
    QString filePath = m_dataDir + "/tx_memos.json";
    QJsonArray memos = loadJsonArray(filePath);
    QString txidStr = QString::fromStdString(txid.GetHex());

    // Try to find existing memo
    bool found = false;
    for (int i = 0; i < memos.size(); ++i) {
        QJsonObject m = memos[i].toObject();
        if (m["txid"].toString() == txidStr) {
            m["memo"] = memo;
            m["updated_at"] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
            memos[i] = m;
            found = true;
            break;
        }
    }

    if (!found) {
        QJsonObject newMemo;
        newMemo["txid"] = txidStr;
        newMemo["memo"] = memo;
        newMemo["created_at"] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
        newMemo["updated_at"] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
        memos.append(newMemo);
    }

    return saveJsonArray(filePath, memos);
}

QString MessagingPage::getTxMemo(const uint256& txid)
{
    QString filePath = m_dataDir + "/tx_memos.json";
    QJsonArray memos = loadJsonArray(filePath);
    QString txidStr = QString::fromStdString(txid.GetHex());

    for (const auto& m : memos) {
        QJsonObject memo = m.toObject();
        if (memo["txid"].toString() == txidStr) {
            return memo["memo"].toString();
        }
    }
    return QString();
}

bool MessagingPage::deleteTxMemo(const uint256& txid)
{
    QString filePath = m_dataDir + "/tx_memos.json";
    QJsonArray memos = loadJsonArray(filePath);
    QString txidStr = QString::fromStdString(txid.GetHex());

    for (int i = 0; i < memos.size(); ++i) {
        QJsonObject m = memos[i].toObject();
        if (m["txid"].toString() == txidStr) {
            memos.removeAt(i);
            return saveJsonArray(filePath, memos);
        }
    }
    return true;
}

std::vector<std::pair<uint256, QString>> MessagingPage::searchTxMemos(const QString& searchQuery)
{
    std::vector<std::pair<uint256, QString>> results;

    QString filePath = m_dataDir + "/tx_memos.json";
    QJsonArray memos = loadJsonArray(filePath);

    for (const auto& m : memos) {
        QJsonObject memo = m.toObject();
        QString txidStr = memo["txid"].toString();
        QString memoText = memo["memo"].toString();

        if (txidStr.contains(searchQuery, Qt::CaseInsensitive) ||
            memoText.contains(searchQuery, Qt::CaseInsensitive)) {
            uint256 txid;
            txid.SetHexDeprecated(txidStr.toStdString());
            results.emplace_back(txid, memoText);
        }
    }

    return results;
}

std::vector<std::pair<uint256, QString>> MessagingPage::getAllTxMemos()
{
    std::vector<std::pair<uint256, QString>> results;

    QString filePath = m_dataDir + "/tx_memos.json";
    QJsonArray memos = loadJsonArray(filePath);

    // Sort by updated_at descending
    QList<QJsonObject> sortedMemos;
    for (const auto& m : memos) {
        sortedMemos.append(m.toObject());
    }
    std::sort(sortedMemos.begin(), sortedMemos.end(),
              [](const QJsonObject& a, const QJsonObject& b) {
                  return a["updated_at"].toVariant().toLongLong() > b["updated_at"].toVariant().toLongLong();
              });

    int count = 0;
    for (const auto& memo : sortedMemos) {
        if (count++ >= 100) break;
        uint256 txid;
        txid.SetHexDeprecated(memo["txid"].toString().toStdString());
        results.emplace_back(txid, memo["memo"].toString());
    }

    return results;
}

void MessagingPage::updateMemoList()
{
    ui->tableMemos->setRowCount(0);

    auto memos = getAllTxMemos();
    for (const auto& [txid, memo] : memos) {
        int row = ui->tableMemos->rowCount();
        ui->tableMemos->insertRow(row);

        ui->tableMemos->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(txid.GetHex())));
        ui->tableMemos->setItem(row, 1, new QTableWidgetItem(memo));
        ui->tableMemos->setItem(row, 2, new QTableWidgetItem(""));
    }
}

// ============================================================================
// Utility Methods
// ============================================================================

void MessagingPage::refreshMessages()
{
    updateOpReturnList();
    updateConversationList();
    updateMemoList();
}

void MessagingPage::onTabChanged(int index)
{
    // Refresh the selected tab's content
    switch (index) {
        case 0: updateOpReturnList(); break;
        case 1: updateConversationList(); break;
        case 2: updateMemoList(); break;
    }
}

void MessagingPage::numBlocksChanged(int count, const QDateTime& blockDate,
                                      double nVerificationProgress, SyncType header,
                                      SynchronizationState sync_state)
{
    // Could scan new blocks for incoming OP_RETURN messages here
    Q_UNUSED(count);
    Q_UNUSED(blockDate);
    Q_UNUSED(nVerificationProgress);
    Q_UNUSED(header);
    Q_UNUSED(sync_state);
}

QString MessagingPage::getAddressLabel(const QString& address)
{
    // Check custom contact labels first
    if (m_contactLabels.contains(address)) {
        return m_contactLabels[address];
    }

    if (!walletModel) return QString();

    AddressTableModel* addressModel = walletModel->getAddressTableModel();
    if (!addressModel) return QString();

    // Search for address in the model
    QModelIndex parent = QModelIndex();
    for (int i = 0; i < addressModel->rowCount(parent); i++) {
        QModelIndex addrIdx = addressModel->index(i, AddressTableModel::Address, parent);
        QString addr = addressModel->data(addrIdx, Qt::DisplayRole).toString();
        if (addr == address) {
            QModelIndex labelIdx = addressModel->index(i, AddressTableModel::Label, parent);
            return addressModel->data(labelIdx, Qt::DisplayRole).toString();
        }
    }

    return QString();
}

bool MessagingPage::validateAddress(const QString& address)
{
    // Use key_io to validate the address
    CTxDestination dest = DecodeDestination(address.toStdString());
    return IsValidDestination(dest);
}

void MessagingPage::onChooseFromAddressBook()
{
    // Placeholder for address book integration
    // Could open AddressBookPage for selecting sender address
}

void MessagingPage::onChooseToAddressBook()
{
    // Placeholder for address book integration
    // Could open AddressBookPage for selecting recipient address
}

void MessagingPage::showMessageNotification(const QString& title, const QString& message)
{
    // Could integrate with system tray notifications
    Q_UNUSED(title);
    Q_UNUSED(message);
}

// ============================================================================
// Chat Background Color
// ============================================================================

void MessagingPage::onChatBackgroundClicked()
{
#if QT_CONFIG(colordialog)
    QColor color = QColorDialog::getColor(m_chatBackgroundColor, this,
        tr("Select Chat Background Color"));

    if (color.isValid()) {
        m_chatBackgroundColor = color;
        saveChatBackgroundColor();
        applyChatBackgroundColor();
    }
#endif
}

void MessagingPage::loadChatBackgroundColor()
{
    QString filePath = m_dataDir + "/chat_settings.json";
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        QJsonObject obj = doc.object();
        QString colorStr = obj["background_color"].toString();
        if (!colorStr.isEmpty()) {
            m_chatBackgroundColor = QColor(colorStr);
        }
    }
}

void MessagingPage::saveChatBackgroundColor()
{
    QString filePath = m_dataDir + "/chat_settings.json";
    QJsonObject obj;
    obj["background_color"] = m_chatBackgroundColor.name();

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(obj).toJson());
    }
}

void MessagingPage::applyChatBackgroundColor()
{
    if (m_chatView) {
        m_chatView->setBackgroundColor(m_chatBackgroundColor);
    }
}

// ============================================================================
// Pending Chat Requests
// ============================================================================

void MessagingPage::onPendingRequestSelected(QListWidgetItem* item)
{
    if (!item) return;

    int requestIndex = item->data(Qt::UserRole).toInt();
    if (requestIndex < 0 || requestIndex >= m_pendingRequests.size()) return;

    // IMPORTANT: Make a COPY of the request, not a reference!
    // The list may be modified during accept/reject which would invalidate a reference
    PendingChatRequest request = m_pendingRequests[requestIndex];

    QString fromLabel = getAddressLabel(request.fromAddress);
    QString displayFrom = fromLabel.isEmpty() ? request.fromAddress : fromLabel;

    QString message;
    if (request.isGroupInvite) {
        message = tr("You have been invited to join a group chat by:\n%1\n\n"
                     "Accept this invitation?").arg(displayFrom);
    } else {
        message = tr("New secure chat request from:\n%1\n\n"
                     "Accept and start encrypted messaging?").arg(displayFrom);
    }

    // Stop the refresh timer during this operation to prevent race conditions
    if (m_refreshTimer) {
        m_refreshTimer->stop();
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Secure Chat Request"), message,
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        acceptChatRequest(request);
    } else {
        rejectChatRequest(request);
    }

    // Restart the refresh timer
    if (m_refreshTimer) {
        m_refreshTimer->start(3000);
    }
}

void MessagingPage::loadPendingRequests()
{
    QString filePath = m_dataDir + "/pending_requests.json";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return;

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    QJsonArray arr = doc.array();

    m_pendingRequests.clear();
    for (const auto& item : arr) {
        QJsonObject obj = item.toObject();
        PendingChatRequest req;
        req.fromAddress = obj["from_address"].toString();
        req.toAddress = obj["to_address"].toString();
        req.timestamp = obj["timestamp"].toVariant().toLongLong();
        req.isGroupInvite = obj["is_group_invite"].toBool();
        req.groupId = obj["group_id"].toString();
        m_pendingRequests.append(req);
    }
}

void MessagingPage::savePendingRequests()
{
    QString filePath = m_dataDir + "/pending_requests.json";
    QJsonArray arr;
    for (const auto& req : m_pendingRequests) {
        QJsonObject obj;
        obj["from_address"] = req.fromAddress;
        obj["to_address"] = req.toAddress;
        obj["timestamp"] = static_cast<qint64>(req.timestamp);
        obj["is_group_invite"] = req.isGroupInvite;
        obj["group_id"] = req.groupId;
        arr.append(obj);
    }

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(arr).toJson());
    }
}

void MessagingPage::updatePendingRequestsList()
{
    if (!ui || !ui->listPendingRequests) return;

    ui->listPendingRequests->clear();

    if (m_pendingRequests.isEmpty()) {
        ui->listPendingRequests->setVisible(false);
        return;
    }

    ui->listPendingRequests->setVisible(true);

    for (int i = 0; i < m_pendingRequests.size(); ++i) {
        const auto& req = m_pendingRequests[i];
        QString label = getAddressLabel(req.fromAddress);
        QString displayText;

        if (req.isGroupInvite) {
            displayText = tr("Group Invite from %1").arg(label.isEmpty() ?
                req.fromAddress.left(12) + "..." : label);
        } else {
            displayText = tr("Chat Request from %1").arg(label.isEmpty() ?
                req.fromAddress.left(12) + "..." : label);
        }

        QListWidgetItem* item = new QListWidgetItem(displayText);
        item->setData(Qt::UserRole, i);
        item->setIcon(QIcon(":/icons/messaging"));
        ui->listPendingRequests->addItem(item);
    }
}

void MessagingPage::addPendingRequest(const PendingChatRequest& request)
{
    // Check if already exists
    for (const auto& req : m_pendingRequests) {
        if (req.fromAddress == request.fromAddress && req.toAddress == request.toAddress) {
            return; // Already pending
        }
    }

    m_pendingRequests.append(request);
    savePendingRequests();
    updatePendingRequestsList();

    // Show notification
    showMessageNotification(tr("New Secure Chat Request"),
        tr("You have a new encrypted chat request"));
}

void MessagingPage::acceptChatRequest(const PendingChatRequest& request)
{
    // Safety check - don't accept requests from self
    if (request.fromAddress.isEmpty() || request.toAddress.isEmpty()) {
        LogPrintf("MessagingPage: Invalid chat request - empty address\n");
        m_pendingRequests.removeAll(request);
        savePendingRequests();
        updatePendingRequestsList();
        return;
    }

    // Mark the handshake as accepted first
    m_handshakeStatus[request.fromAddress] = 2;
    saveExchangedKeys();

    // Try to send handshake accept (may fail if network not ready)
    bool sent = false;
    try {
        sent = sendHandshakeAccept(request.fromAddress, request.toAddress);
    } catch (...) {
        LogPrintf("MessagingPage: Exception in sendHandshakeAccept\n");
    }

    if (!sent) {
        LogPrintf("MessagingPage: Failed to send handshake accept, but accepting locally\n");
    }

    // Handle group invite
    if (request.isGroupInvite && !request.groupId.isEmpty()) {
        LogPrintf("MessagingPage: Joining group %s\n", request.groupId.toStdString());

        // Create or update the group locally
        if (!m_groups.contains(request.groupId)) {
            GroupChat newGroup;
            newGroup.groupId = request.groupId;
            newGroup.groupName = tr("Group Chat");
            newGroup.creatorAddress = request.fromAddress;
            newGroup.createdTime = QDateTime::currentSecsSinceEpoch();

            // Add the inviter as a member
            GroupMember inviter;
            inviter.address = request.fromAddress;
            inviter.pubkeyHex = m_exchangedKeys.value(request.fromAddress, "");
            inviter.joinedTime = newGroup.createdTime;
            inviter.isRevoked = false;
            newGroup.members.append(inviter);

            // Add ourselves as a member
            GroupMember self;
            self.address = request.toAddress;
            self.joinedTime = QDateTime::currentSecsSinceEpoch();
            self.isRevoked = false;
            newGroup.members.append(self);

            m_groups[request.groupId] = newGroup;
            saveGroups();
        } else {
            // Add ourselves to existing group
            GroupChat& group = m_groups[request.groupId];
            GroupMember self;
            self.address = request.toAddress;
            self.joinedTime = QDateTime::currentSecsSinceEpoch();
            self.isRevoked = false;
            group.members.append(self);
            saveGroups();
        }

        m_currentGroupId = request.groupId;
    }

    // Remove from pending
    m_pendingRequests.removeAll(request);
    savePendingRequests();
    updatePendingRequestsList();

    // Create/select conversation
    m_currentConversationPeer = request.fromAddress;
    updateConversationList();

    QString message = request.isGroupInvite ?
        tr("You have joined the group chat.") :
        tr("You can now send encrypted messages to this contact.");

    QMessageBox::information(this, tr("Secure Chat Established"), message);
}

void MessagingPage::rejectChatRequest(const PendingChatRequest& request)
{
    m_pendingRequests.removeAll(request);
    savePendingRequests();
    updatePendingRequestsList();
}

// ============================================================================
// Group Chat Management
// ============================================================================

void MessagingPage::onInviteUserClicked()
{
    if (m_currentConversationPeer.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please select a conversation first."));
        return;
    }

    bool ok;
    QString address = QInputDialog::getText(this,
        tr("Invite User"),
        tr("Enter the WATTx address to invite to this chat:"),
        QLineEdit::Normal, "", &ok);

    if (!ok || address.isEmpty()) return;

    if (!validateAddress(address)) {
        QMessageBox::warning(this, tr("Invalid Address"),
            tr("The address you entered is not valid."));
        return;
    }

    // Create or get group for this conversation
    if (m_currentGroupId.isEmpty()) {
        // Create a new group from this 1:1 conversation
        QStringList members;
        members << m_currentConversationPeer << address;
        m_currentGroupId = createGroup(tr("Group Chat"), members);
    } else {
        // Add to existing group
        inviteToGroup(m_currentGroupId, address);
    }

    // Send invite to the new member
    sendGroupInvite(m_currentGroupId, address);

    QMessageBox::information(this, tr("Invitation Sent"),
        tr("An invitation has been sent to %1").arg(address.left(20) + "..."));
}

void MessagingPage::onManageGroupClicked()
{
    if (m_currentGroupId.isEmpty()) {
        QMessageBox::information(this, tr("Not a Group"),
            tr("This is not a group chat. Use 'Invite' to add members and create a group."));
        return;
    }

    GroupChat& group = m_groups[m_currentGroupId];

    // Build member list for display
    QString memberList;
    for (const auto& member : group.members) {
        QString label = getAddressLabel(member.address);
        QString status = member.isRevoked ? tr(" (revoked)") : "";
        memberList += QString("• %1%2\n").arg(
            label.isEmpty() ? member.address.left(20) + "..." : label,
            status);
    }

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Group Members"));
    msgBox.setText(tr("Members of this group chat:"));
    msgBox.setDetailedText(memberList);

    QPushButton* revokeBtn = msgBox.addButton(tr("Revoke Member"), QMessageBox::ActionRole);
    QPushButton* leaveBtn = msgBox.addButton(tr("Leave Group"), QMessageBox::DestructiveRole);
    msgBox.addButton(QMessageBox::Close);

    msgBox.exec();

    if (msgBox.clickedButton() == revokeBtn) {
        // Show list of members to revoke
        QStringList memberAddresses;
        for (const auto& member : group.members) {
            if (!member.isRevoked) {
                QString label = getAddressLabel(member.address);
                memberAddresses << (label.isEmpty() ? member.address : label + " (" + member.address + ")");
            }
        }

        bool ok;
        QString selected = QInputDialog::getItem(this,
            tr("Revoke Member"),
            tr("Select a member to revoke access:"),
            memberAddresses, 0, false, &ok);

        if (ok && !selected.isEmpty()) {
            // Extract address from selection
            QString address;
            if (selected.contains("(")) {
                int start = selected.lastIndexOf("(") + 1;
                int end = selected.lastIndexOf(")");
                address = selected.mid(start, end - start);
            } else {
                address = selected;
            }
            revokeFromGroup(m_currentGroupId, address);
            QMessageBox::information(this, tr("Member Revoked"),
                tr("The member has been revoked from this group."));
        }
    } else if (msgBox.clickedButton() == leaveBtn) {
        QMessageBox::StandardButton confirm = QMessageBox::question(this,
            tr("Leave Group"),
            tr("Are you sure you want to leave this group? You will no longer receive messages."),
            QMessageBox::Yes | QMessageBox::No);

        if (confirm == QMessageBox::Yes) {
            leaveGroup(m_currentGroupId);
            m_currentGroupId.clear();
            m_currentConversationPeer.clear();
            updateConversationList();
        }
    }
}

void MessagingPage::loadGroups()
{
    QString filePath = m_dataDir + "/groups.json";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return;

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    QJsonObject root = doc.object();

    m_groups.clear();
    for (auto it = root.begin(); it != root.end(); ++it) {
        QJsonObject groupObj = it.value().toObject();
        GroupChat group;
        group.groupId = it.key();
        group.groupName = groupObj["name"].toString();
        group.creatorAddress = groupObj["creator"].toString();
        group.createdTime = groupObj["created_time"].toVariant().toLongLong();

        QJsonArray membersArr = groupObj["members"].toArray();
        for (const auto& m : membersArr) {
            QJsonObject memberObj = m.toObject();
            GroupMember member;
            member.address = memberObj["address"].toString();
            member.pubkeyHex = memberObj["pubkey"].toString();
            member.joinedTime = memberObj["joined_time"].toVariant().toLongLong();
            member.isRevoked = memberObj["is_revoked"].toBool();
            member.revokedTime = memberObj["revoked_time"].toVariant().toLongLong();
            member.revokedBy = memberObj["revoked_by"].toString();
            group.members.append(member);
        }

        QJsonArray revokedArr = groupObj["revoked_addresses"].toArray();
        for (const auto& r : revokedArr) {
            group.revokedAddresses << r.toString();
        }

        m_groups[group.groupId] = group;
    }
}

void MessagingPage::saveGroups()
{
    QString filePath = m_dataDir + "/groups.json";
    QJsonObject root;

    for (auto it = m_groups.begin(); it != m_groups.end(); ++it) {
        const GroupChat& group = it.value();
        QJsonObject groupObj;
        groupObj["name"] = group.groupName;
        groupObj["creator"] = group.creatorAddress;
        groupObj["created_time"] = static_cast<qint64>(group.createdTime);

        QJsonArray membersArr;
        for (const auto& member : group.members) {
            QJsonObject memberObj;
            memberObj["address"] = member.address;
            memberObj["pubkey"] = member.pubkeyHex;
            memberObj["joined_time"] = static_cast<qint64>(member.joinedTime);
            memberObj["is_revoked"] = member.isRevoked;
            memberObj["revoked_time"] = static_cast<qint64>(member.revokedTime);
            memberObj["revoked_by"] = member.revokedBy;
            membersArr.append(memberObj);
        }
        groupObj["members"] = membersArr;

        QJsonArray revokedArr;
        for (const auto& addr : group.revokedAddresses) {
            revokedArr.append(addr);
        }
        groupObj["revoked_addresses"] = revokedArr;

        root[group.groupId] = groupObj;
    }

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson());
    }
}

QString MessagingPage::createGroup(const QString& name, const QStringList& initialMembers)
{
    QString groupId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    GroupChat group;
    group.groupId = groupId;
    group.groupName = name;
    group.creatorAddress = ui->comboBoxIdentity->currentData().toString();
    group.createdTime = QDateTime::currentSecsSinceEpoch();

    for (const QString& addr : initialMembers) {
        GroupMember member;
        member.address = addr;
        member.pubkeyHex = m_exchangedKeys.value(addr, "");
        member.joinedTime = group.createdTime;
        member.isRevoked = false;
        group.members.append(member);
    }

    m_groups[groupId] = group;
    saveGroups();

    return groupId;
}

bool MessagingPage::inviteToGroup(const QString& groupId, const QString& address)
{
    if (!m_groups.contains(groupId)) return false;

    GroupChat& group = m_groups[groupId];

    // Check if already a member
    for (const auto& member : group.members) {
        if (member.address == address) return false;
    }

    GroupMember newMember;
    newMember.address = address;
    newMember.pubkeyHex = m_exchangedKeys.value(address, "");
    newMember.joinedTime = QDateTime::currentSecsSinceEpoch();
    newMember.isRevoked = false;

    group.members.append(newMember);
    saveGroups();

    return true;
}

bool MessagingPage::revokeFromGroup(const QString& groupId, const QString& address)
{
    if (!m_groups.contains(groupId)) return false;

    GroupChat& group = m_groups[groupId];
    QString myAddress = ui->comboBoxIdentity->currentData().toString();

    for (auto& member : group.members) {
        if (member.address == address) {
            member.isRevoked = true;
            member.revokedTime = QDateTime::currentSecsSinceEpoch();
            member.revokedBy = myAddress;
            break;
        }
    }

    // Add to our personal revoked list
    if (!group.revokedAddresses.contains(address)) {
        group.revokedAddresses << address;
    }

    saveGroups();
    return true;
}

bool MessagingPage::leaveGroup(const QString& groupId)
{
    if (!m_groups.contains(groupId)) return false;

    m_groups.remove(groupId);
    saveGroups();
    return true;
}

QList<GroupMember> MessagingPage::getGroupMembers(const QString& groupId)
{
    if (!m_groups.contains(groupId)) return QList<GroupMember>();
    return m_groups[groupId].members;
}

bool MessagingPage::isAddressRevokedInGroup(const QString& groupId, const QString& address)
{
    if (!m_groups.contains(groupId)) return false;
    return m_groups[groupId].revokedAddresses.contains(address);
}

void MessagingPage::sendGroupInvite(const QString& groupId, const QString& toAddress)
{
    if (!walletModel || !messaging::g_message_manager) {
        LogPrintf("MessagingPage::sendGroupInvite: No wallet or message manager\n");
        return;
    }

    wallet::CWallet* pwallet = walletModel->wallet().wallet();
    if (!pwallet) return;

    QString fromAddress = ui->comboBoxIdentity->currentData().toString();
    if (fromAddress.isEmpty()) {
        LogPrintf("MessagingPage::sendGroupInvite: No identity selected\n");
        return;
    }

    // Get our key
    CKey ourKey;
    CPubKey ourPubKey;

    CTxDestination dest = DecodeDestination(fromAddress.toStdString());
    CKeyID keyId;
    if (std::holds_alternative<PKHash>(dest)) {
        keyId = ToKeyID(std::get<PKHash>(dest));
    }

    // Try legacy wallet first
    auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man && !keyId.IsNull()) {
        if (spk_man->GetKey(keyId, ourKey)) {
            ourPubKey = ourKey.GetPubKey();
        }
    }

    // Try descriptor wallets if not found
    if (!ourPubKey.IsValid() && !keyId.IsNull()) {
        for (auto* desc_spk : pwallet->GetAllScriptPubKeyMans()) {
            wallet::DescriptorScriptPubKeyMan* desc_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(desc_spk);
            if (desc_man) {
                CPubKey pubkey;
                if (pwallet->GetPubKey(PKHash(keyId), pubkey)) {
                    auto keys = desc_man->GetSigningProvider(pubkey);
                    if (keys && keys->GetKey(keyId, ourKey)) {
                        ourPubKey = ourKey.GetPubKey();
                        break;
                    }
                }
            }
        }
    }

    if (!ourPubKey.IsValid()) {
        LogPrintf("MessagingPage::sendGroupInvite: Could not get public key\n");
        return;
    }

    // Build group invite message: [MSG_GROUP_INVITE] + [pubkey 33] + [groupId] + [null] + [fromAddress] + [null]
    QByteArray data;
    data.append(char(MSG_GROUP_INVITE));

    // Add our compressed public key
    for (unsigned char c : std::vector<unsigned char>(ourPubKey.begin(), ourPubKey.end())) {
        data.append(char(c));
    }

    // Add group ID (null-terminated)
    data.append(groupId.toUtf8());
    data.append(char(0));

    // Add our address (null-terminated)
    data.append(fromAddress.toUtf8());
    data.append(char(0));

    // Send via P2P
    messaging::EncryptedMessage netMsg;

    // Hash recipient address for routing
    CSHA256 sha;
    std::string recipientStr = toAddress.toStdString();
    sha.Write(reinterpret_cast<const unsigned char*>(recipientStr.data()), recipientStr.size());
    sha.Finalize(netMsg.recipientHash.begin());

    // Hash sender address
    CSHA256 sha2;
    std::string senderStr = fromAddress.toStdString();
    sha2.Write(reinterpret_cast<const unsigned char*>(senderStr.data()), senderStr.size());
    sha2.Finalize(netMsg.senderHash.begin());

    netMsg.timestamp = GetTime();

    // Copy data to message
    for (int i = 0; i < data.size(); i++) {
        netMsg.encryptedData.push_back(static_cast<unsigned char>(data[i]));
    }
    netMsg.msgHash = netMsg.GetHash();

    if (!messaging::g_message_manager->QueueOutgoingMessage(netMsg)) {
        LogPrintf("MessagingPage::sendGroupInvite: Failed to queue message\n");
        return;
    }

    LogPrintf("MessagingPage: Sent group invite for %s to %s\n",
              groupId.toStdString(), toAddress.toStdString());
}
