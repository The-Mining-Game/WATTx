// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/miningpage.h>
#include <qt/clientmodel.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/guiutil.h>
#include <qt/addresstablemodel.h>
#include <qt/rpcconsole.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <univalue.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <util/time.h>
#include <node/randomx_miner.h>
#include <pow.h>
#include <util/strencodings.h>
#include <streams.h>
#include <consensus/merkle.h>
#include <script/script.h>
#include <key_io.h>
#include <core_io.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QSlider>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QProgressBar>
#include <QButtonGroup>
#include <QMessageBox>
#include <QThread>
#include <QApplication>
#include <QTextEdit>
#include <QDateTime>

MiningPage::MiningPage(const PlatformStyle *_platformStyle, QWidget *parent)
    : QWidget(parent)
    , clientModel(nullptr)
    , walletModel(nullptr)
    , platformStyle(_platformStyle)
    , currentGpuBandwidth(50)
{
    setupUi();

    // Stats update timer
    statsTimer = new QTimer(this);
    connect(statsTimer, &QTimer::timeout, this, &MiningPage::updateMiningStats);
}

MiningPage::~MiningPage()
{
    if (statsTimer) {
        statsTimer->stop();
    }
    // Stop mining if active
    if (isMining) {
        node::GetRandomXMiner().StopMining();
    }
}

void MiningPage::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);

    // Title
    QLabel *titleLabel = new QLabel(tr("WATTx Mining (RandomX Algorithm)"), this);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    // Info about RandomX
    QLabel *infoLabel = new QLabel(tr("RandomX is an ASIC-resistant, CPU-optimized proof-of-work algorithm."), this);
    infoLabel->setStyleSheet("color: #888; font-style: italic;");
    infoLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(infoLabel);

    // Mining mode selection
    QGroupBox *modeGroup = new QGroupBox(tr("Mining Mode"), this);
    QHBoxLayout *modeLayout = new QHBoxLayout(modeGroup);

    soloMiningRadio = new QRadioButton(tr("Solo Mining"), this);
    poolMiningRadio = new QRadioButton(tr("Pool Mining"), this);
    soloMiningRadio->setChecked(true);

    QButtonGroup *modeButtonGroup = new QButtonGroup(this);
    modeButtonGroup->addButton(soloMiningRadio);
    modeButtonGroup->addButton(poolMiningRadio);

    modeLayout->addWidget(soloMiningRadio);
    modeLayout->addWidget(poolMiningRadio);
    modeLayout->addStretch();
    mainLayout->addWidget(modeGroup);

    connect(soloMiningRadio, &QRadioButton::toggled, this, &MiningPage::onMiningModeChanged);

    // CPU Mining Controls (RandomX is CPU-optimized)
    QGroupBox *cpuGroup = new QGroupBox(tr("CPU Mining (Recommended for RandomX)"), this);
    createCpuControls(cpuGroup);
    mainLayout->addWidget(cpuGroup);

    // Mining Address
    QGroupBox *addressGroup = new QGroupBox(tr("Mining Reward Address"), this);
    QHBoxLayout *addressLayout = new QHBoxLayout(addressGroup);

    miningAddressCombo = new QComboBox(this);
    miningAddressCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    refreshAddressesBtn = new QPushButton(tr("Refresh"), this);

    addressLayout->addWidget(new QLabel(tr("Pay to:"), this));
    addressLayout->addWidget(miningAddressCombo, 1);
    addressLayout->addWidget(refreshAddressesBtn);
    mainLayout->addWidget(addressGroup);

    connect(refreshAddressesBtn, &QPushButton::clicked, this, &MiningPage::onRefreshAddresses);

    // Pool Settings (initially hidden)
    poolSettingsGroup = new QGroupBox(tr("Pool Settings"), this);
    createPoolControls(poolSettingsGroup);
    poolSettingsGroup->setVisible(false);
    mainLayout->addWidget(poolSettingsGroup);

    // RandomX Settings
    QGroupBox *rxSettingsGroup = new QGroupBox(tr("RandomX Settings"), this);
    QHBoxLayout *rxLayout = new QHBoxLayout(rxSettingsGroup);

    QLabel *modeLabel = new QLabel(tr("Mining Mode:"), this);
    rxModeCombo = new QComboBox(this);  // Store in member variable
    rxModeCombo->addItem(tr("Light Mode (~256 MB RAM)"), 0);
    rxModeCombo->addItem(tr("Full Mode (~2 GB RAM, faster)"), 1);
    rxModeCombo->setCurrentIndex(0);  // Default to light mode
    rxModeCombo->setToolTip(tr("Full mode uses more memory but mines faster"));

    // Safe mode checkbox - disables JIT compilation to prevent crashes
    safeModeCheckbox = new QCheckBox(tr("Safe Mode"), this);
    safeModeCheckbox->setChecked(true);  // Default to safe mode ON
    safeModeCheckbox->setToolTip(tr("Disable JIT compilation for stability. Uncheck for faster mining if your system is stable."));

    rxLayout->addWidget(modeLabel);
    rxLayout->addWidget(rxModeCombo);
    rxLayout->addSpacing(20);
    rxLayout->addWidget(safeModeCheckbox);
    rxLayout->addStretch();
    mainLayout->addWidget(rxSettingsGroup);

    // Not used for RandomX
    shiftSpinBox = nullptr;
    shiftLabel = nullptr;

    // Control Button (single toggle)
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    miningToggleBtn = new QPushButton(tr("Start Miner"), this);
    miningToggleBtn->setMinimumWidth(180);
    miningToggleBtn->setMinimumHeight(50);
    updateMiningButton(false);  // Initialize as stopped state

    buttonLayout->addWidget(miningToggleBtn);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    connect(miningToggleBtn, &QPushButton::clicked, this, &MiningPage::onMiningToggleClicked);

    // Statistics Display
    QGroupBox *statsGroup = new QGroupBox(tr("Mining Statistics"), this);
    createStatsDisplay(statsGroup);
    mainLayout->addWidget(statsGroup);

    // Mining Console (real-time output)
    QGroupBox *consoleGroup = new QGroupBox(tr("Mining Console"), this);
    QVBoxLayout *consoleLayout = new QVBoxLayout(consoleGroup);

    showConsoleCheckbox = new QCheckBox(tr("Show real-time mining output"), this);
    showConsoleCheckbox->setChecked(true);
    consoleLayout->addWidget(showConsoleCheckbox);

    miningConsole = new QTextEdit(this);
    miningConsole->setReadOnly(true);
    miningConsole->setFont(QFont("Monospace", 9));
    miningConsole->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #00ff00; }");
    miningConsole->setMinimumHeight(150);
    miningConsole->setPlaceholderText(tr("Mining output will appear here when mining starts..."));
    consoleLayout->addWidget(miningConsole);

    mainLayout->addWidget(consoleGroup);

    connect(showConsoleCheckbox, &QCheckBox::toggled, miningConsole, &QTextEdit::setVisible);

    mainLayout->addStretch();
    setLayout(mainLayout);
}

void MiningPage::createCpuControls(QGroupBox *group)
{
    QVBoxLayout *layout = new QVBoxLayout(group);

    enableCpuMining = new QCheckBox(tr("Enable CPU Mining"), this);
    enableCpuMining->setChecked(true);
    layout->addWidget(enableCpuMining);

    int maxThreads = QThread::idealThreadCount();
    cpuCoresAvailableLabel = new QLabel(tr("Available CPU cores: %1").arg(maxThreads), this);
    layout->addWidget(cpuCoresAvailableLabel);

    QHBoxLayout *threadsLayout = new QHBoxLayout();
    cpuThreadsLabel = new QLabel(tr("Mining Threads:"), this);
    cpuThreadsSpinBox = new QSpinBox(this);
    cpuThreadsSpinBox->setRange(1, maxThreads);
    cpuThreadsSpinBox->setValue(qMax(1, maxThreads - 1));  // Leave 1 core for system
    cpuThreadsSpinBox->setToolTip(tr("Number of CPU threads to use for mining. Leave 1 core free for UI responsiveness."));

    threadsLayout->addWidget(cpuThreadsLabel);
    threadsLayout->addWidget(cpuThreadsSpinBox);
    threadsLayout->addStretch();
    layout->addLayout(threadsLayout);

    // RandomX features info
    QLabel *rxInfoLabel = new QLabel(this);
    rxInfoLabel->setText(tr("RandomX features: %1").arg(
        node::RandomXMiner::HasHardwareAES() ? "Hardware AES" : "Software AES"));
    rxInfoLabel->setStyleSheet("color: #888;");
    layout->addWidget(rxInfoLabel);

    connect(cpuThreadsSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &MiningPage::onCpuThreadsChanged);
    connect(enableCpuMining, &QCheckBox::toggled, [this](bool checked) {
        cpuThreadsSpinBox->setEnabled(checked);
    });
}

void MiningPage::createGpuControls(QGroupBox *group)
{
    // RandomX doesn't use GPU - this is a stub for compatibility
    QVBoxLayout *layout = new QVBoxLayout(group);

    enableGpuMining = new QCheckBox(tr("GPU Mining (Not available for RandomX)"), this);
    enableGpuMining->setChecked(false);
    enableGpuMining->setEnabled(false);
    enableGpuMining->setToolTip(tr("RandomX is optimized for CPU mining. GPU support is not available."));
    layout->addWidget(enableGpuMining);

    gpuDeviceCombo = new QComboBox(this);
    gpuDeviceCombo->addItem(tr("Not available for RandomX"), -1);
    gpuDeviceCombo->setEnabled(false);
    layout->addWidget(gpuDeviceCombo);

    gpuBandwidthSlider = new QSlider(Qt::Horizontal, this);
    gpuBandwidthSlider->setEnabled(false);
    gpuBandwidthLabel = new QLabel(tr("N/A"), this);
    gpuBandwidthValueLabel = new QLabel("N/A", this);
}

void MiningPage::createPoolControls(QGroupBox *group)
{
    QGridLayout *layout = new QGridLayout(group);

    layout->addWidget(new QLabel(tr("Pool URL:"), this), 0, 0);
    poolUrlEdit = new QLineEdit(this);
    poolUrlEdit->setPlaceholderText(tr("stratum+tcp://pool.example.com:3333"));
    layout->addWidget(poolUrlEdit, 0, 1);

    layout->addWidget(new QLabel(tr("Worker Name:"), this), 1, 0);
    poolWorkerEdit = new QLineEdit(this);
    poolWorkerEdit->setPlaceholderText(tr("wallet_address.worker_name"));
    layout->addWidget(poolWorkerEdit, 1, 1);

    layout->addWidget(new QLabel(tr("Password:"), this), 2, 0);
    poolPasswordEdit = new QLineEdit(this);
    poolPasswordEdit->setPlaceholderText(tr("x (usually not required)"));
    poolPasswordEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(poolPasswordEdit, 2, 1);

    connect(poolUrlEdit, &QLineEdit::textChanged, this, &MiningPage::onPoolUrlChanged);
}

void MiningPage::createStatsDisplay(QGroupBox *group)
{
    QGridLayout *layout = new QGridLayout(group);

    // Status
    layout->addWidget(new QLabel(tr("Status:"), this), 0, 0);
    statusLabel = new QLabel(tr("Idle"), this);
    statusLabel->setStyleSheet("font-weight: bold;");
    layout->addWidget(statusLabel, 0, 1);

    // Hash Rate
    layout->addWidget(new QLabel(tr("Hash Rate:"), this), 0, 2);
    hashRateLabel = new QLabel(tr("0 H/s"), this);
    layout->addWidget(hashRateLabel, 0, 3);

    // Total Hashes
    layout->addWidget(new QLabel(tr("Total Hashes:"), this), 1, 0);
    primesFoundLabel = new QLabel("0", this);
    layout->addWidget(primesFoundLabel, 1, 1);

    // Shares Submitted (for pool mining)
    layout->addWidget(new QLabel(tr("Accepted:"), this), 1, 2);
    gapsCheckedLabel = new QLabel("0", this);
    layout->addWidget(gapsCheckedLabel, 1, 3);

    // Blocks Found
    layout->addWidget(new QLabel(tr("Blocks Found:"), this), 2, 0);
    blocksFoundLabel = new QLabel("0", this);
    blocksFoundLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    layout->addWidget(blocksFoundLabel, 2, 1);

    // Uptime
    layout->addWidget(new QLabel(tr("Uptime:"), this), 2, 2);
    bestMeritLabel = new QLabel("00:00:00", this);
    layout->addWidget(bestMeritLabel, 2, 3);

    // Current Difficulty
    layout->addWidget(new QLabel(tr("Network Difficulty:"), this), 3, 0);
    currentDifficultyLabel = new QLabel("0", this);
    layout->addWidget(currentDifficultyLabel, 3, 1);

    // Progress bar
    miningProgressBar = new QProgressBar(this);
    miningProgressBar->setRange(0, 100);
    miningProgressBar->setValue(0);
    miningProgressBar->setTextVisible(false);
    layout->addWidget(miningProgressBar, 4, 0, 1, 4);
}

void MiningPage::setClientModel(ClientModel *_clientModel)
{
    clientModel = _clientModel;
}

void MiningPage::setWalletModel(WalletModel *_walletModel)
{
    walletModel = _walletModel;
    if (walletModel) {
        updateAddressCombo();
    }
}

void MiningPage::updateAddressCombo()
{
    if (!walletModel) return;

    miningAddressCombo->clear();

    // Get receiving addresses from wallet
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    if (addressModel) {
        QModelIndex parent;
        for (int i = 0; i < addressModel->rowCount(parent); i++) {
            QModelIndex addressIdx = addressModel->index(i, AddressTableModel::Address, parent);
            QModelIndex labelIdx = addressModel->index(i, AddressTableModel::Label, parent);
            QString address = addressModel->data(addressIdx, Qt::DisplayRole).toString();
            QString label = addressModel->data(labelIdx, Qt::DisplayRole).toString();
            QString type = addressModel->data(addressIdx, AddressTableModel::TypeRole).toString();

            if (type == AddressTableModel::Receive) {
                QString displayText = label.isEmpty() ? address : QString("%1 (%2)").arg(label, address);
                miningAddressCombo->addItem(displayText, address);
            }
        }
    }

    // Add option to generate new address
    miningAddressCombo->addItem(tr("Generate new address..."), "new");
}

void MiningPage::onMiningModeChanged()
{
    bool isPool = poolMiningRadio->isChecked();
    poolSettingsGroup->setVisible(isPool);
}

void MiningPage::onCpuThreadsChanged(int value)
{
    currentCpuThreads = value;

    // If mining is active, log thread change (actual restart happens on next block)
    if (isMining) {
        logToConsole(tr("Thread count changed to %1 - will apply on next block").arg(value));
    }
}

void MiningPage::onGpuBandwidthChanged(int value)
{
    currentGpuBandwidth = value;
    if (gpuBandwidthValueLabel) {
        gpuBandwidthValueLabel->setText(QString("%1%").arg(value));
    }
}

void MiningPage::onRefreshAddresses()
{
    updateAddressCombo();
}

void MiningPage::onPoolUrlChanged()
{
    // Validate pool URL format
    QString url = poolUrlEdit->text();
    if (!url.isEmpty() && !url.startsWith("stratum+tcp://") && !url.startsWith("stratum+ssl://")) {
        poolUrlEdit->setStyleSheet("border: 1px solid orange;");
    } else {
        poolUrlEdit->setStyleSheet("");
    }
}

bool MiningPage::validatePoolSettings()
{
    if (poolMiningRadio->isChecked()) {
        if (poolUrlEdit->text().isEmpty()) {
            QMessageBox::warning(this, tr("Mining"), tr("Please enter a pool URL."));
            return false;
        }
        if (poolWorkerEdit->text().isEmpty()) {
            QMessageBox::warning(this, tr("Mining"), tr("Please enter a worker name."));
            return false;
        }
    }
    return true;
}

void MiningPage::onMiningToggleClicked()
{
    if (isMining) {
        stopMining();
    } else {
        if (!validatePoolSettings()) return;

        if (miningAddressCombo->currentData().toString() == "new") {
            // Generate new address
            if (walletModel) {
                QMessageBox::information(this, tr("Mining"),
                    tr("Please generate a new receiving address first from the Receive tab."));
                return;
            }
        }

        startMining();
    }
}

void MiningPage::updateMiningButton(bool mining)
{
    if (mining) {
        miningToggleBtn->setText(tr("Stop Miner"));
        miningToggleBtn->setStyleSheet(
            "QPushButton { "
            "  background-color: #f44336; "
            "  color: white; "
            "  font-weight: bold; "
            "  font-size: 14px; "
            "  padding: 10px 20px; "
            "  border-radius: 5px; "
            "  border: none; "
            "} "
            "QPushButton:hover { background-color: #d32f2f; } "
            "QPushButton:pressed { background-color: #b71c1c; }"
        );
    } else {
        miningToggleBtn->setText(tr("Start Miner"));
        miningToggleBtn->setStyleSheet(
            "QPushButton { "
            "  background-color: #4CAF50; "
            "  color: white; "
            "  font-weight: bold; "
            "  font-size: 14px; "
            "  padding: 10px 20px; "
            "  border-radius: 5px; "
            "  border: none; "
            "} "
            "QPushButton:hover { background-color: #43a047; } "
            "QPushButton:pressed { background-color: #2e7d32; }"
        );
    }
}

void MiningPage::startMining()
{
    if (isMining) return;

    if (!clientModel || !walletModel) {
        statusLabel->setText(tr("Error: Wallet not ready"));
        statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
        return;
    }

    QString address = miningAddressCombo->currentData().toString();
    if (address.isEmpty() || address == "new") {
        QMessageBox::warning(this, tr("Mining"), tr("Please select a valid mining address."));
        return;
    }

    // Clear console and log start
    miningConsole->clear();
    logToConsole(tr("=== WATTx RandomX Mining Started ==="));
    logToConsole(tr("Mining Address: %1").arg(address));

    // Get mining mode and safe mode from UI
    bool fullMode = rxModeCombo && rxModeCombo->currentIndex() == 1;
    int numThreads = cpuThreadsSpinBox->value();
    bool safeMode = safeModeCheckbox && safeModeCheckbox->isChecked();

    logToConsole(tr("Mode: %1, Threads: %2, Safe Mode: %3")
        .arg(fullMode ? "Full (2GB)" : "Light (256MB)")
        .arg(numThreads)
        .arg(safeMode ? "ON" : "OFF"));
    logToConsole(tr(""));

    isMining = true;
    miningStartTime = QDateTime::currentSecsSinceEpoch();  // Track session start
    sessionBlocksFound = 0;
    updateMiningButton(true);  // Show red "Stop Miner" button
    statusLabel->setText(tr("Initializing RandomX..."));
    statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");

    // Start mining in background thread
    std::thread miningThread([this, address, fullMode, safeMode]() {
        int blocksFound = 0;

        // Initialize RandomX
        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("Initializing RandomX context..."));
        }, Qt::QueuedConnection);

        // Get genesis hash for RandomX initialization via RPC
        std::string rpcResult;
        std::string rpcCommand = "getblockhash 0";
        bool success = RPCConsole::RPCExecuteCommandLine(
            clientModel->node(), rpcResult, rpcCommand, nullptr, walletModel);

        if (!success || rpcResult.empty()) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Failed to get genesis hash"));
                statusLabel->setText(tr("Error: Failed to initialize"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }

        // Parse genesis hash (remove quotes if present)
        std::string genesisHashStr = rpcResult;
        if (genesisHashStr.front() == '"') genesisHashStr = genesisHashStr.substr(1);
        if (genesisHashStr.back() == '"') genesisHashStr.pop_back();

        auto genesisHashOpt = uint256::FromHex(genesisHashStr);
        if (!genesisHashOpt) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Invalid genesis hash format"));
                statusLabel->setText(tr("Error: Invalid genesis hash"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }
        uint256 genesisHash = *genesisHashOpt;

        // Initialize RandomX miner
        node::RandomXMiner& miner = node::GetRandomXMiner();
        auto mode = fullMode ? node::RandomXMiner::Mode::FULL : node::RandomXMiner::Mode::LIGHT;

        QMetaObject::invokeMethod(this, [this, fullMode, safeMode]() {
            logToConsole(tr("Loading RandomX %1 mode%2...")
                .arg(fullMode ? "Full (this may take a minute)" : "Light")
                .arg(safeMode ? " (Safe Mode - JIT disabled)" : ""));
        }, Qt::QueuedConnection);

        if (!miner.Initialize(genesisHash.data(), 32, mode, safeMode)) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Failed to initialize RandomX"));
                statusLabel->setText(tr("Error: RandomX init failed"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }

        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("RandomX initialized successfully!"));
            statusLabel->setText(tr("Mining..."));
            statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
        }, Qt::QueuedConnection);

        // Mining loop - get block template, mine, submit
        while (isMining) {
            try {
                // Get block template via direct RPC call (avoids command line parsing issues)
                UniValue templateRequest(UniValue::VOBJ);
                UniValue rulesArray(UniValue::VARR);
                rulesArray.push_back("segwit");
                templateRequest.pushKV("rules", rulesArray);

                UniValue params(UniValue::VARR);
                params.push_back(templateRequest);

                UniValue templateVal;
                try {
                    templateVal = clientModel->node().executeRpc("getblocktemplate", params, "/");
                } catch (const UniValue& rpcError) {
                    // RPC errors are thrown as UniValue objects (via JSONRPCError)
                    std::string errMsg = rpcError.exists("message") ? rpcError["message"].get_str() : rpcError.write();
                    QMetaObject::invokeMethod(this, [this, errMsg]() {
                        logToConsole(tr("getblocktemplate RPC error: %1").arg(QString::fromStdString(errMsg)));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                } catch (const std::exception& rpcError) {
                    std::string errMsg = rpcError.what();
                    QMetaObject::invokeMethod(this, [this, errMsg]() {
                        logToConsole(tr("getblocktemplate failed: %1").arg(QString::fromStdString(errMsg)));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                if (templateVal.isNull()) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Waiting for block template..."));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                // Extract template data with error checking
                if (templateVal["previousblockhash"].isNull() || templateVal["coinbasevalue"].isNull() ||
                    templateVal["target"].isNull() || templateVal["bits"].isNull() ||
                    templateVal["curtime"].isNull() || templateVal["version"].isNull() ||
                    templateVal["height"].isNull() ||
                    templateVal["hashStateRoot"].isNull() || templateVal["hashUTXORoot"].isNull()) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Block template missing required fields"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                std::string prevBlockHash = templateVal["previousblockhash"].get_str();
                int64_t coinbaseValue = templateVal["coinbasevalue"].getInt<int64_t>();
                std::string targetStr = templateVal["target"].get_str();
                std::string bitsStr = templateVal["bits"].get_str();
                int32_t curTime = templateVal["curtime"].getInt<int32_t>();
                int32_t version = templateVal["version"].getInt<int32_t>();
                int height = templateVal["height"].getInt<int>();
                std::string hashStateRootStr = templateVal["hashStateRoot"].get_str();
                std::string hashUTXORootStr = templateVal["hashUTXORoot"].get_str();

                QMetaObject::invokeMethod(this, [this, height]() {
                    logToConsole(tr("Got template for height %1").arg(height));
                }, Qt::QueuedConnection);

                // Create coinbase transaction paying to mining address
                CMutableTransaction coinbaseTx;
                coinbaseTx.vin.resize(1);
                coinbaseTx.vin[0].prevout.SetNull();
                coinbaseTx.vin[0].scriptSig = CScript() << height << OP_0;
                coinbaseTx.vout.resize(1);

                // Decode mining address to script
                CTxDestination dest = DecodeDestination(address.toStdString());
                if (!IsValidDestination(dest)) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Invalid mining address"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }
                coinbaseTx.vout[0].scriptPubKey = GetScriptForDestination(dest);
                coinbaseTx.vout[0].nValue = coinbaseValue;

                // Create block
                CBlock block;
                block.nVersion = version;
                auto prevHashOpt = uint256::FromHex(prevBlockHash);
                if (!prevHashOpt) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                block.hashPrevBlock = *prevHashOpt;
                block.nTime = curTime;
                block.nBits = strtoul(bitsStr.c_str(), nullptr, 16);
                block.nNonce = 0;

                // Set Qtum state roots (required for EVM/AAL validation)
                auto stateRootOpt = uint256::FromHex(hashStateRootStr);
                auto utxoRootOpt = uint256::FromHex(hashUTXORootStr);
                if (!stateRootOpt || !utxoRootOpt) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Invalid state root hashes in template"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                block.hashStateRoot = *stateRootOpt;
                block.hashUTXORoot = *utxoRootOpt;

                // Add coinbase as first transaction
                block.vtx.push_back(MakeTransactionRef(std::move(coinbaseTx)));

                // Add transactions from template (skip for now - just coinbase)
                // TODO: Parse and add transactions from template

                // Calculate merkle root
                block.hashMerkleRoot = BlockMerkleRoot(block);

                // Calculate target
                auto targetOpt = uint256::FromHex(targetStr);
                if (!targetOpt) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                uint256 target = *targetOpt;

                QMetaObject::invokeMethod(this, [this, height]() {
                    logToConsole(tr("Mining block at height %1...").arg(height));
                }, Qt::QueuedConnection);

                // Mine using RandomX - read current thread count (may have changed)
                int activeThreads = this->currentCpuThreads.load();
                std::atomic<bool> blockFound{false};
                CBlock foundBlock;
                miner.StartMining(block, target, activeThreads, [&](const CBlock& minedBlock) {
                    foundBlock = minedBlock;  // Copy block first
                    blockFound = true;        // Then signal (memory barrier)
                });

                // Wait for block or stop signal
                while (!blockFound && isMining && miner.IsMining()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                if (blockFound && isMining) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Block found! Submitting to network..."));
                    }, Qt::QueuedConnection);

                    // Serialize and submit block
                    DataStream ss{};
                    ss << TX_WITH_WITNESS(foundBlock);
                    std::string blockHex = HexStr(ss);

                    // Submit block via direct RPC call
                    UniValue submitParams(UniValue::VARR);
                    submitParams.push_back(blockHex);

                    try {
                        UniValue submitResult = clientModel->node().executeRpc("submitblock", submitParams, "/");
                        // submitblock returns null on success
                        if (submitResult.isNull()) {
                            blocksFound++;
                            QMetaObject::invokeMethod(this, [this, blocksFound, height]() {
                                sessionBlocksFound++;
                                blocksFoundLabel->setText(QString::number(blocksFound));
                                gapsCheckedLabel->setText(QString::number(sessionBlocksFound));
                                logToConsole(tr("*** BLOCK %1 MINED! ***").arg(height));
                            }, Qt::QueuedConnection);
                            // Wait for chain state to fully update after successful block submission
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                        } else {
                            std::string rejectReason = submitResult.isStr() ? submitResult.get_str() : submitResult.write();
                            QMetaObject::invokeMethod(this, [this, rejectReason]() {
                                logToConsole(tr("Block rejected: %1").arg(QString::fromStdString(rejectReason)));
                            }, Qt::QueuedConnection);
                        }
                    } catch (const UniValue& submitError) {
                        // RPC errors are thrown as UniValue objects (via JSONRPCError)
                        std::string errMsg = submitError.exists("message") ? submitError["message"].get_str() : submitError.write();
                        QMetaObject::invokeMethod(this, [this, errMsg]() {
                            logToConsole(tr("submitblock RPC error: %1").arg(QString::fromStdString(errMsg)));
                        }, Qt::QueuedConnection);
                    } catch (const std::exception& submitError) {
                        std::string errMsg = submitError.what();
                        QMetaObject::invokeMethod(this, [this, errMsg]() {
                            logToConsole(tr("submitblock failed: %1").arg(QString::fromStdString(errMsg)));
                        }, Qt::QueuedConnection);
                    }
                }

                // Small delay before next template
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            } catch (const UniValue& e) {
                // RPC errors are thrown as UniValue objects (via JSONRPCError)
                std::string errorMsg = e.exists("message") ? e["message"].get_str() : e.write();
                QMetaObject::invokeMethod(this, [this, errorMsg]() {
                    logToConsole(tr("Mining RPC error: %1").arg(QString::fromStdString(errorMsg)));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } catch (const std::exception& e) {
                std::string errorMsg = e.what();
                QMetaObject::invokeMethod(this, [this, errorMsg]() {
                    logToConsole(tr("Mining error: %1").arg(QString::fromStdString(errorMsg)));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } catch (...) {
                QMetaObject::invokeMethod(this, [this]() {
                    logToConsole(tr("Mining error: unknown exception"));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }

        miner.StopMining();

        QMetaObject::invokeMethod(this, [this, blocksFound]() {
            logToConsole(tr("Mining stopped. Total blocks: %1").arg(blocksFound));
        }, Qt::QueuedConnection);
    });
    miningThread.detach();

    // Start stats timer
    statsTimer->start(2000);
}

void MiningPage::startMiningActual()
{
    if (!isMining) return;

    statusLabel->setText(tr("Mining Active - RandomX"));
    statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    logToConsole(tr("Mining started! Looking for valid hashes..."));

    // Start stats timer
    statsTimer->start(1000);  // Update every 1 second
}

void MiningPage::stopMining()
{
    if (!isMining) return;

    logToConsole(tr(""));
    logToConsole(tr("=== Stopping Mining... ==="));

    // Disable button during stop
    miningToggleBtn->setEnabled(false);
    statusLabel->setText(tr("Stopping..."));
    statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");
    statsTimer->stop();

    // Stop mining in background thread
    std::thread stopThread([this]() {
        node::GetRandomXMiner().StopMining();

        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("=== Mining Stopped ==="));
            isMining = false;
            miningToggleBtn->setEnabled(true);
            updateMiningButton(false);  // Show green "Start Miner" button
            statusLabel->setText(tr("Idle"));
            statusLabel->setStyleSheet("font-weight: bold;");
            miningProgressBar->setValue(0);
        }, Qt::QueuedConnection);
    });
    stopThread.detach();
}

void MiningPage::logToConsole(const QString& message)
{
    if (!miningConsole) return;

    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    miningConsole->append(QString("[%1] %2").arg(timestamp).arg(message));

    // Auto-scroll to bottom
    QTextCursor cursor = miningConsole->textCursor();
    cursor.movePosition(QTextCursor::End);
    miningConsole->setTextCursor(cursor);
}

void MiningPage::onMiningHashrate(double hashrate, uint64_t totalHashes)
{
    if (!isMining) return;

    // Format hashrate
    QString hrText;
    if (hashrate >= 1000000) {
        hrText = QString("%1 MH/s").arg(hashrate / 1000000.0, 0, 'f', 2);
    } else if (hashrate >= 1000) {
        hrText = QString("%1 KH/s").arg(hashrate / 1000.0, 0, 'f', 2);
    } else {
        hrText = QString("%1 H/s").arg(hashrate, 0, 'f', 1);
    }

    hashRateLabel->setText(hrText);
    primesFoundLabel->setText(QString::number(totalHashes));

    // Update progress bar with animation
    int progress = (totalHashes / 1000) % 100;
    miningProgressBar->setValue(progress);
}

void MiningPage::onBlockFound(const CBlock& block)
{
    logToConsole(tr(""));
    logToConsole(tr("*** VALID BLOCK FOUND! ***"));
    logToConsole(QString("Nonce: %1").arg(block.nNonce));
    logToConsole(QString("Time: %1").arg(block.nTime));
}

void MiningPage::updateMiningStats()
{
    if (!isMining) return;

    // Update hashrate and stats from miner
    node::RandomXMiner& miner = node::GetRandomXMiner();
    double hashrate = miner.GetHashrate();
    uint64_t totalHashes = miner.GetTotalHashes();

    onMiningHashrate(hashrate, totalHashes);

    // Update uptime display
    if (miningStartTime > 0) {
        int64_t uptime = QDateTime::currentSecsSinceEpoch() - miningStartTime;
        int hours = uptime / 3600;
        int minutes = (uptime % 3600) / 60;
        int seconds = uptime % 60;
        bestMeritLabel->setText(QString("%1:%2:%3")
            .arg(hours, 2, 10, QChar('0'))
            .arg(minutes, 2, 10, QChar('0'))
            .arg(seconds, 2, 10, QChar('0')));
    }

    // Update accepted (blocks found this session)
    gapsCheckedLabel->setText(QString::number(sessionBlocksFound));

    // Log periodic updates
    static uint64_t lastLoggedHashes = 0;
    if (totalHashes - lastLoggedHashes >= 10000) {
        QString hrText;
        if (hashrate >= 1000) {
            hrText = QString("%1 KH/s").arg(hashrate / 1000.0, 0, 'f', 2);
        } else {
            hrText = QString("%1 H/s").arg(hashrate, 0, 'f', 1);
        }
        logToConsole(QString("Hashrate: %1 | Total: %2 hashes").arg(hrText).arg(totalHashes));
        lastLoggedHashes = totalHashes;
    }
}

