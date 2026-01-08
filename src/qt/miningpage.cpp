// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/miningpage.h>
#include <qt/clientmodel.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/guiutil.h>
#include <qt/addresstablemodel.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>

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

MiningPage::MiningPage(const PlatformStyle *_platformStyle, QWidget *parent)
    : QWidget(parent)
    , clientModel(nullptr)
    , walletModel(nullptr)
    , platformStyle(_platformStyle)
    , isMining(false)
    , currentCpuThreads(1)
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
}

void MiningPage::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);

    // Title
    QLabel *titleLabel = new QLabel(tr("WATTx Mining (Gapcoin Prime Gap Algorithm)"), this);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

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

    // Horizontal layout for CPU and GPU controls
    QHBoxLayout *hardwareLayout = new QHBoxLayout();

    // CPU Mining Controls
    QGroupBox *cpuGroup = new QGroupBox(tr("CPU Mining"), this);
    createCpuControls(cpuGroup);
    hardwareLayout->addWidget(cpuGroup);

    // GPU Mining Controls
    QGroupBox *gpuGroup = new QGroupBox(tr("GPU Mining"), this);
    createGpuControls(gpuGroup);
    hardwareLayout->addWidget(gpuGroup);

    mainLayout->addLayout(hardwareLayout);

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

    // Mining difficulty/shift setting
    QGroupBox *diffGroup = new QGroupBox(tr("Mining Parameters"), this);
    QHBoxLayout *diffLayout = new QHBoxLayout(diffGroup);

    shiftLabel = new QLabel(tr("Shift Value (Prime Size):"), this);
    shiftSpinBox = new QSpinBox(this);
    shiftSpinBox->setRange(14, 512);
    shiftSpinBox->setValue(20);
    shiftSpinBox->setToolTip(tr("Higher shift = larger primes = harder to find but more merit"));

    diffLayout->addWidget(shiftLabel);
    diffLayout->addWidget(shiftSpinBox);
    diffLayout->addStretch();
    mainLayout->addWidget(diffGroup);

    // Control Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    startMiningBtn = new QPushButton(tr("Start Mining"), this);
    startMiningBtn->setMinimumWidth(150);
    startMiningBtn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; }");

    stopMiningBtn = new QPushButton(tr("Stop Mining"), this);
    stopMiningBtn->setMinimumWidth(150);
    stopMiningBtn->setEnabled(false);
    stopMiningBtn->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 10px; }");

    buttonLayout->addWidget(startMiningBtn);
    buttonLayout->addWidget(stopMiningBtn);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    connect(startMiningBtn, &QPushButton::clicked, this, &MiningPage::onStartMiningClicked);
    connect(stopMiningBtn, &QPushButton::clicked, this, &MiningPage::onStopMiningClicked);

    // Statistics Display
    QGroupBox *statsGroup = new QGroupBox(tr("Mining Statistics"), this);
    createStatsDisplay(statsGroup);
    mainLayout->addWidget(statsGroup);

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
    cpuThreadsSpinBox->setValue(qMax(1, maxThreads - 1));  // Leave one core free by default
    cpuThreadsSpinBox->setToolTip(tr("Number of CPU threads to use for mining"));

    threadsLayout->addWidget(cpuThreadsLabel);
    threadsLayout->addWidget(cpuThreadsSpinBox);
    threadsLayout->addStretch();
    layout->addLayout(threadsLayout);

    connect(cpuThreadsSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &MiningPage::onCpuThreadsChanged);
    connect(enableCpuMining, &QCheckBox::toggled, [this](bool checked) {
        cpuThreadsSpinBox->setEnabled(checked);
    });
}

void MiningPage::createGpuControls(QGroupBox *group)
{
    QVBoxLayout *layout = new QVBoxLayout(group);

    enableGpuMining = new QCheckBox(tr("Enable GPU Mining"), this);
    enableGpuMining->setChecked(false);
    enableGpuMining->setToolTip(tr("GPU mining requires OpenCL support"));
    layout->addWidget(enableGpuMining);

    QHBoxLayout *deviceLayout = new QHBoxLayout();
    QLabel *deviceLabel = new QLabel(tr("GPU Device:"), this);
    gpuDeviceCombo = new QComboBox(this);
    gpuDeviceCombo->addItem(tr("Auto-detect"), 0);
    gpuDeviceCombo->addItem(tr("GPU 0 (Primary)"), 0);
    gpuDeviceCombo->setEnabled(false);

    deviceLayout->addWidget(deviceLabel);
    deviceLayout->addWidget(gpuDeviceCombo);
    layout->addLayout(deviceLayout);

    QHBoxLayout *bandwidthLayout = new QHBoxLayout();
    gpuBandwidthLabel = new QLabel(tr("GPU Bandwidth:"), this);
    gpuBandwidthSlider = new QSlider(Qt::Horizontal, this);
    gpuBandwidthSlider->setRange(10, 100);
    gpuBandwidthSlider->setValue(50);
    gpuBandwidthSlider->setEnabled(false);
    gpuBandwidthSlider->setToolTip(tr("Percentage of GPU resources to use for mining"));

    gpuBandwidthValueLabel = new QLabel("50%", this);
    gpuBandwidthValueLabel->setMinimumWidth(40);

    bandwidthLayout->addWidget(gpuBandwidthLabel);
    bandwidthLayout->addWidget(gpuBandwidthSlider, 1);
    bandwidthLayout->addWidget(gpuBandwidthValueLabel);
    layout->addLayout(bandwidthLayout);

    connect(enableGpuMining, &QCheckBox::toggled, [this](bool checked) {
        gpuDeviceCombo->setEnabled(checked);
        gpuBandwidthSlider->setEnabled(checked);
    });

    connect(gpuBandwidthSlider, &QSlider::valueChanged, this, &MiningPage::onGpuBandwidthChanged);
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

    // Hash Rate / Gaps/sec
    layout->addWidget(new QLabel(tr("Search Rate:"), this), 0, 2);
    hashRateLabel = new QLabel(tr("0 gaps/s"), this);
    layout->addWidget(hashRateLabel, 0, 3);

    // Primes Found
    layout->addWidget(new QLabel(tr("Primes Found:"), this), 1, 0);
    primesFoundLabel = new QLabel("0", this);
    layout->addWidget(primesFoundLabel, 1, 1);

    // Gaps Checked
    layout->addWidget(new QLabel(tr("Gaps Checked:"), this), 1, 2);
    gapsCheckedLabel = new QLabel("0", this);
    layout->addWidget(gapsCheckedLabel, 1, 3);

    // Blocks Found
    layout->addWidget(new QLabel(tr("Blocks Found:"), this), 2, 0);
    blocksFoundLabel = new QLabel("0", this);
    blocksFoundLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    layout->addWidget(blocksFoundLabel, 2, 1);

    // Best Merit
    layout->addWidget(new QLabel(tr("Best Merit:"), this), 2, 2);
    bestMeritLabel = new QLabel("0.00", this);
    layout->addWidget(bestMeritLabel, 2, 3);

    // Current Difficulty
    layout->addWidget(new QLabel(tr("Network Difficulty:"), this), 3, 0);
    currentDifficultyLabel = new QLabel("20.00", this);
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
}

void MiningPage::onGpuBandwidthChanged(int value)
{
    currentGpuBandwidth = value;
    gpuBandwidthValueLabel->setText(QString("%1%").arg(value));
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

void MiningPage::onStartMiningClicked()
{
    if (!validatePoolSettings()) return;

    if (miningAddressCombo->currentData().toString() == "new") {
        // Generate new address
        if (walletModel) {
            // Request new address generation
            QMessageBox::information(this, tr("Mining"),
                tr("Please generate a new receiving address first from the Receive tab."));
            return;
        }
    }

    startMining();
}

void MiningPage::onStopMiningClicked()
{
    stopMining();
}

void MiningPage::startMining()
{
    if (isMining) return;

    isMining = true;
    startMiningBtn->setEnabled(false);
    stopMiningBtn->setEnabled(true);
    statusLabel->setText(tr("Mining..."));
    statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");

    // Start the RPC mining command
    if (clientModel && clientModel->node().baseInitialize()) {
        QString address = miningAddressCombo->currentData().toString();
        int threads = enableCpuMining->isChecked() ? cpuThreadsSpinBox->value() : 0;
        int shift = shiftSpinBox->value();

        // Call the RPC command
        try {
            // Using the gapcoin mining RPC we created earlier
            // This would be: startgapcoinmining <threads> <shift>
            QString cmd = QString("startgapcoinmining %1 %2").arg(threads).arg(shift);
            // Execute via RPC interface
            // clientModel->node().executeRpc("startgapcoinmining", ...);
        } catch (...) {
            // Handle error
        }
    }

    // Start stats timer
    statsTimer->start(2000);  // Update every 2 seconds
}

void MiningPage::stopMining()
{
    if (!isMining) return;

    isMining = false;
    startMiningBtn->setEnabled(true);
    stopMiningBtn->setEnabled(false);
    statusLabel->setText(tr("Stopped"));
    statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");

    // Stop the mining
    if (clientModel) {
        try {
            // Call stopgapcoinmining RPC
        } catch (...) {
            // Handle error
        }
    }

    statsTimer->stop();
    miningProgressBar->setValue(0);
}

void MiningPage::updateMiningStats()
{
    if (!isMining || !clientModel) return;

    // Update mining statistics from RPC
    // This would call getgapcoinmininginfo

    // Simulate progress for now
    static int progress = 0;
    progress = (progress + 5) % 100;
    miningProgressBar->setValue(progress);

    // TODO: Fetch real stats from miner
    // UniValue stats = clientModel->node().executeRpc("getgapcoinmininginfo", {});
    // hashRateLabel->setText(QString("%1 gaps/s").arg(stats["gaps_per_second"].get_real()));
    // primesFoundLabel->setText(QString::number(stats["primes_found"].get_int64()));
    // etc.
}
