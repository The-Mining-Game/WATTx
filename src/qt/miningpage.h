// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_QT_MININGPAGE_H
#define WATTX_QT_MININGPAGE_H

#include <interfaces/wallet.h>
#include <QWidget>
#include <QTimer>
#include <memory>

class ClientModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QSlider;
class QGroupBox;
class QRadioButton;
class QCheckBox;
class QProgressBar;
QT_END_NAMESPACE

/**
 * Mining page widget with CPU/GPU mining controls,
 * pool configuration, and mining statistics.
 */
class MiningPage : public QWidget
{
    Q_OBJECT

public:
    explicit MiningPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~MiningPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    void updateMiningStats();

private Q_SLOTS:
    void onStartMiningClicked();
    void onStopMiningClicked();
    void onMiningModeChanged();
    void onCpuThreadsChanged(int value);
    void onGpuBandwidthChanged(int value);
    void onRefreshAddresses();
    void onPoolUrlChanged();

private:
    void setupUi();
    void createCpuControls(QGroupBox *group);
    void createGpuControls(QGroupBox *group);
    void createPoolControls(QGroupBox *group);
    void createStatsDisplay(QGroupBox *group);
    void updateAddressCombo();
    void startMining();
    void stopMining();
    bool validatePoolSettings();

    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    // Mining mode
    QRadioButton *soloMiningRadio;
    QRadioButton *poolMiningRadio;

    // CPU controls
    QCheckBox *enableCpuMining;
    QSpinBox *cpuThreadsSpinBox;
    QLabel *cpuThreadsLabel;
    QLabel *cpuCoresAvailableLabel;

    // GPU controls
    QCheckBox *enableGpuMining;
    QComboBox *gpuDeviceCombo;
    QSlider *gpuBandwidthSlider;
    QLabel *gpuBandwidthLabel;
    QLabel *gpuBandwidthValueLabel;

    // Mining address
    QComboBox *miningAddressCombo;
    QPushButton *refreshAddressesBtn;

    // Pool settings
    QGroupBox *poolSettingsGroup;
    QLineEdit *poolUrlEdit;
    QLineEdit *poolWorkerEdit;
    QLineEdit *poolPasswordEdit;

    // Mining difficulty/shift
    QSpinBox *shiftSpinBox;
    QLabel *shiftLabel;

    // Control buttons
    QPushButton *startMiningBtn;
    QPushButton *stopMiningBtn;

    // Statistics display
    QLabel *statusLabel;
    QLabel *hashRateLabel;
    QLabel *primesFoundLabel;
    QLabel *gapsCheckedLabel;
    QLabel *blocksFoundLabel;
    QLabel *bestMeritLabel;
    QLabel *currentDifficultyLabel;
    QProgressBar *miningProgressBar;

    // Timer for stats updates
    QTimer *statsTimer;

    // Mining state
    bool isMining;
    int currentCpuThreads;
    int currentGpuBandwidth;
};

#endif // WATTX_QT_MININGPAGE_H
