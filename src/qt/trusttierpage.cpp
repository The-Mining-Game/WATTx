// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/trusttierpage.h>
#include <qt/forms/ui_trusttierpage.h>

#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>
#include <qt/guiutil.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <trust/heartbeat_net.h>
#include <chainparams.h>
#include <key_io.h>

#include <QTreeWidgetItem>

TrustTierPage::TrustTierPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TrustTierPage),
    clientModel(nullptr),
    walletModel(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Set up tier requirements tree columns
    ui->tierRequirementsTree->setColumnWidth(0, 120);
    ui->tierRequirementsTree->setColumnWidth(1, 150);
    ui->tierRequirementsTree->setColumnWidth(2, 150);

    // Populate tier requirements (static data from consensus params)
    auto addTierReq = [&](const QString& name, const QString& uptime, const QString& multiplier, const QString& color) {
        QTreeWidgetItem* item = new QTreeWidgetItem(ui->tierRequirementsTree);
        item->setText(0, name);
        item->setText(1, uptime);
        item->setText(2, multiplier);
        item->setForeground(0, QColor(color));
    };
    addTierReq("Bronze", "95.0%+", "1.0x", "#CD7F32");
    addTierReq("Silver", "97.0%+", "1.25x", "#C0C0C0");
    addTierReq("Gold", "99.0%+", "1.5x", "#FFD700");
    addTierReq("Platinum", "99.9%+", "2.0x", "#E5E4E2");

    // Set up network stats tree columns
    ui->networkStatsTree->setColumnWidth(0, 120);
    ui->networkStatsTree->setColumnWidth(1, 120);
    ui->networkStatsTree->setColumnWidth(2, 200);
}

TrustTierPage::~TrustTierPage()
{
    delete ui;
}

void TrustTierPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel()) {
        // Initial update
        updateTrustInfo();
        updateNetworkStats();
    }
}

void TrustTierPage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged,
                this, &TrustTierPage::numBlocksChanged);
    }
}

void TrustTierPage::numBlocksChanged(int count, const QDateTime& blockDate,
                                       double nVerificationProgress,
                                       SyncType header,
                                       SynchronizationState sync_state)
{
    if (header == SyncType::BLOCK_SYNC) {
        updateTrustInfo();
        updateNetworkStats();
    }
}

void TrustTierPage::updateTrustInfo()
{
    if (!walletModel) return;

    const auto& params = Params().GetConsensus();

    // Check if trust tier system is active
    if (!trust::g_heartbeat_manager) {
        ui->labelTierValue->setText(tr("SYSTEM INACTIVE"));
        ui->labelTierValue->setStyleSheet("color: gray;");
        return;
    }

    trust::TrustScoreManager* trustMgr = trust::g_heartbeat_manager->GetTrustManager();
    if (!trustMgr) return;

    // Try to find our validator info using the wallet's staking address
    // Get the staker address from the wallet
    const trust::ValidatorInfo* myValidator = nullptr;

    auto activeValidators = trustMgr->GetActiveValidators();
    // Look for a validator that matches one of our wallet's addresses
    for (const auto& v : activeValidators) {
        CTxDestination dest = PKHash(v.validatorId);
        std::string addr = EncodeDestination(dest);
        if (walletModel->wallet().isMineAddress(addr)) {
            myValidator = trustMgr->GetValidator(v.validatorId);
            break;
        }
    }

    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();

    if (myValidator) {
        // Display tier
        trust::TrustTier tier = myValidator->GetTrustTier(params);
        QString tierName;
        QString tierColor;
        switch (tier) {
            case trust::TrustTier::BRONZE:
                tierName = "BRONZE"; tierColor = "#CD7F32"; break;
            case trust::TrustTier::SILVER:
                tierName = "SILVER"; tierColor = "#C0C0C0"; break;
            case trust::TrustTier::GOLD:
                tierName = "GOLD"; tierColor = "#FFD700"; break;
            case trust::TrustTier::PLATINUM:
                tierName = "PLATINUM"; tierColor = "#E5E4E2"; break;
            default:
                tierName = "NONE"; tierColor = "gray"; break;
        }
        ui->labelTierValue->setText(tierName);
        ui->labelTierValue->setStyleSheet(QString("color: %1;").arg(tierColor));

        // Uptime
        int uptimePct = myValidator->GetUptimePercentage();
        ui->uptimeProgressBar->setValue(uptimePct);
        ui->labelUptimeValue->setText(QString("%1%").arg(uptimePct / 10.0, 0, 'f', 1));

        // Heartbeat info
        ui->labelHeartbeatValue->setText(
            myValidator->lastHeartbeatHeight > 0 ?
            tr("Block %1").arg(myValidator->lastHeartbeatHeight) : tr("Never"));

        int nextHeartbeat = myValidator->lastHeartbeatHeight + params.nHeartbeatInterval;
        ui->labelNextHeartbeatValue->setText(tr("Block %1").arg(nextHeartbeat));

        // Heartbeats received/expected
        ui->labelHeartbeatsValue->setText(
            QString("%1 / %2").arg(myValidator->heartbeatsReceived)
                              .arg(myValidator->heartbeatsExpected));

        // Stake amount
        ui->labelStakeAmountValue->setText(
            BitcoinUnits::formatWithUnit(unit, myValidator->stakeAmount));

        // Estimated reward per block (fixed 5 WATTx base reward)
        CAmount baseReward = 5 * COIN;
        ui->labelRewardEstValue->setText(
            BitcoinUnits::formatWithUnit(unit, baseReward));
    } else {
        ui->labelTierValue->setText(tr("NOT STAKING"));
        ui->labelTierValue->setStyleSheet("color: gray;");
        ui->uptimeProgressBar->setValue(0);
        ui->labelUptimeValue->setText("0.0%");
        ui->labelHeartbeatValue->setText(tr("N/A"));
        ui->labelNextHeartbeatValue->setText(tr("N/A"));
        ui->labelHeartbeatsValue->setText("0 / 0");
        ui->labelStakeAmountValue->setText(BitcoinUnits::formatWithUnit(unit, 0));
        ui->labelRewardEstValue->setText(BitcoinUnits::formatWithUnit(unit, 0));
    }
}

void TrustTierPage::updateNetworkStats()
{
    if (!trust::g_heartbeat_manager) return;

    trust::TrustScoreManager* trustMgr = trust::g_heartbeat_manager->GetTrustManager();
    if (!trustMgr) return;

    ui->networkStatsTree->clear();

    struct TierStat {
        QString name;
        QString color;
        trust::TrustTier tier;
    };

    std::vector<TierStat> tiers = {
        {"Bronze", "#CD7F32", trust::TrustTier::BRONZE},
        {"Silver", "#C0C0C0", trust::TrustTier::SILVER},
        {"Gold", "#FFD700", trust::TrustTier::GOLD},
        {"Platinum", "#E5E4E2", trust::TrustTier::PLATINUM}
    };

    BitcoinUnit unit = walletModel ? walletModel->getOptionsModel()->getDisplayUnit() : BitcoinUnit::BTC;

    for (const auto& ts : tiers) {
        auto validators = trustMgr->GetValidatorsByTier(ts.tier);
        CAmount totalStaked = 0;
        for (const auto& v : validators) {
            totalStaked += v.stakeAmount;
        }

        QTreeWidgetItem* item = new QTreeWidgetItem(ui->networkStatsTree);
        item->setText(0, ts.name);
        item->setForeground(0, QColor(ts.color));
        item->setText(1, QString::number(validators.size()));
        item->setText(2, BitcoinUnits::formatWithUnit(unit, totalStaked));
    }
}
