#include <qt/stakepage.h>
#include <qt/forms/ui_stakepage.h>

#include <qt/bitcoinunits.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>
#include <interfaces/wallet.h>
#include <interfaces/node.h>
#include <qt/transactiondescdialog.h>
#include <qt/styleSheet.h>
#include <qt/transactionview.h>
#include <qt/hardwaresigntx.h>
#include <consensus/amount.h>

#include <node/miner.h>

#include <QSortFilterProxyModel>
#include <QTimer>

Q_DECLARE_METATYPE(interfaces::WalletBalances)

StakePage::StakePage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StakePage),
    clientModel(nullptr),
    walletModel(nullptr),
    platformStyle(_platformStyle),
    transactionView(0),
    m_subsidy(0),
    m_networkWeight(0),
    m_expectedAnnualROI(0)
{
    ui->setupUi(this);
    ui->checkStake->setEnabled(node::CanStake());
    transactionView = new TransactionView(platformStyle, this, true);
    ui->frameStakeRecords->layout()->addWidget(transactionView);
}

StakePage::~StakePage()
{
    delete ui;
}

void StakePage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &StakePage::numBlocksChanged);
        int height = _clientModel->node().getNumBlocks();
        ui->labelHeight->setText(QString::number(height));
        m_subsidy = _clientModel->node().getBlockSubsidy(height);
        m_networkWeight = _clientModel->node().getNetworkStakeWeight();
        m_expectedAnnualROI = _clientModel->node().getEstimatedAnnualROI();
        updateNetworkWeight();
        updateAnnualROI();
    }
}

void StakePage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        transactionView->setModel(model);
        transactionView->chooseType(6);  // Index 6 = Staked transactions
        if(model->wallet().privateKeysDisabled()) {
            ui->checkStake->setEnabled(node::ENABLE_HARDWARE_STAKE);
        }
        if(ui->checkStake->isEnabled()) {
            ui->checkStake->setChecked(model->wallet().getEnabledStaking());
        }

        // Keep up to date with wallet
        interfaces::Wallet& wallet = model->wallet();
        interfaces::WalletBalances balances = wallet.getBalances();
        setBalance(balances);
        connect(model, &WalletModel::balanceChanged, this, &StakePage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &StakePage::updateDisplayUnit);
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void StakePage::setBalance(const interfaces::WalletBalances& balances)
{
    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    m_balances = balances;
    CAmount balance = balances.balance;
    CAmount stake = balances.stake;
    if(walletModel->wallet().privateKeysDisabled())
    {
        balance += balances.watch_only_balance;
        stake += balances.watch_only_stake;
    }
    // "Staking assets" must be what can ACTUALLY stake, not the whole spendable
    // balance.
    //
    // Coins only become eligible after stakematurity confirmations (500), so a
    // wallet whose coins are all younger has a spendable balance but zero
    // staking weight. Showing the raw balance told users they had assets
    // staking while the staking indicator was correctly dark and no stake was
    // possible -- the page and the indicator disagreed, and the page was wrong.
    //
    // tryGetStakeWeight() is the amount the staking code itself considers
    // eligible, so it cannot drift from reality the way a balance figure does.
    uint64_t nWeight = 0;
    const bool haveWeight = walletModel->wallet().tryGetStakeWeight(nWeight);
    const CAmount eligible = haveWeight ? static_cast<CAmount>(nWeight) : 0;

    ui->labelAssets->setText(BitcoinUnits::formatWithUnit(unit, eligible, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    ui->labelStake->setText(BitcoinUnits::formatWithUnit(unit, stake, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    // Say plainly why nothing is staking yet, rather than leaving the user to
    // infer it from a zero next to a spendable balance.
    if (eligible < balance) {
        const CAmount waiting = balance - eligible;
        ui->labelAssets->setToolTip(
            tr("%1 is not yet old enough to stake. Coins become eligible once "
               "they reach the stake maturity shown by getstakinginfo.")
                .arg(BitcoinUnits::formatWithUnit(unit, waiting, false,
                                                  BitcoinUnits::SeparatorStyle::ALWAYS)));
    } else {
        ui->labelAssets->setToolTip(tr("Coins eligible to stake."));
    }
}

void StakePage::on_checkStake_clicked(bool checked)
{
    if(!walletModel)
        return;

    bool privateKeysDisabled = walletModel->wallet().privateKeysDisabled();
    if(!privateKeysDisabled)
        walletModel->wallet().setEnabledStaking(checked);

    if(checked && WalletModel::Locked == walletModel->getEncryptionStatus())
        Q_EMIT requireUnlock(true);

    if(privateKeysDisabled)
    {
        if(checked)
        {
            QTimer::singleShot(500, this, &StakePage::askDeviceForStake);
        }
        else
        {
            walletModel->wallet().setEnabledStaking(false);
        }
    }
}

void StakePage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if (m_balances.balance != -1) {
            setBalance(m_balances);
        }
        updateSubsidy();
    }
}

void StakePage::numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state)
{
    if(header==SyncType::BLOCK_SYNC && clientModel && walletModel)
    {
        ui->labelHeight->setText(BitcoinUnits::formatInt(count));
        m_subsidy = clientModel->node().getBlockSubsidy(count);
        m_networkWeight = clientModel->node().getNetworkStakeWeight();
        m_expectedAnnualROI = clientModel->node().getEstimatedAnnualROI();
        updateSubsidy();
        updateNetworkWeight();
        updateAnnualROI();
    }
}

void StakePage::updateSubsidy()
{
    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    QString strSubsidy = BitcoinUnits::formatWithUnit(unit, m_subsidy, false, BitcoinUnits::SeparatorStyle::ALWAYS) + "/Block";
    ui->labelReward->setText(strSubsidy);
}

void StakePage::updateNetworkWeight()
{
    ui->labelWeight->setText(BitcoinUnits::formatInt(m_networkWeight / COIN));
}

void StakePage::updateAnnualROI()
{
    ui->labelROI->setText(QString::number(m_expectedAnnualROI, 'f', 2) + "%");
}

void StakePage::updateEncryptionStatus()
{
    if(!walletModel)
        return;

    int status = walletModel->getEncryptionStatus();
    switch(status)
    {
    case WalletModel::Unlocked:
        if(walletModel->wallet().getEnabledStaking())
        {
            bool checked = ui->checkStake->isChecked();
            if(!checked) ui->checkStake->onStatusChanged();
        }
        break;
    case WalletModel::Locked:
        if(!walletModel->getWalletUnlockStakingOnly())
        {
            bool checked = ui->checkStake->isChecked();
            if(checked) ui->checkStake->onStatusChanged();
        }
        break;
    }
}

void StakePage::askDeviceForStake()
{
    // Get staking device
    HardwareSignTx hardware(this);
    hardware.setModel(walletModel);
    bool staking = hardware.askDevice(true);
    walletModel->wallet().setEnabledStaking(staking);

    // Update stake button
    bool checked = ui->checkStake->isChecked();
    if(checked != staking) ui->checkStake->onStatusChanged();
}
