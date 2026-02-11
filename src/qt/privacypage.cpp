// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/privacypage.h>
#include <qt/forms/ui_privacypage.h>

#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>
#include <qt/guiutil.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>

#include <interfaces/wallet.h>
#include <interfaces/node.h>

#include <QApplication>
#include <QClipboard>
#include <QTreeWidgetItem>
#include <QMessageBox>

PrivacyPage::PrivacyPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PrivacyPage),
    clientModel(nullptr),
    walletModel(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Set up outputs tree columns
    ui->outputsTree->setColumnWidth(0, 80);   // Type
    ui->outputsTree->setColumnWidth(1, 150);  // Amount
    ui->outputsTree->setColumnWidth(2, 120);  // Confirmations
    ui->outputsTree->setColumnWidth(3, 100);  // Status

    // Set up stealth address tree columns
    ui->stealthAddressTree->setColumnWidth(0, 120);  // Label
    ui->stealthAddressTree->setColumnWidth(1, 400);  // Address
    ui->stealthAddressTree->setColumnWidth(2, 150);  // Created
}

PrivacyPage::~PrivacyPage()
{
    delete ui;
}

void PrivacyPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel()) {
        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged,
                this, &PrivacyPage::updateDisplayUnit);

        connect(model, &WalletModel::balanceChanged,
                this, [this](const interfaces::WalletBalances&) { updatePrivacyBalance(); });

        // Initial update
        updatePrivacyBalance();
        refreshStealthAddresses();
    }
}

void PrivacyPage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged,
                this, &PrivacyPage::numBlocksChanged);
    }
}

void PrivacyPage::numBlocksChanged(int count, const QDateTime& blockDate,
                                     double nVerificationProgress,
                                     SyncType header,
                                     SynchronizationState sync_state)
{
    if (header == SyncType::BLOCK_SYNC && walletModel) {
        updatePrivacyBalance();
    }
}

void PrivacyPage::updatePrivacyBalance()
{
    if (!walletModel) return;

    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();

    // Get transparent balance
    interfaces::WalletBalances balances = walletModel->getCachedBalance();
    ui->labelTransparentBalance->setText(BitcoinUnits::formatWithUnit(unit, balances.balance));

    // Get privacy balances via wallet interface
    CAmount privacyBalance = walletModel->wallet().getPrivacyBalance();
    CAmount fcmpBalance = walletModel->wallet().getFcmpBalance();

    ui->labelPrivateBalance->setText(BitcoinUnits::formatWithUnit(unit, privacyBalance));
    ui->labelFcmpBalance->setText(BitcoinUnits::formatWithUnit(unit, fcmpBalance));

    // Update outputs tree
    ui->outputsTree->clear();

    // List Ring-CT outputs
    auto privacyOutputs = walletModel->wallet().getPrivacyOutputs();
    for (const auto& output : privacyOutputs) {
        QTreeWidgetItem* item = new QTreeWidgetItem(ui->outputsTree);
        item->setText(0, "Ring-CT");
        item->setText(1, BitcoinUnits::formatWithUnit(unit, output.amount));
        item->setText(2, QString::number(output.confirmations));
        item->setText(3, output.spendable ? tr("Spendable") : tr("Maturing"));
    }

    // List FCMP outputs
    auto fcmpOutputs = walletModel->wallet().getFcmpOutputs();
    for (const auto& output : fcmpOutputs) {
        QTreeWidgetItem* item = new QTreeWidgetItem(ui->outputsTree);
        item->setText(0, "FCMP");
        item->setText(1, BitcoinUnits::formatWithUnit(unit, output.amount));
        item->setText(2, QString::number(output.confirmations));
        item->setText(3, output.spendable ? tr("Spendable") : tr("Maturing"));
    }
}

void PrivacyPage::on_shieldButton_clicked()
{
    if (!walletModel) return;

    bool ok;
    double dAmount = ui->shieldAmountEdit->text().toDouble(&ok);
    if (!ok || dAmount <= 0) {
        Q_EMIT message(tr("Shield Error"), tr("Please enter a valid amount."), 0x00040000);
        return;
    }

    CAmount nAmount = dAmount * COIN;
    // Index 0 = FCMP (default), Index 1 = Ring-CT
    bool useFcmp = ui->shieldTypeCombo->currentIndex() == 0;

    // Request wallet unlock if needed
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        return;
    }

    std::string error;
    bool success = walletModel->wallet().shieldFunds(nAmount, useFcmp, error);

    if (success) {
        Q_EMIT message(tr("Shield Success"),
                       tr("Successfully shielded %1 to %2.")
                           .arg(BitcoinUnits::formatWithUnit(
                               walletModel->getOptionsModel()->getDisplayUnit(), nAmount))
                           .arg(useFcmp ? "FCMP" : "Ring-CT"),
                       0x00000040);
        ui->shieldAmountEdit->clear();
        updatePrivacyBalance();
    } else {
        Q_EMIT message(tr("Shield Error"),
                       tr("Failed to shield funds: %1").arg(QString::fromStdString(error)),
                       0x00040000);
    }
}

void PrivacyPage::on_generateStealthButton_clicked()
{
    if (!walletModel) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    QString label = ui->stealthLabelEdit->text().trimmed();
    std::string address;
    std::string error;

    bool success = walletModel->wallet().generateStealthAddress(
        label.toStdString(), address, error);

    if (success) {
        Q_EMIT message(tr("Stealth Address"),
                       tr("New stealth address generated:\n%1").arg(QString::fromStdString(address)),
                       0x00000040);
        ui->stealthLabelEdit->clear();
        refreshStealthAddresses();
    } else {
        Q_EMIT message(tr("Error"),
                       tr("Failed to generate stealth address: %1").arg(QString::fromStdString(error)),
                       0x00040000);
    }
}

void PrivacyPage::on_copyAddressButton_clicked()
{
    QTreeWidgetItem* current = ui->stealthAddressTree->currentItem();
    if (current) {
        QApplication::clipboard()->setText(current->text(1));
        Q_EMIT message(tr("Copy"), tr("Stealth address copied to clipboard."), 0x00000040);
    }
}

void PrivacyPage::refreshStealthAddresses()
{
    if (!walletModel) return;

    ui->stealthAddressTree->clear();

    auto addresses = walletModel->wallet().getStealthAddresses();
    for (const auto& addr : addresses) {
        QTreeWidgetItem* item = new QTreeWidgetItem(ui->stealthAddressTree);
        item->setText(0, QString::fromStdString(addr.label));
        item->setText(1, QString::fromStdString(addr.address));
        item->setText(2, QString::fromStdString(addr.created));
    }
}

void PrivacyPage::updateDisplayUnit()
{
    updatePrivacyBalance();
}
