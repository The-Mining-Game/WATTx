// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_QT_PRIVACYPAGE_H
#define WATTX_QT_PRIVACYPAGE_H

#include <interfaces/wallet.h>
#include <qt/clientmodel.h>

#include <QWidget>
#include <memory>

class WalletModel;
class ClientModel;
class PlatformStyle;

namespace Ui {
    class PrivacyPage;
}

/** Privacy dashboard - balance, shielding, stealth address management */
class PrivacyPage : public QWidget
{
    Q_OBJECT

public:
    explicit PrivacyPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~PrivacyPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    void numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state);

Q_SIGNALS:
    void requireUnlock(bool fromMenu);
    void message(const QString &title, const QString &message, unsigned int style);

private:
    Ui::PrivacyPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle* const platformStyle;

private Q_SLOTS:
    void on_shieldButton_clicked();
    void updatePrivacyBalance();
    void on_generateStealthButton_clicked();
    void on_copyAddressButton_clicked();
    void refreshStealthAddresses();
    void updateDisplayUnit();
};

#endif // WATTX_QT_PRIVACYPAGE_H
