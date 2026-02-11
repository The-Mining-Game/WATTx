// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_QT_TRUSTTIERPAGE_H
#define WATTX_QT_TRUSTTIERPAGE_H

#include <qt/clientmodel.h>

#include <QWidget>

class WalletModel;
class ClientModel;
class PlatformStyle;

namespace Ui {
    class TrustTierPage;
}

/** Trust Tier page widget - displays validator trust tier, uptime, and reward info */
class TrustTierPage : public QWidget
{
    Q_OBJECT

public:
    explicit TrustTierPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~TrustTierPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    void numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state);

Q_SIGNALS:
    void message(const QString &title, const QString &message, unsigned int style);

private:
    Ui::TrustTierPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle* const platformStyle;

private Q_SLOTS:
    void updateTrustInfo();
    void updateNetworkStats();
};

#endif // WATTX_QT_TRUSTTIERPAGE_H
