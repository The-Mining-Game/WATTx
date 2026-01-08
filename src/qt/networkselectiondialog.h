// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_NETWORKSELECTIONDIALOG_H
#define BITCOIN_QT_NETWORKSELECTIONDIALOG_H

#include <QDialog>

class QComboBox;
class QLabel;
class QPushButton;
class QVBoxLayout;

/**
 * Network selection dialog shown at startup.
 * Allows user to choose between Mainnet and Testnet.
 */
class NetworkSelectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NetworkSelectionDialog(QWidget *parent = nullptr);
    ~NetworkSelectionDialog();

    /** Returns true if testnet was selected */
    bool isTestnetSelected() const;

    /** Returns the selected network name */
    QString getSelectedNetwork() const;

private:
    QComboBox *networkCombo;
    QLabel *titleLabel;
    QLabel *descLabel;
    QPushButton *okButton;

    void setupUi();
};

#endif // BITCOIN_QT_NETWORKSELECTIONDIALOG_H
