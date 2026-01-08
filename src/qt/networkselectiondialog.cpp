// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkselectiondialog.h>

#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QApplication>
#include <QScreen>

NetworkSelectionDialog::NetworkSelectionDialog(QWidget *parent)
    : QDialog(parent)
{
    setupUi();
}

NetworkSelectionDialog::~NetworkSelectionDialog()
{
}

void NetworkSelectionDialog::setupUi()
{
    setWindowTitle(tr("WATTx - Select Network"));
    setFixedSize(350, 200);
    setModal(true);

    // Center on screen
    if (QScreen *screen = QApplication::primaryScreen()) {
        QRect screenGeometry = screen->geometry();
        int x = (screenGeometry.width() - width()) / 2;
        int y = (screenGeometry.height() - height()) / 2;
        move(x, y);
    }

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(30, 30, 30, 30);

    // Title
    titleLabel = new QLabel(tr("WATTx Wallet"), this);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    // Description
    descLabel = new QLabel(tr("Select which network to connect to:"), this);
    descLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(descLabel);

    // Network dropdown
    networkCombo = new QComboBox(this);
    networkCombo->addItem(tr("Mainnet (Production)"), QVariant(false));
    networkCombo->addItem(tr("Testnet (Testing)"), QVariant(true));
    networkCombo->setCurrentIndex(0);  // Default to Mainnet
    mainLayout->addWidget(networkCombo);

    // OK Button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    okButton = new QPushButton(tr("Launch"), this);
    okButton->setDefault(true);
    okButton->setMinimumWidth(100);
    buttonLayout->addWidget(okButton);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);

    setLayout(mainLayout);
}

bool NetworkSelectionDialog::isTestnetSelected() const
{
    return networkCombo->currentData().toBool();
}

QString NetworkSelectionDialog::getSelectedNetwork() const
{
    return isTestnetSelected() ? "Testnet" : "Mainnet";
}
