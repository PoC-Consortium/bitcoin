// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_POCX

#include <qt/forgingassignmentdialog.h>
// UI is defined programmatically, not using .ui file

#include <qt/guiutil.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/optionsmodel.h>

#include <interfaces/node.h>

#include <pocx/assignments/opcodes.h>
#include <wallet/wallet.h>
#include <pocx/assignments/transactions.h>
#include <wallet/coincontrol.h>
#include <validation.h>
#include <policy/policy.h>
#include <util/translation.h>
#include <node/types.h>
#include <key_io.h>
#include <coins.h>
#include <node/context.h>
#include <node/transaction.h>
#include <rpc/server_util.h>
#include <policy/policy.h>
#include <chainparams.h>
#include <addresstype.h>

#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpressionValidator>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QRadioButton>
#include <QGroupBox>
#include <QButtonGroup>
#include <QComboBox>
#include <QTimer>
#include <QDebug>

ForgingAssignmentDialog::ForgingAssignmentDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    model(nullptr),
    platformStyle(_platformStyle),
    currentMode(AssignMode)
{
    // Set window properties
    setWindowTitle(tr("Forging Assignment Manager"));
    resize(600, 450);

    // Create main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Create mode selection group
    QGroupBox *modeGroup = new QGroupBox(tr("Operation"));
    QHBoxLayout *modeLayout = new QHBoxLayout(modeGroup);

    assignRadioButton = new QRadioButton(tr("Create Assignment"));
    revokeRadioButton = new QRadioButton(tr("Revoke Assignment"));
    checkRadioButton = new QRadioButton(tr("Check Assignment Status"));

    modeLayout->addWidget(assignRadioButton);
    modeLayout->addWidget(revokeRadioButton);
    modeLayout->addWidget(checkRadioButton);

    assignRadioButton->setChecked(true);

    // Create input form
    QFormLayout *formLayout = new QFormLayout();

    // Plot address combo with editable option
    plotAddressCombo = new QComboBox();
    plotAddressCombo->setEditable(true);
    plotAddressCombo->setPlaceholderText(tr("Select or enter plot address (segwit v0)"));
    plotAddressCombo->setMinimumWidth(350);
    formLayout->addRow(tr("Plot Address:"), plotAddressCombo);

    forgingAddressEdit = new QLineEdit();
    forgingAddressEdit->setPlaceholderText(tr("Enter forging/pool address (segwit v0)"));
    forgingAddressEdit->setEnabled(true);
    forgingAddressLabel = new QLabel(tr("Forging Address:"));
    formLayout->addRow(forgingAddressLabel, forgingAddressEdit);

    // Assignment status display
    assignmentStatusBox = new QGroupBox(tr("Assignment Status"));
    QVBoxLayout *statusLayout = new QVBoxLayout(assignmentStatusBox);
    statusLabel = new QLabel(tr("No status checked yet"));
    statusLabel->setWordWrap(true);
    statusLabel->setStyleSheet("QLabel { padding: 10px; background-color: #f0f0f0; border-radius: 5px; }");
    statusLayout->addWidget(statusLabel);
    assignmentStatusBox->setVisible(false);

    // Description label
    descriptionLabel = new QLabel(tr("Create a new forging assignment to delegate your plot's forging rights."));
    descriptionLabel->setWordWrap(true);

    // Create button box
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    sendButton = new QPushButton(tr("Send Transaction"));
    checkButton = new QPushButton(tr("Check Status"));
    clearButton = new QPushButton(tr("Clear"));

    buttonLayout->addStretch();
    buttonLayout->addWidget(clearButton);
    buttonLayout->addWidget(checkButton);
    buttonLayout->addWidget(sendButton);

    checkButton->setVisible(false);

    // Add all to main layout
    mainLayout->addWidget(modeGroup);
    mainLayout->addLayout(formLayout);
    mainLayout->addWidget(assignmentStatusBox);
    mainLayout->addWidget(descriptionLabel);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Configure input validation for custom addresses (basic bech32 pattern)
    // Note: We use proper address validation in the validation functions
    QRegularExpressionValidator* addressValidator = new QRegularExpressionValidator(
        QRegularExpression("[a-zA-Z0-9]*"), this);
    plotAddressCombo->setValidator(addressValidator);
    forgingAddressEdit->setValidator(addressValidator);

    // Connect signals
    connect(assignRadioButton, &QRadioButton::clicked, this, &ForgingAssignmentDialog::on_assignRadioButton_clicked);
    connect(revokeRadioButton, &QRadioButton::clicked, this, &ForgingAssignmentDialog::on_revokeRadioButton_clicked);
    connect(checkRadioButton, &QRadioButton::clicked, this, &ForgingAssignmentDialog::on_checkRadioButton_clicked);
    connect(sendButton, &QPushButton::clicked, this, &ForgingAssignmentDialog::on_sendButton_clicked);
    connect(checkButton, &QPushButton::clicked, this, &ForgingAssignmentDialog::on_checkButton_clicked);
    connect(clearButton, &QPushButton::clicked, this, &ForgingAssignmentDialog::clear);
    connect(plotAddressCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForgingAssignmentDialog::onAddressComboChanged);
    connect(plotAddressCombo->lineEdit(), &QLineEdit::textChanged, this, &ForgingAssignmentDialog::validateInputs);
    connect(forgingAddressEdit, &QLineEdit::textChanged, this, &ForgingAssignmentDialog::validateInputs);

    // Initial validation
    validateInputs();
}

ForgingAssignmentDialog::~ForgingAssignmentDialog()
{
}

void ForgingAssignmentDialog::setModel(WalletModel *_model)
{
    model = _model;

    if (model && model->getOptionsModel() && model->getAddressTableModel()) {
        // Populate address combo when model is set
        populateAddressCombo();

        // Connect to address table changes to refresh dropdown
        connect(model->getAddressTableModel(), &AddressTableModel::rowsInserted, this, &ForgingAssignmentDialog::populateAddressCombo);
        connect(model->getAddressTableModel(), &AddressTableModel::rowsRemoved, this, &ForgingAssignmentDialog::populateAddressCombo);
    } else {
        // If models aren't ready, try again with a timer
        QTimer::singleShot(100, this, &ForgingAssignmentDialog::populateAddressCombo);
    }
}

void ForgingAssignmentDialog::populateAddressCombo()
{
    if (!model) {
        qDebug() << "ForgingAssignmentDialog: No model available";
        return;
    }

    plotAddressCombo->clear();

    // Add empty item for custom input
    plotAddressCombo->addItem(tr("-- Enter custom address --"), "");

    // Get all receiving addresses
    AddressTableModel* addressTableModel = model->getAddressTableModel();
    if (!addressTableModel) {
        qDebug() << "ForgingAssignmentDialog: No address table model available";
        return;
    }

    int rowCount = addressTableModel->rowCount(QModelIndex());
    qDebug() << "ForgingAssignmentDialog: Address table has" << rowCount << "rows";

    for (int i = 0; i < rowCount; ++i) {
        QModelIndex labelIndex = addressTableModel->index(i, AddressTableModel::Label, QModelIndex());
        QModelIndex addressIndex = addressTableModel->index(i, AddressTableModel::Address, QModelIndex());

        QString type = addressTableModel->data(labelIndex, AddressTableModel::TypeRole).toString();
        QString label = addressTableModel->data(labelIndex, Qt::DisplayRole).toString();
        QString address = addressTableModel->data(addressIndex, Qt::DisplayRole).toString();

        qDebug() << "ForgingAssignmentDialog: Row" << i << "- Type:" << type << "Label:" << label << "Address:" << address;

        // Only add receiving addresses (not change addresses)
        if (type == AddressTableModel::Receive) {
            qDebug() << "ForgingAssignmentDialog: Found receiving address:" << address;

            // Check if address is segwit v0 (WitnessV0KeyHash) - not taproot
            CTxDestination dest = DecodeDestination(address.toStdString());
            bool isSegwitV0 = std::holds_alternative<WitnessV0KeyHash>(dest);

            if (isSegwitV0) {
                QString displayText = label.isEmpty() ? address : QString("%1 (%2)").arg(label, address);
                plotAddressCombo->addItem(displayText, address);
                qDebug() << "ForgingAssignmentDialog: Added segwit v0 to combo:" << displayText;
            } else {
                qDebug() << "ForgingAssignmentDialog: Skipping non-segwit-v0 address:" << address;
            }
        }
    }

    qDebug() << "ForgingAssignmentDialog: Final combo count:" << plotAddressCombo->count();
}

void ForgingAssignmentDialog::onAddressComboChanged(int index)
{
    if (index > 0) {
        // User selected a predefined address
        QString address = plotAddressCombo->itemData(index).toString();
        plotAddressCombo->setEditText(address);
    }

    validateInputs();
}

QString ForgingAssignmentDialog::getAddressFromCombo()
{
    QString text = plotAddressCombo->currentText();

    // If it contains a label in parentheses, extract just the address
    QRegularExpression re("\\(([^)]+)\\)");
    QRegularExpressionMatch match = re.match(text);
    if (match.hasMatch()) {
        return match.captured(1);
    }

    return text;
}

void ForgingAssignmentDialog::setMode(Mode mode)
{
    currentMode = mode;

    switch(mode) {
        case AssignMode:
            assignRadioButton->setChecked(true);
            break;
        case RevokeMode:
            revokeRadioButton->setChecked(true);
            break;
        case CheckMode:
            checkRadioButton->setChecked(true);
            break;
    }

    updateTabsAndLabels();
}

void ForgingAssignmentDialog::on_assignRadioButton_clicked()
{
    currentMode = AssignMode;
    updateTabsAndLabels();
}

void ForgingAssignmentDialog::on_revokeRadioButton_clicked()
{
    currentMode = RevokeMode;
    updateTabsAndLabels();
}

void ForgingAssignmentDialog::on_checkRadioButton_clicked()
{
    currentMode = CheckMode;
    updateTabsAndLabels();
}

void ForgingAssignmentDialog::updateTabsAndLabels()
{
    switch(currentMode) {
        case AssignMode:
            setWindowTitle(tr("Create Forging Assignment"));
            forgingAddressLabel->setVisible(true);
            forgingAddressEdit->setVisible(true);
            sendButton->setVisible(true);
            checkButton->setVisible(false);
            assignmentStatusBox->setVisible(false);
            descriptionLabel->setText(tr("Create a new forging assignment to delegate your plot's forging rights to a pool or another address."));
            sendButton->setText(tr("Send Assignment"));
            break;

        case RevokeMode:
            setWindowTitle(tr("Revoke Forging Assignment"));
            forgingAddressLabel->setVisible(false);
            forgingAddressEdit->setVisible(false);
            sendButton->setVisible(true);
            checkButton->setVisible(false);
            assignmentStatusBox->setVisible(false);
            descriptionLabel->setText(tr("Revoke an existing forging assignment to reclaim your plot's forging rights."));
            sendButton->setText(tr("Send Revocation"));
            break;

        case CheckMode:
            setWindowTitle(tr("Check Assignment Status"));
            forgingAddressLabel->setVisible(false);
            forgingAddressEdit->setVisible(false);
            sendButton->setVisible(false);
            checkButton->setVisible(true);
            assignmentStatusBox->setVisible(true);
            descriptionLabel->setText(tr("Check the current assignment status for a plot address."));
            break;
    }

    validateInputs();
}

void ForgingAssignmentDialog::validateInputs()
{
    bool valid = false;

    switch(currentMode) {
        case AssignMode:
            valid = validatePlotterId() && validateForgingAddress();
            sendButton->setEnabled(valid);
            break;

        case RevokeMode:
            valid = validatePlotterId();
            sendButton->setEnabled(valid);
            break;

        case CheckMode:
            valid = validatePlotterId();
            checkButton->setEnabled(valid);
            break;
    }
}

bool ForgingAssignmentDialog::validatePlotterId()
{
    QString address = getAddressFromCombo();

    if (address.isEmpty()) return false;

    // Check if address is valid segwit v0
    CTxDestination dest = DecodeDestination(address.toStdString());
    bool isSegwitV0 = std::holds_alternative<WitnessV0KeyHash>(dest);

    return isSegwitV0;
}

bool ForgingAssignmentDialog::validateForgingAddress()
{
    QString address = forgingAddressEdit->text().trimmed();

    if (address.isEmpty()) return false;

    // Check if address is valid segwit v0
    CTxDestination dest = DecodeDestination(address.toStdString());
    bool isValid = std::holds_alternative<WitnessV0KeyHash>(dest);

    if (!isValid) return false;

    // Check it's different from plot address
    if (address == getAddressFromCombo()) {
        qDebug() << "ForgingAssignmentDialog: Forging address same as plot address";
        return false;
    }

    return true;
}

void ForgingAssignmentDialog::checkAssignmentStatus()
{
    if (!model || !validatePlotterId()) {
        statusLabel->setText(tr("Invalid plot address"));
        return;
    }

    QString plotAddress = getAddressFromCombo();

    // Convert address to account ID
    CTxDestination dest = DecodeDestination(plotAddress.toStdString());
    if (!IsValidDestination(dest)) {
        statusLabel->setText(tr("Invalid plot address format"));
        return;
    }

    // Get the account ID from the destination
    const WitnessV0KeyHash* witness = std::get_if<WitnessV0KeyHash>(&dest);
    if (!witness) {
        statusLabel->setText(tr("Plot address must be a bech32 address"));
        return;
    }

    // Convert to 20-byte array
    std::array<uint8_t, 20> plotAccountId;
    std::copy(witness->begin(), witness->end(), plotAccountId.begin());

    // Check assignment status via node context
    std::string statusText;
    std::string forgingAddress;
    ForgingState state = ForgingState::UNASSIGNED;
    QString details;

    // Access chainstate through wallet's chain interface
    try {
        // Get the chain interface from the wallet
        wallet::CWallet* pWallet = model->wallet().wallet();
        if (!pWallet) {
            statusLabel->setText(tr("Wallet not available"));
            return;
        }

        // Access the chainstate through the node context (same pattern as in wallettests.cpp)
        auto* nodeContext = model->node().context();
        if (!nodeContext || !nodeContext->chainman) {
            statusLabel->setText(tr("Chainstate not available"));
            return;
        }

        LOCK(cs_main);
        const CCoinsViewCache& view = nodeContext->chainman->ActiveChainstate().CoinsTip();
        int currentHeight = nodeContext->chainman->ActiveChainstate().m_chain.Height();
        auto assignment = view.GetForgingAssignment(plotAccountId, currentHeight);

        if (!assignment.has_value()) {
            statusText = "UNASSIGNED - No assignment exists";
        } else {
            // Get current height for state derivation
            int currentHeight = nodeContext->chainman->ActiveChain().Height();
            state = assignment->GetStateAtHeight(currentHeight);

            // Convert forging address to bech32
            std::vector<unsigned char> forgingBytes(assignment->forgingAddress.begin(),
                                                    assignment->forgingAddress.end());
            CTxDestination forgingDest = WitnessV0KeyHash(uint160(forgingBytes));
            forgingAddress = EncodeDestination(forgingDest);

            // Build detailed status with heights
            switch(state) {
                case ForgingState::UNASSIGNED:
                    statusText = "UNASSIGNED - No assignment exists";
                    break;
                case ForgingState::ASSIGNING: {
                    int blocksRemaining = assignment->assignment_effective_height - currentHeight;
                    statusText = "ASSIGNING - Assignment pending activation";
                    details = QString("<br>• Forging Address: %1"
                                     "<br>• Created at height: %2"
                                     "<br>• Activates at height: %3 (%4 blocks remaining)")
                        .arg(QString::fromStdString(forgingAddress))
                        .arg(assignment->assignment_height)
                        .arg(assignment->assignment_effective_height)
                        .arg(blocksRemaining);
                    break;
                }
                case ForgingState::ASSIGNED:
                    statusText = "ASSIGNED - Active assignment";
                    details = QString("<br>• Forging Address: %1"
                                     "<br>• Created at height: %2"
                                     "<br>• Activated at height: %3")
                        .arg(QString::fromStdString(forgingAddress))
                        .arg(assignment->assignment_height)
                        .arg(assignment->assignment_effective_height);
                    break;
                case ForgingState::REVOKING: {
                    int blocksRemaining = assignment->revocation_effective_height - currentHeight;
                    statusText = "REVOKING - Revocation pending";
                    details = QString("<br>• Forging Address: %1 (still active)"
                                     "<br>• Assignment created: %2, activated: %3"
                                     "<br>• Revoked at height: %4"
                                     "<br>• Revocation becomes effective at: %5 (%6 blocks remaining)")
                        .arg(QString::fromStdString(forgingAddress))
                        .arg(assignment->assignment_height)
                        .arg(assignment->assignment_effective_height)
                        .arg(assignment->revocation_height)
                        .arg(assignment->revocation_effective_height)
                        .arg(blocksRemaining);
                    break;
                }
                case ForgingState::REVOKED:
                    statusText = "REVOKED - Assignment revoked";
                    details = QString("<br>• Previously assigned to: %1"
                                     "<br>• Assignment created: %2, activated: %3"
                                     "<br>• Revoked at height: %4"
                                     "<br>• Revocation effective: %5")
                        .arg(QString::fromStdString(forgingAddress))
                        .arg(assignment->assignment_height)
                        .arg(assignment->assignment_effective_height)
                        .arg(assignment->revocation_height)
                        .arg(assignment->revocation_effective_height);
                    break;
            }
        }
    } catch (const std::exception& e) {
        statusLabel->setText(tr("Error accessing blockchain: %1").arg(e.what()));
        return;
    }

    // Update status display with formatting based on state
    QString stateColor;
    switch(state) {
        case ForgingState::UNASSIGNED:
            stateColor = "#808080"; // Gray
            break;
        case ForgingState::ASSIGNING:
            stateColor = "#FFA500"; // Orange - pending activation
            break;
        case ForgingState::ASSIGNED:
            stateColor = "#008000"; // Green - active
            break;
        case ForgingState::REVOKING:
            stateColor = "#FF6600"; // Red-orange - pending revocation
            break;
        case ForgingState::REVOKED:
            stateColor = "#FF0000"; // Red - revoked
            break;
    }

    QString formattedStatus = QString("<b style='color: %1;'>%2</b>%3")
        .arg(stateColor)
        .arg(QString::fromStdString(statusText))
        .arg(details);

    statusLabel->setText(formattedStatus);
}

void ForgingAssignmentDialog::on_sendButton_clicked()
{
    if (!model) {
        QMessageBox::critical(this, tr("Error"), tr("No wallet model available"));
        return;
    }

    bool success = false;

    switch(currentMode) {
        case AssignMode:
            success = createAssignmentTransaction();
            break;
        case RevokeMode:
            success = createRevocationTransaction();
            break;
        default:
            break;
    }

    if (success) {
        clear();
    }
}

void ForgingAssignmentDialog::on_checkButton_clicked()
{
    checkAssignmentStatus();
}

bool ForgingAssignmentDialog::createAssignmentTransaction()
{
    if (!model) {
        QMessageBox::critical(this, tr("Error"), tr("No wallet model available"));
        return false;
    }

    // Check if wallet is available and not watch-only
    if (model->wallet().privateKeysDisabled()) {
        QMessageBox::critical(this, tr("Error"), tr("Cannot create transactions with watch-only wallet"));
        return false;
    }

    QString plotAddress = getAddressFromCombo();
    QString forgingAddress = forgingAddressEdit->text().trimmed();

    // Convert addresses to destinations
    CTxDestination plotDest = DecodeDestination(plotAddress.toStdString());
    CTxDestination forgingDest = DecodeDestination(forgingAddress.toStdString());

    if (!IsValidDestination(plotDest) || !IsValidDestination(forgingDest)) {
        QMessageBox::critical(this, tr("Error"), tr("Invalid address format"));
        return false;
    }

    // Pre-flight validation: Check current assignment state
    const WitnessV0KeyHash* plot_witness = std::get_if<WitnessV0KeyHash>(&plotDest);
    if (!plot_witness) {
        QMessageBox::critical(this, tr("Error"), tr("Plot address must be segwit v0 (bech32)"));
        return false;
    }

    std::array<uint8_t, 20> plotAccountId;
    std::copy(plot_witness->begin(), plot_witness->end(), plotAccountId.begin());

    // Check assignment state before creating transaction
    auto* nodeContext = model->node().context();
    if (!nodeContext || !nodeContext->chainman) {
        QMessageBox::critical(this, tr("Error"), tr("Node context not available"));
        return false;
    }

    {
        LOCK(cs_main);
        const CCoinsViewCache& view = nodeContext->chainman->ActiveChainstate().CoinsTip();
        int currentHeight = nodeContext->chainman->ActiveChainstate().m_chain.Height();
        auto assignment = view.GetForgingAssignment(plotAccountId, currentHeight);

        if (assignment.has_value()) {
            ForgingState state = assignment->GetStateAtHeight(currentHeight);
            if (state != ForgingState::UNASSIGNED && state != ForgingState::REVOKED) {
                QMessageBox::critical(this, tr("Invalid State"),
                    tr("Cannot create assignment: plot is in %1 state.\n\n"
                       "Assignments can only be created when the plot is UNASSIGNED or REVOKED.")
                    .arg(ForgingStateToString(state)));
                return false;
            }
        }
    }

    // Create the assignment transaction
    wallet::CWallet* pWallet = model->wallet().wallet();
    if (!pWallet) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet not available"));
        return false;
    }

    try {
        // CreateForgingAssignmentTransaction expects bech32 addresses directly
        wallet::CCoinControl coin_control;
        // Set fee rate according to specification: minRelayFee × 10
        CFeeRate minRelayFee = pWallet->chain().relayMinFee();
        coin_control.m_feerate = CFeeRate(minRelayFee.GetFeePerK() * 10);
        CAmount fee = 0;
        auto result = pocx::assignments::CreateForgingAssignmentTransaction(
            *pWallet,
            getAddressFromCombo().toStdString(),
            forgingAddress.toStdString(),
            coin_control,
            fee
        );

        if (!result) {
            QMessageBox::critical(this, tr("Transaction Creation Failed"),
                                QString::fromStdString(util::ErrorString(result).original));
            return false;
        }

        CTransactionRef tx = result.value();

        // Broadcast the transaction
        std::string err_string;
        pWallet->CommitTransaction(tx, {}, {});

        // Try to broadcast
        CAmount max_tx_fee = node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK();
        if (!pWallet->chain().broadcastTransaction(tx, max_tx_fee, true, err_string)) {
            QMessageBox::critical(this, tr("Transaction Failed"),
                                QString::fromStdString(err_string));
            return false;
        }

        QMessageBox::information(this, tr("Success"),
            tr("Forging assignment transaction sent successfully.\n"
               "Transaction ID: %1").arg(QString::fromStdString(tx->GetHash().ToString())));

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                             tr("Failed to create transaction: %1").arg(e.what()));
        return false;
    }
}

bool ForgingAssignmentDialog::createRevocationTransaction()
{
    if (!model) {
        QMessageBox::critical(this, tr("Error"), tr("No wallet model available"));
        return false;
    }

    // Check if wallet is available and not watch-only
    if (model->wallet().privateKeysDisabled()) {
        QMessageBox::critical(this, tr("Error"), tr("Cannot create transactions with watch-only wallet"));
        return false;
    }

    QString plotAddress = getAddressFromCombo();

    // Convert address to destination
    CTxDestination plotDest = DecodeDestination(plotAddress.toStdString());

    if (!IsValidDestination(plotDest)) {
        QMessageBox::critical(this, tr("Error"), tr("Invalid address format"));
        return false;
    }

    // Pre-flight validation: Check current assignment state
    const WitnessV0KeyHash* plot_witness = std::get_if<WitnessV0KeyHash>(&plotDest);
    if (!plot_witness) {
        QMessageBox::critical(this, tr("Error"), tr("Plot address must be segwit v0 (bech32)"));
        return false;
    }

    std::array<uint8_t, 20> plotAccountId;
    std::copy(plot_witness->begin(), plot_witness->end(), plotAccountId.begin());

    // Check assignment state before creating transaction
    auto* nodeContext = model->node().context();
    if (!nodeContext || !nodeContext->chainman) {
        QMessageBox::critical(this, tr("Error"), tr("Node context not available"));
        return false;
    }

    {
        LOCK(cs_main);
        const CCoinsViewCache& view = nodeContext->chainman->ActiveChainstate().CoinsTip();
        int currentHeight = nodeContext->chainman->ActiveChainstate().m_chain.Height();
        auto assignment = view.GetForgingAssignment(plotAccountId, currentHeight);

        if (!assignment.has_value()) {
            QMessageBox::critical(this, tr("Invalid State"),
                tr("Cannot revoke assignment: plot has no assignment.\n\n"
                   "The plot is currently UNASSIGNED."));
            return false;
        }

        ForgingState state = assignment->GetStateAtHeight(currentHeight);
        if (state != ForgingState::ASSIGNED) {
            QMessageBox::critical(this, tr("Invalid State"),
                tr("Cannot revoke assignment: plot is in %1 state.\n\n"
                   "Revocations can only be created when the plot is ASSIGNED (active).")
                .arg(ForgingStateToString(state)));
            return false;
        }
    }

    // Create the revocation transaction
    wallet::CWallet* pWallet = model->wallet().wallet();
    if (!pWallet) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet not available"));
        return false;
    }

    try {
        // OP_RETURN architecture: Pass plot address directly
        wallet::CCoinControl coin_control;
        // Set fee rate according to specification: minRelayFee × 10
        CFeeRate minRelayFee = pWallet->chain().relayMinFee();
        coin_control.m_feerate = CFeeRate(minRelayFee.GetFeePerK() * 10);
        CAmount fee = 0;
        auto result = pocx::assignments::CreateForgingRevocationTransaction(
            *pWallet,
            plotAddress.toStdString(),
            coin_control,
            fee
        );

        if (!result) {
            QMessageBox::critical(this, tr("Transaction Creation Failed"),
                                QString::fromStdString(util::ErrorString(result).original));
            return false;
        }

        CTransactionRef tx = result.value();

        // Broadcast the transaction
        std::string err_string;
        pWallet->CommitTransaction(tx, {}, {});

        // Try to broadcast
        CAmount max_tx_fee = node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK();
        if (!pWallet->chain().broadcastTransaction(tx, max_tx_fee, true, err_string)) {
            QMessageBox::critical(this, tr("Transaction Failed"),
                                QString::fromStdString(err_string));
            return false;
        }

        QMessageBox::information(this, tr("Success"),
            tr("Forging revocation transaction sent successfully.\n"
               "Transaction ID: %1").arg(QString::fromStdString(tx->GetHash().ToString())));

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                             tr("Failed to create transaction: %1").arg(e.what()));
        return false;
    }
}

void ForgingAssignmentDialog::clear()
{
    plotAddressCombo->setCurrentIndex(0);
    plotAddressCombo->clearEditText();
    forgingAddressEdit->clear();
    statusLabel->setText(tr("No status checked yet"));
    validateInputs();
}

#endif // ENABLE_POCX