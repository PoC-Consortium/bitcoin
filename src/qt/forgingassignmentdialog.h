// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_FORGINGASSIGNMENTDIALOG_H
#define BITCOIN_QT_FORGINGASSIGNMENTDIALOG_H

#include <QWidget>
#include <memory>

class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QComboBox;
class QGroupBox;
QT_END_NAMESPACE

// UI created programmatically

/** Widget for creating forging assignment and revocation transactions */
class ForgingAssignmentDialog : public QWidget
{
    Q_OBJECT

public:
    enum Mode {
        AssignMode,
        RevokeMode,
        CheckMode
    };

    explicit ForgingAssignmentDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~ForgingAssignmentDialog();

    void setModel(WalletModel *model);
    void setMode(Mode mode);

public Q_SLOTS:
    void clear();

private Q_SLOTS:
    void on_assignRadioButton_clicked();
    void on_revokeRadioButton_clicked();
    void on_checkRadioButton_clicked();
    void on_sendButton_clicked();
    void on_checkButton_clicked();
    void updateTabsAndLabels();
    void validateInputs();
    void populateAddressCombo();
    void onAddressComboChanged(int index);

Q_SIGNALS:
    void message(const QString &title, const QString &message, unsigned int style);

private:
    // UI elements
    QComboBox *plotAddressCombo;
    QLineEdit *forgingAddressEdit;
    QLabel *forgingAddressLabel;
    QLabel *descriptionLabel;
    QLabel *statusLabel;
    QGroupBox *assignmentStatusBox;
    QRadioButton *assignRadioButton;
    QRadioButton *revokeRadioButton;
    QRadioButton *checkRadioButton;
    QPushButton *sendButton;
    QPushButton *checkButton;
    QPushButton *clearButton;

    WalletModel *model;
    const PlatformStyle *platformStyle;
    Mode currentMode;

    bool validatePlotterId();
    bool validateForgingAddress();
    bool createAssignmentTransaction();
    bool createRevocationTransaction();
    void checkAssignmentStatus();
    QString getAddressFromCombo();
};

#endif // BITCOIN_QT_FORGINGASSIGNMENTDIALOG_H