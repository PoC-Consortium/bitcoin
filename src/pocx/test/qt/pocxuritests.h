// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#ifndef BITCOIN_POCX_TEST_QT_POCXURITESTS_H
#define BITCOIN_POCX_TEST_QT_POCXURITESTS_H

#include <QObject>

class PoCXURITests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void nativePaymentURIs();
};

#endif // BITCOIN_POCX_TEST_QT_POCXURITESTS_H
