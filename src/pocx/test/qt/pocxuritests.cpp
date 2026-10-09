// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#include <pocx/test/qt/pocxuritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QTest>
#include <QUrl>

void PoCXURITests::nativePaymentURIs()
{
    SendCoinsRecipient rv;
    QUrl uri;
    // PoCX: btcx: is the native scheme, bitcoin: is still accepted on parse.
    uri.setUrl(QString("btcx:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("BTCX:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));

    uri.setUrl(QString("pocx:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Formatting always emits btcx:
    SendCoinsRecipient out;
    out.address = QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W");
    out.amount = 10000000000LL;
    out.label = QString("Wikipedia Example");
    QVERIFY(GUIUtil::formatBitcoinURI(out).startsWith("btcx:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"));
    QVERIFY(!GUIUtil::formatBitcoinURI(out).startsWith("bitcoin:"));
}
