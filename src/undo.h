// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        ::Serialize(s, VARINT(txout.nHeight * uint32_t{2} + txout.fCoinBase ));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout)); }
};

#ifdef ENABLE_POCX
/** Undo information for PoCX forging assignments (OP_RETURN-only architecture) */
struct ForgingUndo
{
    enum class UndoType : uint8_t {
        ADDED = 0,      // Assignment was added (delete on undo)
        MODIFIED = 1,   // Assignment was modified (restore on undo)
        REVOKED = 2     // Assignment was revoked (un-revoke on undo)
    };

    UndoType type;
    ForgingAssignment assignment;  // Full assignment state before change

    ForgingUndo() : type(UndoType::ADDED) {}
    ForgingUndo(UndoType t, const ForgingAssignment& a) : type(t), assignment(a) {}

    SERIALIZE_METHODS(ForgingUndo, obj) {
        uint8_t type_byte = static_cast<uint8_t>(obj.type);
        READWRITE(type_byte, obj.assignment);
        SER_READ(obj, obj.type = static_cast<UndoType>(type_byte));
    }
};
#endif

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

#ifdef ENABLE_POCX
    std::vector<ForgingUndo> vforgingundo; // PoCX assignment changes
#endif

    SERIALIZE_METHODS(CBlockUndo, obj) {
        READWRITE(obj.vtxundo);
#ifdef ENABLE_POCX
        READWRITE(obj.vforgingundo);
#endif
    }
};

#endif // BITCOIN_UNDO_H
