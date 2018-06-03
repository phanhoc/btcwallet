package signtrans

import (
	"errors"
	"github.com/btcsuite/btcutil"
	txScript "github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg"
	"fmt"
)

type addressToKey struct {
	key        *btcec.PrivateKey
	compressed bool
}

func mkGetKey(keys map[string]addressToKey) txScript.KeyDB {
	if keys == nil {
		return txScript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
			bool, error) {
			return nil, false, errors.New("nope")
		})
	}
	return txScript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
		bool, error) {
		a2k, ok := keys[addr.EncodeAddress()]
		if !ok {
			return nil, false, errors.New("nope")
		}
		return a2k.key, a2k.compressed, nil
	})
}

func mkGetScript(scripts map[string][]byte) txScript.ScriptDB {
	if scripts == nil {
		return txScript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
			return nil, errors.New("nope")
		})
	}
	return txScript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
		script, ok := scripts[addr.EncodeAddress()]
		if !ok {
			return nil, errors.New("nope")
		}
		return script, nil
	})
}

func SignAndCheck(tx *wire.MsgTx, privKey *btcec.PrivateKey, compressed bool, previousScript []byte) error {
	pk := (*btcec.PublicKey)(&privKey.PublicKey).
		SerializeCompressed()
	address, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pk), &chaincfg.SimNetParams)
	if err != nil {
		return fmt.Errorf("failed to make address: %v", err)
	}

	pkScript, err := txScript.PayToAddrScript(address)
	if err != nil {
		return fmt.Errorf("failed to make pkscript: %v", err)
	}

	getKey := mkGetKey(map[string]addressToKey{
		address.EncodeAddress(): {key: privKey, compressed: compressed},
	})

	getScript := mkGetScript(nil)
	for i, txIn := range tx.TxIn {
		script, err := txScript.SignTxOutput(&chaincfg.SimNetParams, tx, i,
			pkScript, txScript.SigHashAll, getKey, getScript, nil)
		if err != nil {
			return fmt.Errorf("failed to sign output: %v", err)
		}
		txIn.SignatureScript = script
	}

	return nil
}
