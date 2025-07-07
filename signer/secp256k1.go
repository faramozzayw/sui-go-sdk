package signer

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/blake2b"
)

const SigFlagSecp256k1 = 0x01

type Secp256k1Signer struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  *secp256k1.PublicKey
	SuiAddress string
}

func NewSecp256k1Signer(secretKey []byte) *Secp256k1Signer {
	privKey := secp256k1.PrivKeyFromBytes(secretKey)
	pubKey := privKey.PubKey()
	addr := toSuiAddress(pubKey.SerializeCompressed(), byte(SigFlagSecp256k1))

	return &Secp256k1Signer{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		SuiAddress: addr,
	}
}

func (s *Secp256k1Signer) Sign(message []byte) ([]byte, error) {
	digest := blake2b.Sum256(message)
	msgHash := sha256.Sum256(digest[:])

	sig := ecdsa.Sign(s.PrivateKey, msgHash[:])

	r := sig.R()
	ss := sig.S()

	rBytes := r.Bytes()
	sBytes := ss.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)

	copy(rPadded[32-len(rBytes):], rBytes[:])
	copy(sPadded[32-len(sBytes):], sBytes[:])

	rawSig := append(rPadded, sPadded...)

	return rawSig, nil
}

func (s *Secp256k1Signer) SignMessage(data string, scope constant.IntentScope) (*SignedMessageSerializedSig, error) {
	txBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	message := models.NewMessageWithIntent(txBytes, scope)
	digest := blake2b.Sum256(message)
	hash := sha256.Sum256(digest[:])

	sig := ecdsa.Sign(s.PrivateKey, hash[:])
	r := sig.R()
	ss := sig.S()

	rBytes := r.Bytes()
	sBytes := ss.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes[:])
	copy(sPadded[32-len(sBytes):], sBytes[:])

	rawSig := append(rPadded, sPadded...)

	return &SignedMessageSerializedSig{
		Message:   data,
		Signature: models.ToSerializedSignature(rawSig, s.PublicKey.SerializeCompressed(), SigFlagSecp256k1),
	}, nil
}

func (s *Secp256k1Signer) Address() string {
	return s.SuiAddress
}

func (s *Secp256k1Signer) PublicKeyBytes() []byte {
	return s.PrivateKey.PubKey().SerializeCompressed()
}

func (s *Secp256k1Signer) Schema() byte {
	return byte(SigFlagSecp256k1)
}
