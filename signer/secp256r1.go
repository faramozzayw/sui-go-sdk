package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"golang.org/x/crypto/blake2b"
)

const SigFlagSecp256r1 = 0x02

type Secp256r1Signer struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	SuiAddress string
}

func NewSecp256r1Signer(secretKey []byte) *Secp256r1Signer {
	d := new(big.Int).SetBytes(secretKey)
	curve := elliptic.P256()

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(secretKey)

	pubBytes := elliptic.MarshalCompressed(curve, priv.PublicKey.X, priv.PublicKey.Y)
	addr := toSuiAddress(pubBytes, SigFlagSecp256r1)

	return &Secp256r1Signer{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		SuiAddress: addr,
	}

}

func (s *Secp256r1Signer) Sign(message []byte) ([]byte, error) {
	digest := blake2b.Sum256(message)
	msgHash := sha256.Sum256(digest[:])

	r, ss, err := ecdsa.Sign(rand.Reader, s.PrivateKey, msgHash[:])
	if err != nil {
		return nil, err
	}

	rBytes := r.Bytes()
	sBytes := ss.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)

	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	rawSig := append(rPadded, sPadded...)

	return rawSig, nil
}

func (s *Secp256r1Signer) SignMessage(data string, scope constant.IntentScope) (*SignedMessageSerializedSig, error) {
	txBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	message := models.NewMessageWithIntent(txBytes, scope)
	digest := blake2b.Sum256(message)
	hash := sha256.Sum256(digest[:])

	r, ss, err := ecdsa.Sign(rand.Reader, s.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}

	rBytes := r.Bytes()
	sBytes := ss.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	rawSig := append(rPadded, sPadded...)
	pubBytes := elliptic.MarshalCompressed(s.PublicKey.Curve, s.PublicKey.X, s.PublicKey.Y)

	return &SignedMessageSerializedSig{
		Message:   data,
		Signature: models.ToSerializedSignature(rawSig, pubBytes, SigFlagSecp256r1),
	}, nil

}

func (s *Secp256r1Signer) Address() string {
	return s.SuiAddress
}

func (s *Secp256r1Signer) PublicKeyBytes() []byte {
	return elliptic.MarshalCompressed(s.PrivateKey.Curve, s.PrivateKey.PublicKey.X, s.PrivateKey.PublicKey.Y)
}

func (s *Secp256r1Signer) Schema() byte {
	return byte(SigFlagSecp256r1)
}
