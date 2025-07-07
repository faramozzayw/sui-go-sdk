package signer

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/block-vision/sui-go-sdk/cryptography/scheme"
	"github.com/btcsuite/btcutil/bech32"
)

var signatureFlagToScheme = map[byte]string{
	0x00: "ED25519",
	0x01: "Secp256k1",
	0x02: "Secp256r1",
	0x03: "MultiSig",
	0x05: "ZkLogin",
	0x06: "Passkey",
}

type ParsedSuiSecretKey struct {
	Schema    scheme.SignatureScheme
	SecretKey []byte
}

const suiPrivateKeyPrefix = "suiprivkey"

// DecodeSuiPrivateKey decodes a Bech32-encoded Sui private key string
// into its schema type and raw secret key bytes.
func DecodeSuiPrivateKey(value string) (*ParsedSuiSecretKey, error) {
	hrp, data, err := bech32.Decode(value)
	if err != nil {
		return nil, err
	}

	if hrp != suiPrivateKeyPrefix {
		return nil, errors.New("invalid private key prefix")
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}

	if len(converted) < 2 {
		return nil, errors.New("invalid extended secret key")
	}

	flag := converted[0]
	secretKey := converted[1:]

	schema, ok := scheme.SignatureFlagToScheme[flag]
	if !ok {
		return nil, fmt.Errorf("unknown signature scheme flag: 0x%02x", flag)
	}

	return &ParsedSuiSecretKey{
		Schema:    schema,
		SecretKey: secretKey,
	}, nil
}

// SignerFromSuiSecret creates a SuiSigner instance from a Bech32-encoded Sui private key string.
// It supports Ed25519, Secp256k1, and Secp256r1 key schemas.
func SignerFromSuiSecret(encoded string) (Keypair, error) {
	parsed, err := DecodeSuiPrivateKey(encoded)
	if err != nil {
		return nil, err
	}

	switch string(parsed.Schema) {
	case "ED25519":
		if len(parsed.SecretKey) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid ed25519 seed length")
		}
		s := NewSigner(parsed.SecretKey)
		return s, nil

	case "Secp256k1":
		if len(parsed.SecretKey) != 32 {
			return nil, fmt.Errorf("invalid secp256k1 private key length")
		}
		s := NewSecp256k1Signer(parsed.SecretKey)
		return s, nil
	case "Secp256r1":
		if len(parsed.SecretKey) != 32 {
			return nil, fmt.Errorf("invalid secp256r1 private key length")
		}
		s := NewSecp256r1Signer(parsed.SecretKey)
		return s, nil

	default:
		return nil, fmt.Errorf("unsupported schema: %s", parsed.Schema)
	}
}
