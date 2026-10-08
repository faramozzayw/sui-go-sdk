package signer_test

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

var (
	testEd25519Key   = "suiprivkey1qz86u0u95ky0zfaenhqrge4483m8sh5h59fr0pkgnypncrqcnx8ws4safpm"
	testSecp256k1Key = "suiprivkey1qz3s8u9scv5fk6ma0wm8n2rsvmqwtykcer0tfwjeknt8xy96verxqrdxpcf"
	testSecp256r1Key = "suiprivkey1qqlfj0p5tqd6fshhvypswl068k8awt5y54vjmwx8zf07ct6829xqz89gjdp"
)

var (
	testEd25519Signature   = "2mRkjtvn7rYxIlRfNKXC0h0esH2HEAaihvpXFD2ReMUBghJjkTdi+bDL6/WT0reI3zEB2+IV+ywa+8xvqvzwAA=="
	testSecp256k1Signature = "n14lks5/kqxifoeucE2t8TiPTUogbCGCCFOOT4INz068SQaY+eHc3vqNG/s3AjGZFDApbsqYvymkBUx7An4KAA=="
)

var (
	testEd25519Pubkey   = "4c3f14681e53aab8321c67894d5dd0894846281e9eca2715e528b00fa572bb57"
	testSecp256k1Pubkey = "f0dace75124b87898830199178b90c208625559afb19956c9d004522cf4b3dd9"
	testSecp256r1Pubkey = "0fc82bba88b167627cefe26b085f1afe11c61a282f4e1eae3f575c7aae7fee05"
)

func TestDecodeSuiPrivateKey(t *testing.T) {
	// Test invalid prefix
	_, err := signer.DecodeSuiPrivateKey("wrongprefix1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	assert.Error(t, err)

	// Test unknown schema flag (simulate with altered data)
	invalidKey := "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzzzzzz"
	_, err = signer.DecodeSuiPrivateKey(invalidKey)
	assert.Error(t, err)
}

func TestValidatedSecpSignerConstructors(t *testing.T) {
	invalidScalars := [][]byte{
		make([]byte, 32),
		make([]byte, 31),
	}

	for _, secretKey := range invalidScalars {
		if got, err := signer.NewSecp256k1SignerFromSecretKey(secretKey); err == nil || got != nil {
			t.Fatal("NewSecp256k1SignerFromSecretKey() accepted an invalid private key")
		}
		if got, err := signer.NewSecp256r1SignerFromSecretKey(secretKey); err == nil || got != nil {
			t.Fatal("NewSecp256r1SignerFromSecretKey() accepted an invalid private key")
		}
	}
	if got, err := signer.NewSecp256k1SignerFromSecretKey(secp256k1.Params().N.Bytes()); err == nil || got != nil {
		t.Fatal("NewSecp256k1SignerFromSecretKey() accepted its curve order")
	}
	if got, err := signer.NewSecp256r1SignerFromSecretKey(elliptic.P256().Params().N.Bytes()); err == nil || got != nil {
		t.Fatal("NewSecp256r1SignerFromSecretKey() accepted its curve order")
	}

	if got := signer.NewSecp256k1Signer(make([]byte, 32)); got != nil {
		t.Fatal("legacy Secp256k1 constructor must return nil for an invalid private key")
	}
	if got := signer.NewSecp256r1Signer(make([]byte, 32)); got != nil {
		t.Fatal("legacy Secp256r1 constructor must return nil for an invalid private key")
	}
}

func TestKeypairSignaturesVerifyAcrossSchemes(t *testing.T) {
	tests := []struct {
		name    string
		keypair signer.Keypair
	}{
		{"Ed25519", signer.NewSigner(make([]byte, 32))},
		{"Secp256k1", signer.NewSecp256k1Signer(append(make([]byte, 31), 1))},
		{"Secp256r1", signer.NewSecp256r1Signer(append(make([]byte, 31), 1))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := tt.keypair.SignMessage(base64.StdEncoding.EncodeToString([]byte("compatibility test")), constant.PersonalMessageIntentScope)
			if err != nil {
				t.Fatalf("SignPersonalMessage() error = %v", err)
			}

			parsed, err := models.FromSerializedSignature(signed.Signature)
			if err != nil {
				t.Fatalf("FromSerializedSignature() error = %v", err)
			}
			if got, want := len(parsed.PubKey), len(tt.keypair.PublicKeyBytes()); got != want {
				t.Fatalf("public key length = %d, want %d", got, want)
			}

			gotSigner, verified, err := models.VerifyPersonalMessage("compatibility test", signed.Signature)
			if err != nil {
				t.Fatalf("VerifyPersonalMessage() error = %v", err)
			}
			if !verified {
				t.Fatal("VerifyPersonalMessage() did not verify signature")
			}
			if gotSigner != tt.keypair.GetAddress() {
				t.Fatalf("signer = %s, want %s", gotSigner, tt.keypair.GetAddress())
			}
		})
	}
}

func TestSecp256r1SignaturesUseLowS(t *testing.T) {
	keypair, err := signer.NewSecp256r1SignerFromSecretKey(append(make([]byte, 31), 1))
	if err != nil {
		t.Fatalf("NewSecp256r1SignerFromSecretKey() error = %v", err)
	}

	for i := 0; i < 8; i++ {
		rawSignature, err := keypair.Sign([]byte("low-s test"))
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		assertLowSecp256r1S(t, rawSignature)

		signed, err := keypair.SignMessage(base64.StdEncoding.EncodeToString([]byte("low-s test")), constant.PersonalMessageIntentScope)
		if err != nil {
			t.Fatalf("SignMessage() error = %v", err)
		}
		parsed, err := models.FromSerializedSignature(signed.Signature)
		if err != nil {
			t.Fatalf("FromSerializedSignature() error = %v", err)
		}
		assertLowSecp256r1S(t, parsed.Signature)
	}
}

func TestVerifyPersonalMessageRejectsHighSSecpSignatures(t *testing.T) {
	tests := []struct {
		name    string
		keypair signer.Keypair
		order   *big.Int
	}{
		{"Secp256k1", signer.NewSecp256k1Signer(append(make([]byte, 31), 1)), secp256k1.Params().N},
		{"Secp256r1", signer.NewSecp256r1Signer(append(make([]byte, 31), 1)), elliptic.P256().Params().N},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const message = "reject high-s signature"
			signed, err := tt.keypair.SignMessage(base64.StdEncoding.EncodeToString([]byte(message)), constant.PersonalMessageIntentScope)
			if err != nil {
				t.Fatalf("SignMessage() error = %v", err)
			}

			_, verified, err := models.VerifyPersonalMessage(message, signed.Signature)
			if err != nil || !verified {
				t.Fatalf("VerifyPersonalMessage() valid signature = (%t, %v), want (true, nil)", verified, err)
			}

			highS := replaceSignatureS(t, signed.Signature, tt.order)
			_, verified, err = models.VerifyPersonalMessage(message, highS)
			if verified {
				t.Fatal("VerifyPersonalMessage() accepted a high-s signature")
			}
			if err == nil || !strings.Contains(err.Error(), "non-canonical high-s") {
				t.Fatalf("VerifyPersonalMessage() error = %v, want non-canonical high-s error", err)
			}
		})
	}
}

func replaceSignatureS(t *testing.T, serializedSignature string, curveOrder *big.Int) string {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(serializedSignature)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if len(payload) < 65 {
		t.Fatalf("serialized signature length = %d, want at least 65", len(payload))
	}

	s := new(big.Int).SetBytes(payload[33:65])
	highS := new(big.Int).Sub(curveOrder, s)
	if highS.Cmp(s) <= 0 {
		t.Fatal("original signature is not low-s")
	}
	copy(payload[65-len(highS.Bytes()):65], highS.Bytes())
	return base64.StdEncoding.EncodeToString(payload)
}

func assertLowSecp256r1S(t *testing.T, signature []byte) {
	t.Helper()
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
	s := new(big.Int).SetBytes(signature[32:])
	halfOrder := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		t.Fatal("signature has a high s value")
	}
}

func TestSignerFromSuiSecret(t *testing.T) {
	tests := []struct {
		name           string
		encoded        string
		expectedSig    string
		expectedPubkey string
	}{
		{"Ed25519", testEd25519Key, testEd25519Signature, testEd25519Pubkey},
		{"Secp256k1", testSecp256k1Key, testSecp256k1Signature, testSecp256k1Pubkey},
		// P-256 signing uses an entropy source, so its signature bytes are not a
		// stable fixture. Its serialization, verification, and low-s form are
		// tested independently.
		{"Secp256r1", testSecp256r1Key, "", testSecp256r1Pubkey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := signer.SignerFromSuiSecret(tt.encoded)
			assert.NoError(t, err)
			assert.NotNil(t, signer)

			pubKeyBytes := signer.PublicKeyBytes()
			pubKeyHex := hex.EncodeToString(pubKeyBytes)
			assert.NotEmpty(t, pubKeyHex)

			msg := []byte("test message")
			sig, err := signer.Sign(msg)

			if tt.expectedSig != "" {
				assert.Equal(t, tt.expectedSig, base64.StdEncoding.EncodeToString(sig))
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, sig)
			assert.NotEmpty(t, pubKeyBytes)
			assert.Equal(t, tt.expectedPubkey, pubKeyHex)
		})
	}
}
