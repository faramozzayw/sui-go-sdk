package signer

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestNormalizeSecp256r1S(t *testing.T) {
	curve := elliptic.P256()
	highS := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	if got := normalizeSecp256r1S(curve, highS); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("normalized high s = %s, want 1", got)
	}

	lowS := big.NewInt(1)
	if got := normalizeSecp256r1S(curve, lowS); got.Cmp(lowS) != 0 {
		t.Fatalf("normalized low s = %s, want %s", got, lowS)
	}
}
