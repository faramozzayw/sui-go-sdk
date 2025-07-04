package signer

import (
	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
)

type Keypair interface {
	SignMessage(data string, scope constant.IntentScope) (*SignedMessageSerializedSig, error)
	SignTransaction(b64TxBytes string) (*models.SignedTransactionSerializedSig, error)
	SignPersonalMessage(message string) (*SignedMessageSerializedSig, error)

	// SignPersonalMessageV1 is the same as SignPersonalMessage, but it uses the new message format for personal messages.
	SignPersonalMessageV1(message string) (*SignedMessageSerializedSig, error)

	// SignMessageV1 is the same as SignMessage, but it uses the new message format for personal messages.
	SignMessageV1(data string, scope constant.IntentScope) (*SignedMessageSerializedSig, error)

	Schema() byte
	Address() string
}
