package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/block-vision/sui-go-sdk/models"

	"github.com/machinebox/graphql"
	"golang.org/x/crypto/blake2b"

	"github.com/block-vision/sui-go-sdk/constant"
)

type Ed25519PublicKey struct {
	signature []byte
}

func NewEd25519PublicKey(signature []byte) *Ed25519PublicKey {
	return &Ed25519PublicKey{
		signature: signature,
	}
}

func (e *Ed25519PublicKey) ToSuiAddress() string {
	return ""
}

func (e *Ed25519PublicKey) VerifyPersonalMessage(message []byte, signature []byte, client *graphql.Client) (bool, error) {
	b64Message := base64.StdEncoding.EncodeToString(message)
	return VerifyMessage(b64Message, base64.StdEncoding.EncodeToString(signature), constant.PersonalMessageIntentScope)
}

func VerifyMessage(message, signature string, scope constant.IntentScope) (pass bool, err error) {
	b64Bytes, _ := base64.StdEncoding.DecodeString(message)
	messageBytes := models.NewMessageWithIntent(b64Bytes, scope)

	serializedSignature, err := models.FromSerializedSignature(signature)
	if err != nil {
		return false, err
	}
	digest := blake2b.Sum256(messageBytes)

	pass = ed25519.Verify(serializedSignature.PubKey[:], digest[:], serializedSignature.Signature)

	return
}

func Ed25519PublicKeyToSuiAddress(pubKey []byte) string {
	newPubkey := []byte{byte(models.SigFlagEd25519)}
	newPubkey = append(newPubkey, pubKey...)

	addrBytes := blake2b.Sum256(newPubkey)
	return fmt.Sprintf("0x%s", hex.EncodeToString(addrBytes[:])[:64])
}
