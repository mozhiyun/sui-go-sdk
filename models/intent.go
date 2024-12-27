package models

import (
	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/fardream/go-bcs/bcs"
)

type AppId int

const (
	Sui AppId = 0
)

type IntentVersion int

const (
	V0 IntentVersion = 0
)

func IntentWithScope(intentScope constant.IntentScope) []int {
	return []int{int(intentScope), int(V0), int(Sui)}
}

func NewMessageWithIntent(message []byte, scope constant.IntentScope) []byte {
	intent := []byte{scope, 0, 0}
	messageBCS := bcs.MustMarshal(message)
	intentMessage := make([]byte, len(intent)+len(messageBCS))
	copy(intentMessage, intent)
	copy(intentMessage[len(intent):], messageBCS)
	return intentMessage
}
