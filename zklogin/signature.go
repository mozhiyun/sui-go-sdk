package zklogin

import (
	"fmt"
	"github.com/fardream/go-bcs/bcs"

	"github.com/block-vision/sui-go-sdk/mystenbcs"
)

func parseZkLoginSignature(signature interface{}) (*ZkLoginSignature, error) {
	var bytes []byte
	var err error

	// Check if the input is a base64 string or a byte array
	switch sig := signature.(type) {
	case string:
		bytes, err = mystenbcs.FromBase64(sig)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64: %v", err)
		}
	case []byte:
		bytes = sig
	default:
		return nil, fmt.Errorf("unsupported input type")
	}

	// Deserialize the bytes into ZkLoginSignature struct using BCS
	var zkSigInner ZkLoginSignatureInner
	numBytes, err := bcs.Unmarshal(bytes, &zkSigInner)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BCS data: %v", err)
	}
	fmt.Println("Number of bytes read:", numBytes)
	return &ZkLoginSignature{
		Inputs:        zkSigInner.Inputs,
		MaxEpoch:      zkSigInner.MaxEpoch,
		UserSignature: zkSigInner.UserSignature,
	}, nil
}
