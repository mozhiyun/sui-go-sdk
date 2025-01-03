package zklogin

type ProofPoints struct {
	A []string
	B [][]string
	C []string
}

type IssBase64Details struct {
	Value     string
	IndexMod4 uint8
}

type ZkLoginSignatureInputs struct {
	ProofPoints      ProofPoints
	IssBase64Details IssBase64Details
	HeaderBase64     string
	AddressSeed      string
}

type ZkLoginSignature struct {
	Inputs        ZkLoginSignatureInputs
	MaxEpoch      uint64
	UserSignature []byte
	Iss           string
	AddressSeed   string
}

type ZkLoginSignatureInner struct {
	Inputs        ZkLoginSignatureInputs
	MaxEpoch      uint64
	UserSignature []byte
}
