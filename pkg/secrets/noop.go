package secrets

func NewNoopDecrypter(params map[string]string, isFile bool) Decrypter {
	return &NoopDecrypter{
		value:  params["v"],
		isFile: isFile,
	}
}

type NoopDecrypter struct {
	value  string
	isFile bool
}

func (n *NoopDecrypter) Decrypt() (string, error) {
	return n.value, nil
}

func (n *NoopDecrypter) IsFile() bool {
	return n.isFile
}
