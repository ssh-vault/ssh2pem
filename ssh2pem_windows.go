// +build windows

package ssh2pem

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
)

func readLength(data []byte) ([]byte, uint32, error) {
	l_buf := data[0:4]

	buf := bytes.NewBuffer(l_buf)

	var length uint32

	err := binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}

	return data[4:], length, nil
}

func readBigInt(data []byte, length uint32) ([]byte, *big.Int, error) {
	var bigint = new(big.Int)
	bigint.SetBytes(data[0:length])
	return data[length:], bigint, nil
}

func getRsaValues(data []byte) (format string, e, n *big.Int, err error) {
	data, length, err := readLength(data)
	if err != nil {
		return
	}

	format = string(data[0:length])
	data = data[length:]

	data, length, err = readLength(data)
	if err != nil {
		return
	}

	data, e, err = readBigInt(data, length)
	if err != nil {
		return
	}

	data, length, err = readLength(data)
	if err != nil {
		return
	}

	data, n, err = readBigInt(data, length)
	if err != nil {
		return
	}

	return
}

// DecodePublicKey return *rsa.PublicKey interface
func DecodePublicKey(str string) (interface{}, error) {
	tokens := strings.Split(str, " ")

	if len(tokens) < 2 {
		return nil, fmt.Errorf("Invalid key format")
	}

	key_type := tokens[0]
	data, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return nil, err
	}

	format, e, n, err := getRsaValues(data)
	if format != key_type {
		return nil, fmt.Errorf("Key type mismatch %s != %s", key_type, format)
	}

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return pubKey, nil
}

// GetPem return ssh-rsa public key in PEM PKCS8
func GetPem(key string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}

	pubKey, err := DecodePublicKey(string(bytes))
	if err != nil {
		return nil, err
	}

	pkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkix,
	}), nil
}
