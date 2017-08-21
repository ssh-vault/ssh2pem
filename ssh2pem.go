package ssh2pem

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
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
	f, err := os.Open(key)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var b bytes.Buffer

	// remove empty lines from file
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) > 0 {
			b.WriteString(fmt.Sprintf("%s\n", scanner.Text()))
		}
	}

	// check if ssh key is the private key
	// TODO find a way of doing this not depending on ssh-keygen
	block, r := pem.Decode(b.Bytes())
	fmt.Printf("len(r) = %+v\n", len(r))
	if len(r) == 0 {
		if block.Type == "RSA PRIVATE KEY" {
			tmpKey, err := ioutil.TempFile("", "trimCR")
			if err != nil {
				return nil, err
			}
			defer os.Remove(tmpKey.Name())
			if _, err := tmpKey.Write(b.Bytes()); err != nil {
				return nil, err
			}
			if err := tmpKey.Close(); err != nil {
				return nil, err
			}
			out, err := exec.Command("ssh-keygen",
				"-yf",
				tmpKey.Name(),
				"-e",
				"-m",
				"PKCS8").Output()
			if err != nil {
				return out, fmt.Errorf("Verify private key permissions, try chmod 0400 %s, %s", key, err)
			}
			return out, err
		}
	}

	pubKey, err := GetPublicKeyPem(b.String())
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// GetPublicKeyPem return the public key in PEM PKCS8
func GetPublicKeyPem(key string) ([]byte, error) {
	pubKey, err := DecodePublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("Use a public ssh key: %s", err)
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
