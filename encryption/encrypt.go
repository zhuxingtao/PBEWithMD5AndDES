package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
)

func getDerivedKey(password string, salt []byte, count int) ([]byte, []byte) {
	key := md5.Sum([]byte(password + string(salt)))
	for i := 0; i < count-1; i++ {
		key = md5.Sum(key[:])
	}
	return key[:8], key[8:]
}

func pKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

func DesEncrypt(origData, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = pKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func DesDecrypt(crypted, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func Decrypt(msg, password string) (string, error) {
	msgBytes, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	salt := msgBytes[:8]
	encText := msgBytes[8:]

	dk, iv := getDerivedKey(password, salt, 1000)

	text, err := DesDecrypt(encText, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}

func Encrypt(msg, password string) (string, error) {
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	padNum := 8 - (len(msg) % 8)
	for i := 0; i <= padNum; i++ {
		msg += string(rune(padNum))
	}
	dk, iv := getDerivedKey(password, salt, 1000)
	encText, err := DesEncrypt([]byte(msg), dk, iv)
	if err != nil {
		return "", err
	}
	r := append(salt, encText...)
	encodeString := base64.StdEncoding.EncodeToString(r)
	return encodeString, nil
}

func main() {

	eMsg, err := Encrypt("adfs", "abcd")
	dMsg, err := Decrypt(eMsg, "abcd")

	fmt.Printf("%v\n%v\n%v ", eMsg, dMsg, err)
}
