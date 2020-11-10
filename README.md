# PBEWithMD5AndDES
golang implementation of PBEWithMD5AndDES by Jasypt Java Package: org.jasypt.encryption.pbe.StandardPBEStringEncryptor


### EXAMPLE
```
package main
import (
    "github.com/zhuxingtao/PBEWithMD5AndDES/encryption"
    "fmt"
)
func main() {

	eMsg, err := encryption.Encrypt("msg", "password")
	dMsg, err := encryption.Decrypt(eMsg, "password")

	fmt.Printf("%v\n%v\n%v ", eMsg, dMsg, err)
}

```