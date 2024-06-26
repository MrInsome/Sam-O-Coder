package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
)

// Encryptor struct
type Encryptor struct {
	Password string
}

// DeriveKey derives a key using PBKDF2
func (e *Encryptor) DeriveKey(salt []byte) []byte {
	key := pbkdf2Key([]byte(e.Password), salt, 100000, 32)
	return key
}

// Encrypt encrypts plaintext using AES-CFB
func (e *Encryptor) Encrypt(plaintext string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	key := e.DeriveKey(salt)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	encryptedData := make([]byte, 0)
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, iv...)
	encryptedData = append(encryptedData, ciphertext[aes.BlockSize:]...)

	return salt, encryptedData, nil
}

// SaveToFile saves encrypted data to a file
func SaveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// Decryptor struct
type Decryptor struct {
	Password string
}

// Decrypt decrypts encrypted data
func (d *Decryptor) Decrypt(encryptedData []byte) (string, error) {
	salt := encryptedData[:16]
	iv := encryptedData[16:32]
	ciphertext := encryptedData[32:]

	key := pbkdf2Key([]byte(d.Password), salt, 100000, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

func pbkdf2Key(password, salt []byte, iterations, keylen int) []byte {
	return pbkdf2([]byte(password), []byte(salt), iterations, keylen, sha256.New)
}

func pbkdf2(password, salt []byte, iterations, keylen int, hash func() hash.Hash) []byte {
	key := pbkdf2HMAC(hash, password, salt, iterations, keylen)
	return key
}

func pbkdf2HMAC(hash func() hash.Hash, password, salt []byte, iterations, keylen int) []byte {
	hmac := hmac(hash, password)
	hashSize := hmac.Size()
	numBlocks := (keylen + hashSize - 1) / hashSize
	var buf []byte
	for block := 1; block <= numBlocks; block++ {
		ib := make([]byte, 4)
		ib[0] = byte(block >> 24)
		ib[1] = byte(block >> 16)
		ib[2] = byte(block >> 8)
		ib[3] = byte(block)
		u := hmac(salt, ib)
		f := u
		for n := 1; n < iterations; n++ {
			u = hmac(salt, u)
			for x := range u {
				f[x] ^= u[x]
			}
		}
		buf = append(buf, f...)
	}
	return buf[:keylen]
}

func hmac(hash func() hash.Hash, password []byte) []byte {
	hm := hash()
	hm.Write(password)
	return hm.Sum(nil)
}

func main() {
	var plaintext string
	fmt.Print("Enter the message to encrypt: ")
	fmt.Scanln(&plaintext)

	var password string
	fmt.Print("Enter the password for encryption: ")
	fmt.Scanln(&password)

	encryptor := Encryptor{Password: password}
	salt, encryptedData, err := encryptor.Encrypt(plaintext)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	fmt.Println("Password:", password)
	fmt.Println("Salt:", hex.EncodeToString(salt))
	fmt.Println("Encrypted:", hex.EncodeToString(encryptedData))

	filename := "encrypted_data.bin"
	err = SaveToFile(filename, encryptedData)
	if err != nil {
		fmt.Println("Failed to save encrypted data to file:", err)
		return
	}
	fmt.Println("Encrypted data saved to", filename)

	var decryptPassword string
	fmt.Print("Enter the password for decryption: ")
	fmt.Scanln(&decryptPassword)

	encryptedDataFromFile, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read encrypted data from file:", err)
		return
	}

	decryptor := Decryptor{Password: decryptPassword}
	decrypted, err := decryptor.Decrypt(encryptedDataFromFile)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Println("Decrypted:", decrypted)
}
