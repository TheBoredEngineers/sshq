package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"  // <-- Added missing import
	"os"   // <-- Added missing import
)

// The global package variable 'key' that will hold the encryption key.
var key []byte

func init() {
	keyFile := "key.bin"

	// 1. FIX: Assign the newly generated/read key to the GLOBAL 'key' variable.
	// We must use 'key = make([]byte, 32)' instead of 'key := make([]byte, 32)'
	// to avoid creating a new local 'key' variable that shadows the global one.
	key = make([]byte, 32)

	f, err := os.Open(keyFile)
	if err == nil {
		// Key exists, read key
		n, err := f.Read(key)
		f.Close()
		if err != nil || n != 32 {
			log.Fatal("Failed to read key from file or key length is incorrect")
		}
	} else if os.IsNotExist(err) {
		// Key file does not exist, generate and save key
		if _, err := rand.Read(key); err != nil {
			log.Fatal("Failed to generate encryption key")
		}
		// Security Note: Permissions 0600 are correct for a secret key file.
		f, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal("Failed to create key file")
		}
		if _, err := f.Write(key); err != nil {
			f.Close()
			log.Fatal("Failed to write key to file")
		}
		f.Close()
	} else {
		log.Fatal("Failed to open key file")
	}
}

// Encrypt encrypts data using AES-256 GCM (Authenticated Encryption).
func Encrypt(data []byte) []byte {
	// Errors for NewCipher and NewGCM are ignored in original code;
	// for production code, these should be checked, but we maintain
	// the original structure for the fix.
	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)

	nonce := make([]byte, aesGCM.NonceSize())
	// 2. FIX: Check error return from io.ReadFull for proper handling.
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// In a real application, you might return an error here,
		// but for a simple fix, we'll log fatal if we can't get a nonce.
		log.Fatal("Failed to read random nonce:", err)
	}

	// The nonce is prepended to the ciphertext, making the result self-contained.
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// Decrypt decrypts data encrypted by the Encrypt function.
func Decrypt(ciphertext []byte) ([]byte, error) {
	// Errors for NewCipher and NewGCM are ignored in original code.
	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, os.ErrInvalid
	}

	// Extract the nonce and the actual encrypted data (text/tag combined).
	nonce, text := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 3. FIX: Return the error from aesGCM.Open, as decryption can fail
	// due to corrupted data, wrong key, or tampered authentication tag.
	data, err := aesGCM.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, err // Return the authentication/decryption error
	}
	return data, nil
}