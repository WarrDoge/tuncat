package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func obscure(plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(obscureKey))
	if err != nil {
		return "", err
	}
	plain := []byte(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plain)
	return obscurePrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func reveal(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, obscurePrefix) {
		return encoded, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, obscurePrefix))
	if err != nil {
		return "", fmt.Errorf("decode obscured password: %w", err)
	}
	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("obscured password too short")
	}
	block, err := aes.NewCipher([]byte(obscureKey))
	if err != nil {
		return "", err
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	plain := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plain, ciphertext)
	return string(plain), nil
}

func readPassword(prompt string) (string, error) {
	if term.IsTerminal(syscall.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(syscall.Stdin)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	var line string
	_, err := fmt.Scanln(&line)
	return line, err
}

func RunObscure() error {
	pw, err := readPassword("Enter password to obscure: ")
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	result, err := obscure(pw)
	if err != nil {
		return fmt.Errorf("obscuring password: %w", err)
	}
	fmt.Println(result)
	return nil
}
