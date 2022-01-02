package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

const (
	colorGreen = "\u001b[32m"
	colorReset = "\u001b[0m"
)

var (
	alphabet   = regexp.MustCompile("^[0-9a-f]*$")
	numWorkers = runtime.NumCPU()
)

func main() {
	var one bool
	var prefix, suffix string
	flag.BoolVar(&one, "one", false, "Stop after finding first address")
	flag.StringVar(&prefix, "p", "", "Public address prefix")
	flag.StringVar(&suffix, "s", "", "Public address suffix")
	flag.Parse()
	if prefix == "" && suffix == "" {
		fmt.Printf(`
This tool generates Ethereum public and private keypair until it finds address
which contains required prefix and/or suffix.
Address part can contain only digits and letters from A to F.
For fast results suggested length of sum of preffix and suffix is 4-6 characters.
If you want more, be patient.

Usage:

`)
		flag.PrintDefaults()
		os.Exit(1)
	}
	if !alphabet.MatchString(prefix) {
		fmt.Println("Prefix must match the alphabet:", alphabet.String())
		os.Exit(2)
	}
	if !alphabet.MatchString(suffix) {
		fmt.Println("Suffix must match the alphabet:", alphabet.String())
		os.Exit(3)
	}
	
	fmt.Println("Starting search...")
	
	keyChan := make(chan *keystore.Key)
	for i := 0; i < numWorkers; i++ {
		go generateKey(prefix, suffix, keyChan)
	}
	for k := range keyChan {
		addressHex := k.Address.Hex()[2:]
		fmt.Printf(
			"Address: 0x%s%s%s%s%s%s%s\n",
			colorGreen,
			addressHex[:len(prefix)],
			colorReset,
			addressHex[len(prefix):len(addressHex)-len(suffix)],
			colorGreen,
			addressHex[len(addressHex)-len(suffix):],
			colorReset)

		fmt.Print("Save? [y/N]: ")
		resp := ""
		fmt.Scanln(&resp)

		if strings.Contains(resp, "y") {
			target := ""
			fmt.Print("Target file: ")
			fmt.Scanln(&target)

			for {
				fmt.Print("Password: ")
				pw1, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					log.Fatal(err)
				}

				fmt.Print("\nPassword again: ")
				pw2, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Print("\n")
				if err != nil {
					log.Fatal(err)
				}

				if bytes.Compare(pw1, pw2) != 0 {
					fmt.Println("Not equal, again...")
					continue
				}

				keybytes, err := keystore.EncryptKey(k, string(pw1), keystore.StandardScryptN, keystore.StandardScryptP)
				if err != nil {
					log.Fatal(err)
				}

				err = ioutil.WriteFile(target, keybytes, 0700)
				if err != nil {
					log.Fatal(err)
				}
				
				break
			}
			
			fmt.Println("Key saved to " + target)

			break
		}

	}
}

func generateKey(prefix, suffix string, keyChan chan *keystore.Key) {
	for {
		privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		addressHex := hex.EncodeToString(address[:])
		if prefix != "" && !strings.HasPrefix(addressHex, prefix) {
			continue
		}
		if suffix != "" && !strings.HasSuffix(addressHex, suffix) {
			continue
		}

		id, err := uuid.NewRandom()
		if err != nil {
			log.Fatal(err)
		}

		keyChan <- &keystore.Key{
			Id:         id,
			Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
			PrivateKey: privateKey,
		}
	}
}
