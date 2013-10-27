// mischief@offblast.org 2013

// generate .onion addresses
//
// TODO: generate the right addresses, use more than one goroutine
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
)

type Result struct {
	Addr       string
	PrivateKey bytes.Buffer
}

const (
	onionencoding = "abcdefghijklmnopqrstuvwxyz234567"
)

var (
	pattern = flag.String("pattern", "", "onion address pattern")

	onionpattern *regexp.Regexp

	wg sync.WaitGroup
)

func gen(stop chan bool, out chan Result) {
	defer wg.Done()

generate:
	for {
		select {
		case <-stop:
			break generate
		default:
			rsakey, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				log.Printf("rsa.GenerateKey: %s", err)
				break generate
			}

			derbytes, err := x509.MarshalPKIXPublicKey(&rsakey.PublicKey)
			if err != nil {
				log.Printf("x509.MarshalPKIXPublicKey: %s", err)
				break generate
			}

			hash := sha1.New()
			hash.Write(derbytes)
			sum := hash.Sum(nil)
			sum = sum[:10]

			var buf32 bytes.Buffer

			b32enc := base32.NewEncoder(base32.NewEncoding(onionencoding), &buf32)
			b32enc.Write(sum)
			b32enc.Close()

			// only need 16 chars
			buf32.Truncate(16)
			onion := buf32.String()

			if onionpattern.MatchString(onion) {
				var res Result

				res.Addr = onion + ".onion"

				pem.Encode(&res.PrivateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsakey)})

				out <- res

				break generate
			}

			//time.Sleep(100 * time.Millisecond)
			//break generate
		}
	}

	close(out)
}

func main() {
	flag.Parse()

	if *pattern == "" {
		log.Fatal("no pattern set")
	}

	// make sure case insensitive.
	onionpattern = regexp.MustCompile("(?i)" + *pattern)

	sigch := make(chan os.Signal, 1)

	signal.Notify(sigch, os.Interrupt, os.Kill)

	stop := make(chan bool, 1)
	out := make(chan Result, 1)

	go gen(stop, out)
	wg.Add(1)

	for {
		select {
		case s := <-sigch:
			log.Print("got signal", s)
			stop <- true
			goto done
		case res := <-out:
			if res.Addr == "" {
				goto done
			}

			log.Printf("found match: %s", res.Addr)
			fmt.Printf("%s", res.PrivateKey.String())
		}
	}

done:
	wg.Wait()
}
