// mischief@offblast.org 2013

// generate .onion addresses
//
// TODO: generate the right addresses, use more than one goroutine
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sync"
)

type Result struct {
	Addr       string
	PrivateKey bytes.Buffer
}

var (
	pattern      = flag.String("pattern", "", "onion address pattern")
	onionpattern *regexp.Regexp
	wg           sync.WaitGroup
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

			onionaddr := address(&rsakey.PublicKey)
			if onionaddr == "" {
				log.Printf("address empty")
				break generate
			}

			if onionpattern.MatchString(onionaddr) {
				res := Result{Addr: onionaddr + ".onion"}
				pem.Encode(&res.PrivateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsakey)})
				out <- res
				break generate
			}

			out <- Result{}
		}
	}
}

func main() {
	var err error

	flag.Parse()

	if *pattern == "" {
		log.Fatal("no pattern set")
	}

	rpat := "^(?i)" + *pattern

	// make sure case insensitive.
	onionpattern, err = regexp.Compile(rpat)

	if err != nil {
		log.Fatalf("bad pattern: %s", err)
	}

	ncpu := runtime.NumCPU()

	log.Printf("searching for %q using %d cpus...", rpat, ncpu)

	sigch := make(chan os.Signal, 1)
	stop := make(chan bool, 1)
	out := make(chan Result, ncpu*10)

	runtime.GOMAXPROCS(ncpu)
	signal.Notify(sigch, os.Interrupt, os.Kill)

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go gen(stop, out)
	}

	var stat uint64

	for {
		select {
		case s := <-sigch:
			log.Printf("got signal %s", s)
			close(stop)
			goto done
		case res := <-out:
			stat++
			if stat%25 == 0 {
				log.Printf("%d checked...", stat)
			}

			if res.Addr == "" {
				break
			}

			log.Printf("found match after %d tries: %s", stat, res.Addr)
			fmt.Printf("%s", res.PrivateKey.String())

			close(stop)
			goto done
		}
	}

done:
	wg.Wait()

	close(out)
}
