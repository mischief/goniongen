package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/base32"
)

var onionencoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

// creates an onion address given an rsa public key component
func address(pub *rsa.PublicKey) string {
	derbytes, _ := asn1.Marshal(*pub)

	// 1. Let H = H(PK).
	hash := sha1.New()
	hash.Write(derbytes)
	sum := hash.Sum(nil)

	// 2. Let H' = the first 80 bits of H, considering each octet from
	//    most significant bit to least significant bit.
	sum = sum[:10]

	// 3. Generate a 16-character encoding of H', using base32 as defined
	//    in RFC 4648.
	var buf32 bytes.Buffer
	b32enc := base32.NewEncoder(onionencoding, &buf32)
	b32enc.Write(sum)
	b32enc.Close()

	return buf32.String()
}
