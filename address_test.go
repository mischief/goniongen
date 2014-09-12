package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

var (
	taddr = "egsluwnygzik5pim"
	tpriv = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDLCUoxCXuPTkrXsLlp2iSaMXCEUE4Q3ddIqM3vqptJJDGtQUNq
sZ6Y6QtkIp/SNk3PFJpWOIEyYRvxVvbVCS5nH/ewc+cA8HWz5GUTZVLlK6nVzVEn
5qWWUHtBGMCf4r3puY/KvbiO/6WMvXiAJ3NitkJuvBk/okfogOKiIj7c7wIDAQAB
AoGBAIFpTmyrCqJw2KtZ7RRXAnV1ha4QMXH2tD2PupNEPu4Dr9YqfvoGdHwqLiSJ
HS0zh6yyCR1jrpWZ5+GP+IwY6gWWZj/eeTqC/SyweP7YTCkgkrWebTQUurTi5FyZ
CSH5vSkapKajU3KPRvdqW0AI+Xhs0pGsBkvKa8o2Yyg1lsOBAkEA4OzZIcz5Zf+H
To09ISgmS3TmCE3CrHkg6rU4Zjnltfeq9xChonxqaHLwrqYdEwFNSk/wParWax6Q
Ga7msYO6nwJBAOcWRnZ/j36MuqJPeDj4XEznKiewf4TZz9gyiUPPcSFIWSNXRLWW
RPtBLc9php+zWyAhqxfwNsLemSGfdJcaC7ECQQDaRv+wvaqKQaCdqpNYSg5fy+Iw
zMXPev1myNci3az/GorfmVRCy1q4YlMQKkSs3OaU517Neaz7530Qb5uRSbUhAkEA
3u5mW7sDu5oYEq2H1a4DnU0FJfTnkEpwcKmQMpLVGL6q/6UY6/Vj5uAiSY4MCdUF
fCH+5MEgky4bnIwv9fVygQJBALYqF32XTdDBxVj/Mt2yQG7qT6wThjHXMUptK9DS
5TVLMw/rFJuVi5l8miydQRPTyXCnOkQHlWCFUJu10V2MIRc=
-----END RSA PRIVATE KEY-----`)
)

func TestAddress(t *testing.T) {
	block, _ := pem.Decode(tpriv)
	if block == nil {
		t.Fatalf("bad key data")
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		t.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("bad private key: %s", err)
	}

	onionaddr := address(&pkey.PublicKey)

	if onionaddr != taddr {
		t.Fatalf("address: got %s want %s", onionaddr, taddr)
	}
}
