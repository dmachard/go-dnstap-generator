package main

import (
	"testing"
)

func GetIntPointer(value int) *int {
	return &value
}

func TestRandomString(t *testing.T) {
	randstr := RandomString(5, 10)
	if len(randstr) < 5 && len(randstr) > 10 {
		t.Errorf("random string failed, bad length")
	}
}
func TestGenerateDns(t *testing.T) {
	_, _, err := GenerateDnsQuestion(GetIntPointer(5), GetIntPointer(10), "", "")
	if err != nil {
		t.Errorf("generate dns packet failed: %s", err)
	}
}

func TestGenerateDnstap(t *testing.T) {
	qr, rp, _ := GenerateDnsQuestion(GetIntPointer(5), GetIntPointer(15), "", "")
	dtqr, dtrp := GenerateDnstap(qr, rp)

	if string(dtqr.GetIdentity()) != "dnstap-generator" {
		t.Errorf("dnstap identity is invalid: %s", string(dtqr.GetIdentity()))
	}
	if string(dtrp.GetIdentity()) != "dnstap-generator" {
		t.Errorf("dnstap identity is invalid: %s", string(dtrp.GetIdentity()))
	}
}

func BenchmarkGenerateDns(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateDnsQuestion(GetIntPointer(5), GetIntPointer(25), "", "")
		if err != nil {
			break
		}
	}
}
