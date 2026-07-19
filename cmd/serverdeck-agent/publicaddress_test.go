package main

import "testing"

func TestDetectPublicAddressRejectsUnknownNetwork(t *testing.T) {
	if _, err := detectPublicAddressForNetwork("tcp"); err == nil {
		t.Fatal("expected an unsupported address-family error")
	}
}
