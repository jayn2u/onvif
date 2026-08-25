package wsdiscovery

import "testing"

func TestSelectInterface_InvalidCIDR(t *testing.T) {
	if _, err := SelectInterface("not-a-cidr"); err == nil {
		t.Fatal("expected an error for an invalid CIDR, got nil")
	}
}

func TestSelectInterface_NoMatchingInterface(t *testing.T) {
	// TEST-NET-3 (RFC 5737): reserved for documentation, no local interface
	// should ever be assigned an address in this range.
	if _, err := SelectInterface("203.0.113.0/24"); err == nil {
		t.Fatal("expected an error when no interface matches the camera subnet, got nil")
	}
}
