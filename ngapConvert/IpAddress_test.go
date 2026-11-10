// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package ngapConvert_test

import (
	"bytes"
	"testing"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapConvert"
	"github.com/omec-project/ngap/v2/ngapType"
)

var (
	testIPv4Bytes = []byte{192, 0, 2, 1}
	testIPv6Bytes = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	testDualBytes = append(append([]byte{}, testIPv4Bytes...), testIPv6Bytes...)
)

const (
	testIPv4 = "192.0.2.1"
	testIPv6 = "2001:db8::1"

	testBadAddr = "not-an-ip"
)

func transportLayerAddress(b []byte, bitLength uint64) ngapType.TransportLayerAddress {
	return ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: b, BitLength: bitLength}}
}

func TestIPAddressToString(t *testing.T) {
	testCases := []struct {
		name     string
		addr     ngapType.TransportLayerAddress
		wantIPv4 string
		wantIPv6 string
	}{
		{name: "32-bit IPv4", addr: transportLayerAddress(testIPv4Bytes, 32), wantIPv4: testIPv4},
		{name: "128-bit IPv6", addr: transportLayerAddress(testIPv6Bytes, 128), wantIPv6: testIPv6},
		{name: "160-bit IPv4 and IPv6", addr: transportLayerAddress(testDualBytes, 160), wantIPv4: testIPv4, wantIPv6: testIPv6},
		{name: "zero value", addr: ngapType.TransportLayerAddress{}},
		{name: "unsupported bit length", addr: transportLayerAddress(testDualBytes[:8], 64)},
		{name: "32 bits with no bytes", addr: transportLayerAddress(nil, 32)},
		{name: "32 bits with 3 bytes", addr: transportLayerAddress(testIPv4Bytes[:3], 32)},
		{name: "32 bits with 16 bytes", addr: transportLayerAddress(testIPv6Bytes, 32)},
		{name: "128 bits with 4 bytes", addr: transportLayerAddress(testIPv4Bytes, 128)},
		{name: "128 bits with 20 bytes", addr: transportLayerAddress(testDualBytes, 128)},
		{name: "160 bits with no bytes", addr: transportLayerAddress(nil, 160)},
		{name: "160 bits with 4 bytes", addr: transportLayerAddress(testIPv4Bytes, 160)},
		{name: "160 bits with 16 bytes", addr: transportLayerAddress(testIPv6Bytes, 160)},
		{name: "160 bits with 21 bytes", addr: transportLayerAddress(append(append([]byte{}, testDualBytes...), 0), 160)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotIPv4, gotIPv6 := ngapConvert.IPAddressToString(tc.addr)
			if gotIPv4 != tc.wantIPv4 || gotIPv6 != tc.wantIPv6 {
				t.Errorf("IPAddressToString(%v) = (%q, %q), want (%q, %q)",
					tc.addr.Value, gotIPv4, gotIPv6, tc.wantIPv4, tc.wantIPv6)
			}
		})
	}
}

func TestIPAddressToNgap(t *testing.T) {
	testCases := []struct {
		name          string
		ipv4          string
		ipv6          string
		wantBytes     []byte
		wantBitLength uint64
	}{
		{name: "IPv4 only", ipv4: testIPv4, wantBytes: testIPv4Bytes, wantBitLength: 32},
		{name: "IPv6 only", ipv6: testIPv6, wantBytes: testIPv6Bytes, wantBitLength: 128},
		{name: "IPv4 and IPv6", ipv4: testIPv4, ipv6: testIPv6, wantBytes: testDualBytes, wantBitLength: 160},
		{name: "IPv4-mapped IPv6 in the IPv4 argument", ipv4: "::ffff:" + testIPv4, wantBytes: testIPv4Bytes, wantBitLength: 32},
		{
			// Unchanged from earlier releases: To16() accepts an IPv4 string
			// and the result is the IPv4-mapped IPv6 address.
			name:          "IPv4 in the IPv6 argument",
			ipv6:          testIPv4,
			wantBytes:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1},
			wantBitLength: 128,
		},
		{name: "both empty"},
		{name: "unparsable IPv4", ipv4: testBadAddr},
		{name: "IPv6 in the IPv4 argument", ipv4: testIPv6},
		{name: "IPv4 with port", ipv4: testIPv4 + ":38412"},
		{name: "unparsable IPv6", ipv6: "2001:db8::zz"},
		{name: "IPv6 with zone", ipv6: "fe80::1%eth0"},
		{name: "valid IPv4 and unparsable IPv6", ipv4: testIPv4, ipv6: testBadAddr},
		{name: "unparsable IPv4 and valid IPv6", ipv4: testBadAddr, ipv6: testIPv6},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ngapConvert.IPAddressToNgap(tc.ipv4, tc.ipv6)
			if got.Value.BitLength != tc.wantBitLength || !bytes.Equal(got.Value.Bytes, tc.wantBytes) {
				t.Errorf("IPAddressToNgap(%q, %q) = %v, want {%v %d}",
					tc.ipv4, tc.ipv6, got.Value, tc.wantBytes, tc.wantBitLength)
			}
		})
	}
}

// TestIPAddressAperRoundTrip encodes each address form with the NGAP APER
// constraints of TransportLayerAddress, decodes it again as the AMF does for
// a received message, and converts it back to strings.
func TestIPAddressAperRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{name: "IPv4 round trip", ipv4: testIPv4},
		{name: "IPv6 round trip", ipv6: testIPv6},
		{name: "dual round trip", ipv4: testIPv4, ipv6: testIPv6},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := aper.MarshalWithParams(ngapConvert.IPAddressToNgap(tc.ipv4, tc.ipv6), "")
			if err != nil {
				t.Fatalf("aper.MarshalWithParams: %v", err)
			}
			var decoded ngapType.TransportLayerAddress
			if err = aper.UnmarshalWithParams(encoded, &decoded, ""); err != nil {
				t.Fatalf("aper.UnmarshalWithParams: %v", err)
			}
			gotIPv4, gotIPv6 := ngapConvert.IPAddressToString(decoded)
			if gotIPv4 != tc.ipv4 || gotIPv6 != tc.ipv6 {
				t.Errorf("round trip of (%q, %q) = (%q, %q)", tc.ipv4, tc.ipv6, gotIPv4, gotIPv6)
			}
		})
	}
}
