// Copyright 2019 Communication Service/Software Laboratory, National Chiao Tung University (free5gc.org)
//
// SPDX-License-Identifier: Apache-2.0

package ngapConvert

import (
	"net"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/logger"
	"github.com/omec-project/ngap/v2/ngapType"
)

// IPAddressToString decodes a TransportLayerAddress into its IPv4 and/or IPv6
// text form. As described in TS 38.414 clause 5.1, the address is 32 bits
// (IPv4), 128 bits (IPv6) or 160 bits (IPv4 in the first 32 bits followed by
// IPv6). Any other bit length, or a byte slice whose length does not match the
// bit length, is malformed and yields two empty strings.
func IPAddressToString(ipAddr ngapType.TransportLayerAddress) (ipv4Addr, ipv6Addr string) {
	ip := ipAddr.Value

	switch ip.BitLength {
	case 32: // ipv4
		if !hasByteLength(ip, net.IPv4len) {
			return "", ""
		}
		ipv4Addr = net.IP(ip.Bytes).String()
	case 128: // ipv6
		if !hasByteLength(ip, net.IPv6len) {
			return "", ""
		}
		ipv6Addr = net.IP(ip.Bytes).String()
	case 160: // ipv4 + ipv6, and ipv4 is contained in the first 32 bits
		if !hasByteLength(ip, net.IPv4len+net.IPv6len) {
			return "", ""
		}
		ipv4Addr = net.IP(ip.Bytes[:net.IPv4len]).String()
		ipv6Addr = net.IP(ip.Bytes[net.IPv4len:]).String()
	default:
		logger.NgapLog.Warnf("IPAddressToString: unsupported TransportLayerAddress bit length %d", ip.BitLength)
	}
	return ipv4Addr, ipv6Addr
}

func hasByteLength(ip aper.BitString, want int) bool {
	if len(ip.Bytes) != want {
		logger.NgapLog.Warnf("IPAddressToString: TransportLayerAddress of %d bits carries %d bytes, want %d",
			ip.BitLength, len(ip.Bytes), want)
		return false
	}
	return true
}

// IPAddressToNgap encodes an IPv4 and/or IPv6 address as a TransportLayerAddress
// (TS 38.414 clause 5.1): 32 bits for IPv4 only, 128 bits for IPv6 only and
// 160 bits when both are given. If either non-empty string is not a valid
// address of its family, or both are empty, the zero TransportLayerAddress is
// returned and a warning is logged.
func IPAddressToNgap(ipv4Addr, ipv6Addr string) ngapType.TransportLayerAddress {
	var ipBytes []byte

	if ipv4Addr != "" {
		ipv4NetIP := net.ParseIP(ipv4Addr).To4()
		if ipv4NetIP == nil {
			logger.NgapLog.Warnf("IPAddressToNgap: invalid IPv4 address %q", ipv4Addr)
			return ngapType.TransportLayerAddress{}
		}
		ipBytes = append(ipBytes, ipv4NetIP...)
	}

	if ipv6Addr != "" {
		ipv6NetIP := net.ParseIP(ipv6Addr).To16()
		if ipv6NetIP == nil {
			logger.NgapLog.Warnf("IPAddressToNgap: invalid IPv6 address %q", ipv6Addr)
			return ngapType.TransportLayerAddress{}
		}
		ipBytes = append(ipBytes, ipv6NetIP...)
	}

	if len(ipBytes) == 0 {
		logger.NgapLog.Warnln("IPAddressToNgap: Both ipv4 and ipv6 are empty string")
		return ngapType.TransportLayerAddress{}
	}

	return ngapType.TransportLayerAddress{
		Value: aper.BitString{
			Bytes:     ipBytes,
			BitLength: uint64(len(ipBytes) * 8),
		},
	}
}
