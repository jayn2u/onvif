package wsdiscovery

import (
	"fmt"
	"net"
)

// SelectInterface picks the network interface WS-Discovery should send its
// UDP multicast Probe on, instead of requiring a hardcoded interface name.
//
// A fixed interface name (e.g. "eth0") breaks on devices such as NVIDIA
// Jetson boards, where the physical Ethernet port maps to a different
// interface name depending on the OS image / JetPack version. SelectInterface
// walks all local interfaces and returns the first one that satisfies all of:
//
//  1. UP        - the link is administratively and operationally up
//  2. Multicast - the interface supports multicast (required by WS-Discovery)
//  3. Static IP - the interface has an assigned, non-loopback IPv4 address
//  4. Subnet    - that address falls inside the camera's subnet
//
// cameraCIDR identifies the camera network, e.g. "192.168.1.0/24".
func SelectInterface(cameraCIDR string) (string, error) {
	_, cameraNet, err := net.ParseCIDR(cameraCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid camera subnet %q: %w", cameraCIDR, err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}

			if cameraNet.Contains(ip4) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no usable network interface found for camera subnet %s", cameraCIDR)
}
