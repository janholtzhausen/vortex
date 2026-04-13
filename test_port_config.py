#!/usr/bin/env python3
"""
Example script to configure vortex protected ports via BPF map.
This would be integrated into vortex's main application.
"""

import struct
import socket


# Port configuration structure matching BPF definition
class PortConfig:
    def __init__(self):
        self.ports = []  # List of port numbers (host byte order)

    def to_bytes(self):
        """Convert to bytes for BPF map update"""
        # Maximum 16 ports
        max_ports = 16
        ports_bytes = b""

        # Convert ports to network byte order
        for port in self.ports[:max_ports]:
            ports_bytes += struct.pack("!H", port)

        # Pad with zeros if less than 16 ports
        ports_bytes += b"\x00\x00" * (max_ports - len(self.ports[:max_ports]))

        # Count byte
        count_byte = struct.pack("B", min(len(self.ports), max_ports))

        # Padding (7 bytes)
        padding = b"\x00" * 7

        return ports_bytes + count_byte + padding

    @classmethod
    def from_bytes(cls, data):
        """Create from bytes (for reading from BPF map)"""
        config = cls()

        # Parse ports (16 * 2 bytes = 32 bytes)
        ports_data = data[:32]
        for i in range(0, 32, 2):
            port = struct.unpack("!H", ports_data[i : i + 2])[0]
            if port != 0:
                config.ports.append(port)

        # Parse count (1 byte)
        count = struct.unpack("B", data[32:33])[0]

        # Trim to actual count
        config.ports = config.ports[:count]

        return config


def configure_ports_via_bpftool(ports):
    """
    Example command to update port configuration using bpftool.
    In reality, vortex would do this programmatically via libbpf.
    """
    config = PortConfig()
    config.ports = ports

    # Convert to hex for bpftool
    config_hex = config.to_bytes().hex()

    print("Example bpftool command to configure ports:")
    print(f"sudo bpftool map update pinned /sys/fs/bpf/vortex/port_config_map \\")
    print(f"  key hex 00 00 00 00 value hex {config_hex}")
    print()
    print(f"This would protect ports: {ports}")


def main():
    # Example 1: Default web ports
    print("=== Example 1: Default web ports ===")
    configure_ports_via_bpftool([80, 443])
    print()

    # Example 2: Additional management port
    print("=== Example 2: Web + management port ===")
    configure_ports_via_bpftool([80, 443, 8443])
    print()

    # Example 3: Non-standard ports only
    print("=== Example 3: Non-standard HTTPS ===")
    configure_ports_via_bpftool([9443])
    print()

    # Example 4: Multiple services
    print("=== Example 4: Multiple services ===")
    configure_ports_via_bpftool([80, 443, 3000, 8080, 8443])


if __name__ == "__main__":
    main()
