#!/usr/bin/env python3

import sys
import os
import hashlib
import datetime
import socket
import time
import math

__VERSION__: str = "2.0.0"

# Constants for knock sequence generation
# The sequence length determines how many ports are in the knock sequence
SEQUENCE_LENGTH = int(os.environ.get("KNOCKD_ROTATOR_LENGTH", 10))
assert SEQUENCE_LENGTH >= 5, "KNOCKD_ROTATOR_LENGTH must be at least 5"

# The secret provides additional security against sequence guessing
SECRET = os.environ.get("KNOCKD_ROTATOR_SECRET")
if not SECRET:
    sys.stderr.write("Error: KNOCKD_ROTATOR_SECRET environment variable must be set\n")
    sys.exit(1)
elif len(SECRET) < 10:
    sys.stderr.write(
        "Error: KNOCKD_ROTATOR_SECRET must be at least 10 characters long\n"
    )
    sys.exit(1)

# PROTO_MODULO determines protocol selection:
# - If PROTO_MODULO is 0, always use TCP
# - If PROTO_MODULO > 0, port % PROTO_MODULO even = tcp, odd = udp
PROTO_MODULO = int(os.environ.get("KNOCKD_ROTATOR_PROTO_MODULO", 0))

# Period modulo determines how frequently the sequence changes (in seconds)
# Default: 21600 (6 hours)
PERIOD_MODULO = int(os.environ.get("KNOCKD_ROTATOR_PERIOD_MODULO", 21600))
if "KNOCKD_ROTATOR_PERIOD_MODULO" not in os.environ:
    sys.stderr.write(
        "Warning: KNOCKD_ROTATOR_PERIOD_MODULO not set, using default of 21600 (6 hours)\n"
    )

# Port list for sequence generation
# Default: 2000-65536 range to avoid requiring elevated privileges
port_str = os.environ.get("KNOCKD_ROTATOR_PORTS", "2000-65536")
PORTS = []
for part in port_str.split(","):
    part = part.strip()
    if "-" in part:
        start, end = part.split("-", 1)
        # Include both ends of the range
        PORTS.extend(list(range(int(start), int(end) + 1)))
    else:
        PORTS.append(int(part))

# Ensure no duplicates
if len(PORTS) != len(set(PORTS)):
    sys.stderr.write("Error: Duplicate ports in KNOCKD_ROTATOR_PORTS are not allowed\n")
    sys.exit(1)

# Ensure at least 2 ports
assert len(PORTS) >= 2, "KNOCKD_ROTATOR_PORTS must contain at least 2 ports"

# Warn if 3 or fewer ports
if len(PORTS) <= 3:
    sys.stderr.write(
        "Warning: Only {} ports available. This significantly reduces security.\n".format(
            len(PORTS)
        )
    )

# Sort ports for consistency
PORTS.sort()

# Minimum entropy required (in bits) for a secure knock sequence
# 40 bits is roughly equivalent to a 12-character alphanumeric password
MIN_ENTROPY_BITS = 40


def calculate_knock_entropy(sequence_length: int, port_count: int) -> float:
    """
    Calculate the entropy of a knock sequence in bits.

    Args:
        sequence_length: Length of the knock sequence
        port_count: Number of possible ports to choose from

    Returns:
        float: Entropy in bits (sequence_length * log2(port_count))
    """
    if port_count <= 1:
        return 0
    return sequence_length * math.log2(port_count)


def calculate_shared_seed(offset: int = 0) -> int:
    """
    Calculate the shared seed based on the current time period with an optional offset.

    Args:
        offset: Integer offset to shift the period (negative for past periods, positive for future)
                Default is 0 (current period)

    Returns:
        int: The calculated seed value based on current UTC time with the applied offset
    """
    current_timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    # Calculate the beginning of the current period
    period_start = ((current_timestamp // PERIOD_MODULO) + offset) * PERIOD_MODULO
    assert period_start
    assert len(str(period_start)) > 5, f"Suspicious period start value: {period_start}"
    return period_start


# Keep this for compatibility reasons
__SHARED_SEED__ = calculate_shared_seed()


def generate_knock_sequence(service_name: str, offset: int = 0) -> str:
    """
    Generate a formatted knock sequence for a specific service.

    This function combines port generation and formatting into a single call.
    The sequence is based on the current time period and the service name.
    Protocol is determined by port number: even ports use tcp, odd ports use udp.

    If the provided service_name doesn't end with "_ROTATOR", it will
    automatically be appended to ensure compatibility with knock_rotator_server.py.

    Args:
        service_name: The name of the service to generate a sequence for
        offset: Integer offset to shift the time period (default: 0)

    Returns:
        Formatted sequence string (e.g. "1234:tcp 5678:udp 9012:tcp")

    Raises:
        ValueError: If the configuration provides insufficient entropy
    """
    # Calculate and check entropy before generating sequence
    entropy_bits = calculate_knock_entropy(SEQUENCE_LENGTH, len(PORTS))
    if entropy_bits < MIN_ENTROPY_BITS:
        error_msg = (
            f"Insufficient entropy: {entropy_bits:.2f} bits. "
            f"Required minimum: {MIN_ENTROPY_BITS} bits. "
            f"Increase SEQUENCE_LENGTH or add more ports."
        )
        sys.stderr.write(f"Error: {error_msg}\n")
        raise ValueError(error_msg)

    # Ensure service_name ends with _ROTATOR
    if not service_name.endswith("_ROTATOR"):
        service_name = f"{service_name}_ROTATOR"

    # Calculate seed with the provided offset
    current_seed = calculate_shared_seed(offset)

    # Create the seed for this specific service
    section_seed = f"{current_seed}{service_name}{SECRET}"

    # Generate the ports
    ports = []
    for i in range(1, SEQUENCE_LENGTH + 1):
        # Generate a hash from seed+iteration
        hash_input = f"{section_seed}{i}".encode("utf-8")
        hash_value = hashlib.sha256(hash_input).hexdigest()

        # Take first 8 hex chars and convert to decimal
        decimal = int(hash_value[:8], 16)

        # Select a port from our port list
        port_index = decimal % len(PORTS)
        port = PORTS[port_index]
        assert port in PORTS, f"Port {port} not in allowed port list"
        ports.append(port)

    # Format the sequence with protocol determination
    # Use original format: PORT:tcp or PORT:udp
    if PROTO_MODULO == 0:
        # When PROTO_MODULO is 0, always use TCP
        sequence = " ".join([f"{port}:tcp" for port in ports])
    else:
        # Otherwise use modulo to determine protocol
        sequence = " ".join(
            [f"{port}:{'tcp' if port % PROTO_MODULO == 0 else 'udp'}" for port in ports]
        )

    # Validate the sequence meets our requirements
    for port_proto in sequence.split():
        port_str, proto = port_proto.split(":")
        port = int(port_str)
        assert 2000 <= port <= 65535, f"Port {port} is outside valid range (2000-65535)"
        assert proto in [
            "tcp",
            "udp",
        ], f"Protocol {proto} is not valid (must be tcp or udp)"

    return sequence


def knock_ports(host: str, sequence: str):
    """
    Perform port knocking on a target host using the generated sequence.

    Args:
        host: The target host to knock on
        sequence: Space-separated list of port:protocol pairs
    """
    # Parse the sequence into port/protocol pairs
    for port_proto in sequence.split():
        port, proto = port_proto.split(":")
        port = int(port)

        if proto.lower() == "udp":
            print(f"Knocking UDP port {port}...")
            # For UDP, we create a UDP socket and try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(b"", (host, port))
            finally:
                sock.close()
        else:  # TCP
            print(f"Knocking TCP port {port}...")
            # For TCP, we create a TCP socket and try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set timeout to 1 second
            try:
                sock.connect((host, port))
            except (socket.timeout, socket.error):
                # Expected to fail if port is closed, which is normal
                pass
            finally:
                sock.close()

        # Small delay between knocks
        time.sleep(0.1)


def main():
    """Main function to parse command line arguments and either generate a sequence or perform port knocking."""
    import argparse

    # Calculate and display entropy information
    entropy_bits = calculate_knock_entropy(SEQUENCE_LENGTH, len(PORTS))
    print(f"Knock sequence entropy: {entropy_bits:.2f} bits")
    if entropy_bits < MIN_ENTROPY_BITS:
        print(
            f"WARNING: Current configuration has low entropy ({entropy_bits:.2f} bits)"
        )
        print(f"Minimum recommended entropy: {MIN_ENTROPY_BITS} bits")

    # parse 'gene' as 'generate' etc
    argv = sys.argv
    if "generate" not in argv and "knock" not in argv:
        for ia, a in enumerate(sys.argv):
            if "generate".startswith(a):
                sys.argv[ia] = "generate"
                break
            elif "knock".startswith(a):
                sys.argv[ia] = "knock"
                break

    parser = argparse.ArgumentParser(
        description="Port knock sequence generator and client"
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Generate mode
    gen_parser = subparsers.add_parser("generate", help="Generate a knock sequence")
    gen_parser.add_argument(
        "service_name", help="Name of the service to generate sequence for"
    )
    gen_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Time period offset (negative for past, positive for future)",
    )

    # Knock mode
    knock_parser = subparsers.add_parser("knock", help="Perform port knocking")
    knock_parser.add_argument("host", help="Target host to knock on")
    knock_parser.add_argument(
        "service_name", help="Name of the service to generate sequence for"
    )
    knock_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Time period offset (negative for past, positive for future)",
    )

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode == "generate":  # Generate mode
        print(generate_knock_sequence(args.service_name, args.offset))

    elif args.mode == "knock":  # Knock mode
        sequence = generate_knock_sequence(args.service_name, args.offset)
        knock_ports(args.host, sequence)

    else:
        print(f"Unknown mode: {args.mode}")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
