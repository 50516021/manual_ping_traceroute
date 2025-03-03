# main scriot for traceroute

import os
import sys
import time
import struct
import socket
import argparse
from modules.modules import checksum_func


def create_packet(size=32):  # default size is 32 bytes
    """Create an ICMP Echo Request packet.
    :param name: size
    :returns: ICMP header + data
    :rtype: bytes
    """
    icmp_type = 8  # ICMP Echo Request
    code = 0
    checksum_value = 0
    packet_id = os.getpid() & 0xFFFF
    sequence = 1
    header = struct.pack(
        "bbHHh",
        icmp_type,
        code,
        checksum_value,
        packet_id,
        sequence)
    data = struct.pack("d", time.time()) + b'Q' * (size - struct.calcsize("d"))
    chksum = checksum_func(header + data)
    header = struct.pack("bbHHh", icmp_type, code, chksum, packet_id, sequence)
    return header + data


def traceroute(target, max_hops, queries, numeric, summary, packet_size=32):
    """Mimic the Linux traceroute command with options -n, -q, and -S.
    :param name: target, max_hops, queries, numeric, summary
    :returns: N/A
    :rtype: N/A
    """
    try:
        dest_addr = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Traceroute request could not find host {target}.")
        sys.exit()

    print(f"traceroute to {target} ({dest_addr}), {max_hops} hops max, {packet_size + 8} byte packets:")

    for ttl in range(1, max_hops + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as recv_socket:
            recv_socket.settimeout(2)

            unanswered = 0  # Counter for unanswered packets
            times = []  # List to store response times for each query
            addresses = []  # List to store addresses for each query

            for _ in range(queries):
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as send_socket:
                    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    packet = create_packet(packet_size)
                    try:
                        send_socket.sendto(packet, (target, 33434))
                    except socket.error as e:
                        print(f"traceroute: sendto: {e.strerror}")
                        print(f"traceroute: wrote {target} {packet_size + 8} chars, ret=-1")
                        unanswered += 1
                        times.append("*")
                        addresses.append("*")
                        continue

                try:
                    start_time = time.time()
                    recv_packet, addr = recv_socket.recvfrom(512)
                    elapsed_time = (time.time() - start_time) * 1000
                    addr = addr[0]
                    times.append(round(elapsed_time, 2))
                    addresses.append(addr)

                    if numeric:
                        hostname = addr
                    else:
                        try:
                            hostname = socket.gethostbyaddr(addr)[0]
                        except socket.herror:
                            hostname = addr

                except socket.timeout:
                    unanswered += 1
                    times.append("*")
                    addresses.append("*")

            if addresses:
                unique_addresses = list(set(addresses))
                if len(unique_addresses) == 1:
                    addr_str = unique_addresses[0]
                else:
                    addr_str = " ".join(unique_addresses)

                times_str = "  ".join(f"{time} ms" if time != "*" else "*" for time in times)
                loss_percentage = (unanswered / queries) * 100
                if summary:
                    print(f"{ttl}\t{addr_str} ({addr_str})\t{times_str} ({loss_percentage:.1f}% loss)")
                else:
                    print(f"{ttl}\t{addr_str} ({addr_str})\t{times_str}")
            else:
                print(f"{ttl}\t*")

            if addr == dest_addr:
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom traceroute implementation.")
    parser.add_argument("host", help="Target host to trace")
    parser.add_argument("-n", "--numeric", action="store_true", help="Show numeric IPs only")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Max hops before giving up")
    parser.add_argument("-q", "--queries", type=int, default=3, help="Number of probes per TTL")
    parser.add_argument("-S", "--summary", action="store_true", help="Print summary of losses")

    args = parser.parse_args()
    traceroute(args.host, args.max_hops, args.queries, args.numeric, args.summary)
