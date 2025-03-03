# main scriot for traceroute

import os
import sys
import time
import struct
import socket
import argparse
from modules.modules import checksum_func


def create_packet():
    """Create an ICMP Echo Request packet.
    :param name: N/A
    :returns: ICMP header + data
    :rtype: bytes
    """
    icmp_type = 8  # ICMP Echo Request
    code = 0
    checksum = 0
    packet_id = os.getpid() & 0xFFFF
    sequence = 1
    header = struct.pack("bbHHh", icmp_type, code, checksum, packet_id, sequence)
    data = struct.pack("d", time.time())
    chksum = checksum_func(header + data)
    header = struct.pack("bbHHh", icmp_type, code, chksum, packet_id, sequence)
    return header + data


def traceroute(target, max_hops, queries, numeric):
    """Mimic the Linux traceroute command.
    :param name: target, max_hops, queries, numeric
    :returns: N/A
    :rtype: N/A
    """
    try:
        dest_addr = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Traceroute request could not find host {target}.")
        sys.exit()

    print(f"traceroute to {target} ({dest_addr}), {max_hops} hops max,  byte packets")

    for ttl in range(1, max_hops + 1):
        times = []
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as recv_socket:
            recv_socket.settimeout(2)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as send_socket:
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                send_socket.sendto(b"", (target, 33434))

                try:
                    start_time = time.time()
                    recv_packet, addr = recv_socket.recvfrom(512)
                    elapsed_time = (time.time() - start_time) * 1000
                    addr = addr[0]
                    times.append(round(elapsed_time, 2))

                    if numeric:
                        hostname = addr
                    else:
                        try:
                            hostname = socket.gethostbyaddr(addr)[0]
                        except socket.herror:
                            hostname = addr

                except socket.timeout:
                    times.append("*")

        if times:
            times_str = "  ".join(f"{time} ms" if time != "*" else "*" for time in times)
            print(f"{ttl}  {hostname} ({addr})  {times_str}")
        else:
            print(f"{ttl}  *")

        if addr == dest_addr:
            break


if __name__ == "__main__":
    """Main function to parse command line arguments and run traceroute.
    :param name: N/A
    :returns: N/A
    :rtype: N/A
    """

    parser = argparse.ArgumentParser(description="Custom traceroute implementation.")
    parser.add_argument("host", help="Target host to trace")
    parser.add_argument("-n", "--numeric", action="store_true", help="Show numeric IPs only")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Max hops before giving up")
    parser.add_argument("-q", "--queries", type=int, default=3, help="Number of probes per TTL")

    args = parser.parse_args()
    traceroute(args.host, args.max_hops, args.queries, args.numeric)
