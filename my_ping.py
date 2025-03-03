# main scriot for ping
import os
import sys
import time
import struct
import socket
import argparse
import select
import statistics
import signal
from modules.modules import checksum_func


ICMP_ECHO_REQUEST = 8
ICMP_DEST_UNREACH = 3


def create_packet(id, size):
    """Create ICMP packet with given ID and size.
    :param name: id, size
    :returns: ICMP header + data
    :rtype: bytes
    """
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = bytes(size)
    chksum = checksum_func(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, chksum, id, 1)
    return header + data


def send_ping(sock, dest_addr, id, size):
    """Send a single ping packet.
    :param name: sock, dest_addr, id, size
    :returns: N/A
    :rtype: N/A
    """
    packet = create_packet(id, size)
    sock.sendto(packet, (dest_addr, 1))
    print(f"DEBUG: Sent packet to {dest_addr} with id={id}")


def receive_ping(sock, id, wait_interval):
    """Receive a ping response.
    :param name: sock, id, wait_interval
    :returns: Time taken to receive the response
    :rtype: float
    """

    time_remaining = wait_interval
    while True:
        start_time = time.time()
        readable = select.select([sock], [], [], time_remaining)
        if not readable[0]:
            return None

        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)
        print(f"DEBUG: Received packet from {addr[0]}: type={type}, code={code}, checksum={checksum}, id={packet_id}, sequence={sequence}")

        if type == ICMP_DEST_UNREACH:
            # analyse ICMP error message and gain original packet id
            original_header = rec_packet[48:56]
            _, _, _, original_id, _ = struct.unpack("bbHHh", original_header)
            print(f"DEBUG: Original packet ID in ICMP error message: {original_id}")
            if original_id == id:
                return None

        if packet_id == id:
            return time_received - start_time

        time_remaining -= time_received - start_time
        if time_remaining <= 0:
            return None


def print_summary(host, transmitted, received, delays):
    """Print the ping summary.
    :param name: host, transmitted, received, delays
    :returns: N/A
    :rtype: N/A
    """
    print(f"\n--- {host} ping statistics ---")
    packet_loss = ((transmitted - received) / transmitted) * 100
    print(f"{transmitted} packets transmitted, {received} packets received, {packet_loss:.1f}% packet loss")
    if delays:
        min_delay = round(min(delays), 3)
        avg_delay = round(statistics.mean(delays), 3)
        max_delay = round(max(delays), 3)
        stddev_delay = round(statistics.stdev(delays), 3)
        print(f"round-trip min/avg/max/stddev = {min_delay}/{avg_delay}/{max_delay}/{stddev_delay} ms")


def ping(host, count, wait_interval, size, timeout):
    """Mimic the Linux ping command.
    :param name: host, count, wait_interval, size, timeout
    :returns: N/A
    :rtype: N/A
    """

    def timeout_handler(signum, frame):
        raise TimeoutError

    if timeout:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

    try:
        try:
            dest_addr = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"Ping request could not find host {host}.")
            sys.exit()

        print(f"PING {host} ({dest_addr}): {size} data bytes")

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        transmitted = 0
        received = 0
        delays = []
        
        packet_id = os.getpid() & 0xFFFF  # generate unique packet id

        i = 0
        try:
            while count is None or i < count:
                send_ping(sock, dest_addr, packet_id, size)
                transmitted += 1
                result = receive_ping(sock, packet_id, wait_interval)

                if result is None:
                    print(f"Request timeout for icmp_seq {i}")
                else:
                    delay, ttl = result
                    received += 1
                    delays.append(delay * 1000)
                    print(f"{size} bytes from {dest_addr}: icmp_seq={i} ttl={ttl} time={round(delay * 1000, 2)} ms")
                i += 1
        except KeyboardInterrupt:
            print_summary(host, transmitted, received, delays)
            sys.exit()

        sock.close()
        print_summary(host, transmitted, received, delays)
    except TimeoutError:
        print("\nExecution timed out")
        print_summary(host, transmitted, received, delays)
        sys.exit()
    finally:
        if timeout:
            signal.alarm(0)


if __name__ == "__main__":
    """Main function to parse command line arguments and ping the target host.
    :param name: N/A
    :returns: N/A
    :rtype: N/A
    """
    parser = argparse.ArgumentParser(description="Custom ping implementation.")
    parser.add_argument("host", help="Target host to ping")
    parser.add_argument("-c", "--count", type=int, default=None, help="Number of packets to send")
    parser.add_argument("-i", "--interval", type=float, default=1, help="Interval between packets")
    parser.add_argument("-s", "--size", type=int, default=56, help="Payload size in bytes")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Timeout before giving up on response")

    args = parser.parse_args()
    ping(args.host, args.count, args.interval, args.size, args.timeout)
