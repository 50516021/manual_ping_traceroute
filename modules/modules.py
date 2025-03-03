# module script for network communication

def checksum_func(source_string):
    """Calculate the checksum of the packet.
    :param name: source_string
    :returns: checksum
    :rtype: int (hexadecimal)
    """

    sum = 0
    count_to = (len(source_string) // 2) * 2

    for count in range(0, count_to, 2):
        sum += (source_string[count] << 8) + source_string[count + 1]

    if count_to < len(source_string):
        sum += source_string[-1] << 8

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff
