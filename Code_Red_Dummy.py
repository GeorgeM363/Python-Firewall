from scapy.all import IP, TCP, Raw

def generate_dummy_codered_packet(
    src_ip="10.0.0.5",
    dst_ip="192.168.1.252",
    x_count=200
):
    """
    Generates a SAFE, non-exploitable Code Red–like HTTP packet
    for detection testing only.
    """

    payload = (
        b"GET /default.ida?" +
        b"X" * x_count +
        b" HTTP/1.0\r\n\r\n"
    )

    packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=12345, dport=80, flags="PA") /
        Raw(load=payload)
    )

    print(payload)
    return packet