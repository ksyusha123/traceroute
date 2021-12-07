import click
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP, TCP, UDP
from ipwhois import IPWhois, IPDefinedError
from time import perf_counter


def get_asn(ip):
    try:
        return IPWhois(ip).lookup_whois()["asn"]
    except IPDefinedError:
        return "-"


@click.command()
@click.option("-t", "--timeout", default=2, required=False)
@click.option("-p", "--port", required=False)
@click.option("-n", "--max_requests_number", default=32, required=False)
@click.option("-v", "--verbose", is_flag=True, default=False)
@click.argument("ip")
@click.argument("protocol")
def traceroute(timeout, port, max_requests_number, verbose, ip, protocol):
    if protocol == "tcp":
        transport_layer_pkt_part = TCP(dport=port)
    elif protocol == "udp":
        transport_layer_pkt_part = UDP(dport=port)
    else:
        transport_layer_pkt_part = ICMP()
    current_ttl = 1
    while current_ttl <= max_requests_number:
        pkt = IP(dst=ip, ttl=current_ttl) / transport_layer_pkt_part
        start = perf_counter()
        reply = sr1(pkt, verbose=0, timeout=timeout)
        total_time = round(perf_counter() - start, 2)
        output = f"{current_ttl} "
        if not reply:
            output += "*"
        else:
            current_ip = reply.src
            output += f"{current_ip} {total_time}"
            if verbose:
                output += f" {get_asn(current_ip)}"
            current_ttl += 1
            if current_ip == ip:
                print(output)
                break
        print(output)


if __name__ == '__main__':
    traceroute()
