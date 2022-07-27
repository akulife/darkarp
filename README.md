# About tool
"darkarp.py is a basic ARP (Address Resolution Protocol) spoofing tool written with Python programming language, which also implements packet sniffing.
<hr />

# Installation 

clone the repository

`git clone https://github.com/akulife/darkarp.git`

enter directory called 'darkarp'

`cd darkarp`

install requirements

`pip install -m requirements.txt`

print usage 

`python3 darkarp.py`
<hr />

# Usage


<pre>
[aku@thug darkarp]# python3 darkarp.py 

	⠀⠀⠀⠀⠀⣠⣴⣶⣯⠪⣕⢶⣦⣔⢄⠀⠀⠀⠀  			      db      `7MMF' `YMM'`7MMF'   `7MF'
	⠀⠀⠀⢀⣼⣿⣿⣿⣿⣧⡙⣧⢹⣿⣷⣇⠀⠀⠀⠀  			     ;MM:       MM   .M'    MM       M  
	⠀⠀⠀⣸⣿⣿⣿⣿⡟⠛⢿⣾⢿⡟⠟⢛⡄⠀⠀⠀  			    ,V^MM.      MM .d"      MM       M  
	⠀⠀⠀⣿⣿⣿⣿⢟⣯⢖⣒⣚⣭⠀⣣⣈⡨⣢⠀   			   ,M  `MM      MMMMM.      MM       M  
	⠀⠀⠀⣿⣿⣿⢏⡛⠱⢿⣧⣿⢿⡂⠻⠭⠿⣴⠀⠀  			   AbmmmqMA     MM  VMA     MM       M  
	⠀⠀⣰⣿⣿⡟⢼⣿⡶⡄⣴⣶⣶⠇⠀⢶⣶⡎⡗⠀  			  A'     VML    MM   `MM.   YM.     ,M  
	⠀⢠⣿⣿⣿⢇⣷⣭⣃⠈⠙⠁⣠⢟⡟⡷⡙⢸⣷⠃  			.AMA.   .AMMA..JMML.   MMb.  `bmmmmd"'  
	⢀⣿⣿⠿⢟⣸⣷⠶⠯⠍⠀⡫⢬⣬⣤⣥⡅⣊⣿⣼                           
	⡜⣫⣴⣿⣿⣿⠁⢰⣿⣿⣿⣿⣞⠿⢛⣵⣾⡿⠛⠁			@akulife - raminiskandarov2004@gmail.com
	⠙⠿⠿⠿⣿⣿⣼⣬⣿⣿⣿⣿⣿⣷⠟⠉⠁⠀⠀⠀


usage: darkarp.py [-h] [-t TARGET] [-g GATEWAY] [-i INTERFACE]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        -t 192.168.0.5
  -g GATEWAY, --gateway GATEWAY
                        -g 192.168.0.1
  -i INTERFACE, --interface INTERFACE
                        -i wlan0

</pre>

As you can see from the arguments on the output above, for defining the target which is you want to attack, you need to use the -t flag, and for
defining the gateway use the -g flag. Also if you want to sniff the network traffic which comes from the target, use -I flag and define the interface.

<pre>
[aku@thug darkarp]# sudo python3 darkarp.py -t 192.168.0.5 -g 192.168.0.1 -i eth0 
</pre>
For running the script you need to run as a root user. note that also if you don't want to perform network sniffing then ignore -i flag.
</hr>
