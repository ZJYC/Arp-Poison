# Arp-Poison
Arp posion script (scapy/python)

I usually use this script to prevent other poeple from watching movie in my wifi net,And It works very well. 

If you want to use this script,you need to install **scapy** at first,And,you need to know the target's mac(By other tools)

and then you can call function <Attack_MAC> like this way "Attack_MAC("ens33","192.168.0.1","04:e6:76:46:a6:f3",60,300,1)"

to attack the target.

The params's meaning are:

**"ens33"** was my network interface(usually are "wlan0")

**"192.168.0.1"** was my gateway's IP

**"04:e6:76:46:a6:f3"** was target's mac

**60** means that it will generate and send 60 packets everytime

**300** means it will send 300 times

**1** means the interval between every send
