#!/usr/bin/env python
from scapy.all import *
import time
import random
import os
import ElementLib as E

Table_arp = {}
#
def GetSubNet(OurIP):
    OurIP=OurIP[::-1].split(".",1)[1][::-1]+"."
    return OurIP
#
def ScanfByArpOnce(OurIP = "192.168.1.1",Start = 0,End = 255,TimeOut = 3,ClearAtFirst = 1):
    if ClearAtFirst is 0 : Table_arp.clear()
    SubString = GetSubNet(OurIP)
    ip = []
    for num in range(Start,End+1):ip.append(SubString+str(num))
    ans,unans=srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(op=1,pdst=ip),timeout=TimeOut)
    def GetArpResult(r):
        Table_arp[r.sprintf("%ARP.hwsrc%")] = r.sprintf("%ARP.psrc%")
        return r.sprintf("%ARP.hwsrc%\t%ARP.psrc%")
    g = lambda(s,r):GetArpResult(r)
    ans.summary(g)

def ScanfByArp(Retry=4,Delay=4):
    for i in range(0,Retry):
        time.sleep(i*Delay)
        #Clear the table at first
        ScanfByArpOnce(OurIP=E.MY_ip,Start=100,End=150,TimeOut=Delay,ClearAtFirst=i)
    #To clean the file
    with open(E.ScanResultFileName,"w") as ScanResult:
        ScanResult.writelines("")
    #write the mac-ip info to file
    with open(E.ScanResultFileName,"a") as ScanResult:
        for mac,ip in Table_arp.items():
            ScanResult.writelines(mac+","+ip+"\n")
#test passed
def Test():
    print("Test begin....")
    ScanfByArp(2,1)
    print("Test over.....")
#
def ScanTask(Counter,Delay,Interval):
    if E.GetOurInf() == False:return
    while True:
        ScanfByArp(random.randrange(Counter[0],Counter[1]),\
        random.randrange(Delay[0],Delay[1]))
        SleepTime = random.randrange(Interval[0],Interval[1])
        print("Will sleep for %d Seconds..."%SleepTime)
        time.sleep(SleepTime)
#
ScanTask(Counter=(1,6),Delay=(1,4),Interval=(60,300))
