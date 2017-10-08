#!/usr/bin/env python
from scapy.all import *
import time
import random
import os

Table_arp = {}

def GetSubNet(OurIP):
    OurIP=OurIP[::-1].split(".",1)[1][::-1]+"."
    return OurIP

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
        ScanfByArpOnce(Start=100,End=150,TimeOut=Delay,ClearAtFirst=i)
    #To clean the file
    with open("ScanResult.txt","w") as ScanResult:
        ScanResult.writelines("")
    #write the mac-ip info to file
    with open("ScanResult.txt","a") as ScanResult:
        for mac,ip in Table_arp.items():
            ScanResult.writelines(mac+","+ip+"\n")
#test passed
def Test():
    print("Test begin....")
    ScanfByArp(2,1)
    print("Test over.....")
#
def ScanTask(IntervalMin=60,IntervalMax=300):
    while True:
        Time2Sleep = random.randrange(IntervalMin,IntervalMax)
        ScanfByArp(3,3)
        time.sleep(Time2Sleep)
ScanTask(10,20)
