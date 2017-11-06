#!/usr/bin/env python
from scapy.all import *
import time
import random
import os
import fileinput
import ElementLib as E
#------------------------------------------------
Rules,MAC,Interval,Mode,Plan=[],[],[],[],[]
Payload=ARP()*E.PayloadLen
ScanResults=[]
ScanResultsMAC=[]
ScanResultsIP=[]
ScanResultFileTs=[]
RulesFileTs=[]

def ImportRules(FileName):
    global Rules
    if DoseRulesModified():
        Rules = list(fileinput.input(FileName))
        return True
    else:
        return False

def ImportScanResult(FileName):
    global ScanResults
    global ScanResultsMAC
    global ScanResultsIP

    if DoseScanRusultModified():
        ScanResultsMAC=[]
        ScanResultsIP=[]
        ScanResults = fileinput.input(FileName)
        for ScanResult in ScanResults:
            ScanResult = ScanResult.replace("\n","")
            ScanResultsMAC.append(ScanResult.split(",")[0])
            ScanResultsIP.append(ScanResult.split(",")[1])
        return True
    else:
        return False

def DoseScanRusultModified():
    global ScanResultFileTs
    if ScanResultFileTs != os.path.getmtime(ScanResultFileName):
        ScanResultFileTs = os.path.getmtime(ScanResultFileName);return True
    else:
        return False

def DoseRulesModified():
    global RulesFileTs
    if RulesFileTs != os.path.getmtime(RulesFileName):
        RulesFileTs = os.path.getmtime(RulesFileName);return True
    else:
        return False

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
    Payload=ARP()*E.PayloadLen

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
        Temp_mac = E.RandomMacs(E.VendorMAC01,PackNum)
        #PKT_1 = Ether(dst=TargtMAC)/ARP(op=1,psrc=E.GW_ip,hwsrc=Temp_mac,pdst=TargetIP,hwdst=TargtMAC)
        #PKT_2 = Ether(dst=E.GW_mac)/ARP(op=2,psrc=TargetIP,hwsrc=Temp_mac,pdst=E.GW_ip,hwdst=E.GW_mac)
        #print(type(PKT_1))
        for i in range(0,PackNum):
            PKT_1 = Ether(dst=TargtMAC)/ARP(op=1,psrc=E.GW_ip,hwsrc=Temp_mac[i],pdst=TargetIP,hwdst=TargtMAC)
            PKT_2 = Ether(dst=E.GW_mac)/ARP(op=2,psrc=TargetIP,hwsrc=Temp_mac[i],pdst=E.GW_ip,hwdst=E.GW_mac)
            PKT.append(PKT_1)
            PKT.append(PKT_2)
    return PKT

def FillPayload4MAC(MAC,offset):
    if MatchTarget(MAC) == False:return False
    if E.PlanCheck(Plan) == False:return False

    PackNum,PackInsert = E.PayloadLen / int(Interval),int(Interval)
    PKT_temp = GeneratePacket4MAC(PackNum,MAC,ScanResultsIP[ScanResultsMAC.index(MAC)])
    for i in range(0,PackNum):
        #Ensure not outrange
        if i >= PackNum - 1:return
        Payload[PackNum*i+offset] = PKT_temp[i]

def FillPayload4MACs():
    PayloadUpdate = ImportRules(RulesFileName) | \
    ImportScanResult(ScanResultFileName)
    if PayloadUpdate == True:
        ClearPayload()
        for Rule in Rules:
            ReadRule(Rule)
            FillPayload4MAC(MAC,Rules.index(Rule))
    return PayloadUpdate

def AnalysisTask(Interval=5):
    if E.GetOurInf() == False:return
    while True:
        if FillPayload4MACs() == True:
            wrcap("PcapFileName",Payload)
            print("Update Pcap File...")
        else:
            print("will sleep for %d"%Interval)
            time.sleep(Interval)

AnalysisTask()
