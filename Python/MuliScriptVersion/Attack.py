#!/usr/bin/env python
from scapy.all import *
import time
import random
import os
import ElementLib as E

Payload=[]
PayloadFileTs=[]

def SendOnePacket(Face,PKT,Interval=0.02):
    try:
        sendp(PKT,iface = Face)
        time.sleep(Interval)
    except:print("!!Send Error!!")

def SendPacks(Face,PKT,Group=10,Interval=0.02):
    if len(PKT) == 0:return
	for i in range(0,len(PKT)):
	    if i >= ((len(PKT) / Group) - 1):return
	    SendOnePacket(Face,PKT[i*Group:(i+1)*Group],Interval)
	    i = i + Group

def ImportPayload():
    global Payload
    if DosePayloadFileModified() == True:
        try:
            Payload = rdpcap(E.PcapFileName)
        except:print("File %s Not existed..."%E.PcapFileName)
        return True
    else:
        return False
    
def DosePayloadFileModified():
    global PayloadFileTs
    if PayloadFileTs != os.path.getmtime(E.PcapFileName):
        PayloadFileTs = os.path.getmtime(E.PcapFileName);
        return True
    else:
        return False

def AttackTask():
    while True:
        ImportPayload()
        SendPacks(E.NetFaceName,Payload,10,0.02)

AttackTask()
