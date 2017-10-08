#!/usr/bin/env python

from scapy.all import *

import time

import random

import os



#"192.168.0.1"->"192.168.0."

def GetSubNet(OurIP):

    OurIP=OurIP[::-1].split(".",1)[1][::-1]+"."

    return OurIP

#AA,00,AA,AA,AA,00->AA,XX,AA,AA,AA,XX

def RandomMac(Vendor):

    import random

    if len(Vendor) > 6:return false

    return ":".join(map(lambda x:"%02X"%random.randint(0,0xFF) if x==0 else "%02X"%x,Vendor+[0]*(6-len(Vendor))))

#

def RandomMacs(Vendor,Num):

    Result=[]

    for i in range(0,Num):

        Result.append(RandomMac(Vendor))

    return Result

#

def RandomIP(Vendor):

    import random

    if len(Vendor) > 4:return false

    return ":".join(map(lambda x:"%d"%random.randint(0,0xFF) if x==0 else "%d"%x,Vendor+[0]*(4-len(Vendor))))

#

def RandomIPs(Vendor,Num):

    Result=[]

    for i in range(0,Num):

        Result.append(RandomIP(Vendor))

    return Result

#

def PlanCheck(Plan):
    i=0

    CurHour=time.localtime(time.time()).tm_hour

    CurMinu=time.localtime(time.time()).tm_min

    CurCounter=CurHour*60+CurMinu

    #Temp_Start=int(Plan[i*4+0])*60+int(Plan[i*4+1])

    #Temp_End=Plan[i*4+2]*60+Plan[i*4+3]
    Plan = Plan.replace("\r","")
    Temp_Start = int(Plan.split(":")[0])*60 + int(Plan.split(":")[1])
    Temp_End = int(Plan.split(":")[2])*60 + int(Plan.split(":")[3])

    if (CurCounter>Temp_Start)and(CurCounter<Temp_End):
    	return True

    return False



def GetOurInf(Face,Debug=True):

    global MY_ip

    global MY_mac

    MY_ip = get_if_addr(Face)

    MY_mac = get_if_hwaddr(Face)

    if MY_ip is None or MY_mac is None:return False

    if Debug is True:print("%s -> %s"%(MY_ip,MY_mac))

    return True
