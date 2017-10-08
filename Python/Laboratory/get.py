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
VendorMAC = [0xAA,0x00,0xAA,0xAA,0xAA,0xAA]
print(RandomMacs(VendorMAC,10))
