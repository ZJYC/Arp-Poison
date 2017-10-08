
#str="192.168.0.1"
#str=str[::-1].split(".",1)[1][::-1]+"."
#print(str)
#print(GetSubNet("192.168.0.1"))

import fileinput

lines,MAC,Interval,Mode,Plan="","","","",""
#读取规则到lines
def ImportRules(FileName):
    global lines
    lines = fileinput.input(FileName)
#解释一条规则
def ReadRule(Rule):
    global MAC
    global Interval
    global Mode
    global Plan
    Rule=Rule.split(",")
    MAC,Interval,Mode,Plan=Rule[0],Rule[1],Rule[2],Rule[3]
    print(MAC,Interval,Mode,Plan)
ImportRules("Rules.txt")
for line in lines:
    ReadRule(line)
