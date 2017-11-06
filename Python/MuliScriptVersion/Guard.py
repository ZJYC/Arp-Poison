#!/usr/bin/env python

import subprocess as s
import psutil
import time

args1=["gnome-terminal","-x","./Attack.py"]
args2=["gnome-terminal","-x","./Analysis.py"]
args3=["gnome-terminal","-x","./Scan.py"]

argus=[args1,args2,args3]
Process=[]

def ProcessExisted(Process):
    pids = psutil.pids()
    if Process.pid in pids:return True
    return False

def StartProcess(argus):
    global Process
    for arg in argus:
        Process.append(s.Popen(arg))

def RestartProcess(arg):
    Process[argus.index(arg)] = s.Popen(arg)

def EnsureProcess():
    for process in Process:
        if ProcessExisted(process) == False:
            RestartProcess(argus[Process.index(process)])

def GuardTask():
    StartProcess(argus)
    while True:
        EnsureProcess()
        time.sleep(5)
GuardTask()
