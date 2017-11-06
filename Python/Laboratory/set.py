import subprocess as s

process = s.Popen("get.py",shell=True)

print("PID is %d "%process.pid)
