#TLP: WHITE (free to share)
#Name: Maze Ransomware Vaccine
#Author: Telsy Threat Intelligence Research Team
#Description: Prevent Maze Ransomware execution through Mutex creation

import win32event
from threading import Thread
import time
from subprocess import Popen, PIPE

class MutexThread (Thread):
   def __init__(self, mutexname):
      Thread.__init__(self)
      self.mutexname = mutexname

   def run(self):
      mutex = win32event.CreateMutex(None, True, self.mutexname)
      while (True):
          time.sleep(1)

def removeesc(string):
    return string.replace("\r\n","").replace("\\r\\n","").replace("\r","").replace("\\r","").replace("\"","").replace("'","").replace("b","")

def gethostname():
    p = Popen(["hostname"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    hostname = removeesc(str(stdout))
    return hostname.upper()

def getserialvolume():
    p = Popen(["cmd","/c","vol","c:"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    id = removeesc(str(stdout)).replace("-","").split(" ")[-1]
    id = id.strip().lower()
    if id.startswith("0"):
        id = id[1:]
    return id

def getdomain():
    p = Popen(["wmic", "computersystem", "get", "domain"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    domain = removeesc(str(stdout)).replace("Domain","").strip()
    result = domain.upper()

    return result

def getcode(string):
    bytes = bytearray(string, "UTF-8")
    n = int(len(string)/8)

    var_edx = 0
    var_esi = 0x724
    var_ecx = 0
    j=0
    i=0

    for i in range(0,n):
        byte = bytes[i * 8]
        var_edx = byte
        var_edx += var_esi

        var_esi = 0
        var_ecx += var_edx
        var_esi += var_edx

        j=1
        while j<8:
            byte = bytes[j+(i*8)]

            var_edx = byte
            var_ecx += var_esi
            var_edx += var_esi

            var_esi = 0
            var_ecx += var_edx
            var_esi += var_edx
            j+=1

        var_ecx += var_esi


    offset = j *(i+1)
    n = len(string) % 8

    for k in range(0,n):
        byte = bytes[offset+k]
        var_esi += byte
        var_ecx += var_esi

        var_esi += 0
        var_ecx += var_esi

    var_edi = 0x80078071

    var_eax = var_esi * var_edi
    var_edx = var_eax >> 32
    var_edx = var_edx >> 0x0f
    var_eax = var_edx * 0xfff1

    var_esi = var_esi - var_eax
    var_eax = var_ecx

    var_eax = var_eax * var_edi
    var_edx = var_eax >> 32
    var_edx = var_edx >> 0x0f
    var_eax = var_edx * 0xfff1

    var_ecx = var_ecx - var_eax
    var_ecx = var_ecx << 0x10
    var_ecx = var_ecx | var_esi
    
    result = hex(var_ecx).rstrip("L").replace("0x","")
    if result.startswith("0"):
        result = id[1:]
    return result

pcname = gethostname()
domainname = getdomain()
string = domainname + "\\" + pcname

volume = getserialvolume()
code1 = getcode(string)
code2 = getcode(pcname)

mutexname1 = "Global\\" + code1 + volume
mutexname2 = "Global\\" + code2 + volume

thread1 = MutexThread(mutexname1)
thread2 = MutexThread(mutexname2)

thread1.start()
thread2.start()
