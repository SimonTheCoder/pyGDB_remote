
import socket
import re
from threading import Thread,currentThread,activeCount

from checksum import checksum

__DEBUG__ = True

class Sender:
    def __init__(self,conn):
        self.conn = conn
        self.last_sent = ("",True)
    def send(self,data,need_checksum=True):
        if __DEBUG__ is True:print "<- %s" % data
        if need_checksum:
            self.conn.sendall("$%s#%s" % (data,checksum(data)))
        else:
            self.conn.sendall(data)
        self.last_sent = (data,need_checksum)
    def resend(self):
        self.send(self.last_sent[0],self.last_sent[1])

class Packet:
    packetRE = re.compile(r'([\+\-]*)\$([^#]+)#([0-9a-f]{2})');
    def __init__(self,raw_data):
        self.raw_data = raw_data
        self.ack = None
        self.command = None
        self.checksum = None

        if raw_data == "-":
            self.ack = "-"
            return
        
        if raw_data == "+":
            self.ack = "+"
            return

        matchObj = self.packetRE.match(raw_data)
        if matchObj is None:
            self = None
            print "WARN: %s can not be parsed!" % raw_data
            return
        self.ack =matchObj.group(1)
        self.command =matchObj.group(2)
        self.checksum =matchObj.group(3)
        
    def is_valid(self):
        if self.command is None or self.checksum is None:
            if self.ack is not None:
                return True
            else:
                return False
        
        if checksum(self.command) == self.checksum:
            return True
        else:
            return False

class GDB_server(object):
    def __init__(self, host="127.0.0.1" , port=1234):
        self.host = host
        self.port = port
        self.ack_mode =True
    
    def start(self):
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.s.bind((self.host, self.port))
        self.s.listen(1)
        if __DEBUG__ is True:print "Server listenning %s:%d" % (self.host,self.port) 
        self.conn,self.gdb_addr = self.s.accept()
        if __DEBUG__ is True:print "connet from:",self.gdb_addr
        self.sender = Sender(self.conn)

        #enter main loop
        while True:
            data = self.conn.recv(4096+8)
            if len(data) == 0:
                conn.close()
                print "connect lost."
                break

            #pump up packet
            if __DEBUG__ is True:print "raw data: %s" % data            
            pack = Packet(data)
            self.packet_handle(pack)

    def packet_handle(self,packet):
        '''Abstract Method'''
        pass
    
    def send(self,data,need_checksum=True):
        self.sender.send(data,need_checksum)

class Dummy_device(GDB_server):
    def packet_handle(self,packet):
        
        pass

class Proxy_server(GDB_server):
    def __init__(self,host,port):
        super(Proxy_server,self).__init__(host,port)
        self.socks = None
    
    def revc_from_qemu(self):
        while True:
            try:
                res_data = self.socks.recv(4096)
                print("GOT: %s" % res_data)
            except socket.timeout:
                print("qemu gdb time out!")
                res_data = "-"
            self.send(res_data, False)
    def connect_real(self,host="127.0.0.1",port=1234):
        if self.socks is not None:
            return
        socks = socket.socket()
        #socks.settimeout(1)
        socks.connect((host,port))
        self.socks = socks
        Thread(target = self.revc_from_qemu, args =()).start()
 
    def packet_handle(self,packet):
        self.connect_real() 
        self.socks.sendall(packet.raw_data)

if __name__ == "__main__":
    server = Proxy_server("127.0.0.1", 51234)
    server.start()

if __name__ == "__main__old":
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)  
    s.bind(('127.0.0.1',1234))
    s.listen(1)

    ack_mode = True
    while True:
        conn,addr = s.accept()
        print "connet from:",addr
        sender = Sender(conn)
        while True:
            data = conn.recv(4096+8)
            if len(data) == 0:
                conn.close()
                print "connect lost."
                break
            print "-> %s" % data
            
            pack = Packet(data)
            if not pack.is_valid():
                #sender.send("-",False)
                print "Packet checksum fail! ack= %s , command = %s, checksum = %s" % (pack.ack,pack.command,pack.checksum)
                continue
            if pack.ack == "-":
                sender.resend()
                continue
            
            if pack.ack[0] == "+" or pack.ack[0] == "-" or pack.ack == "-+" and pack.checksum is None:
                continue
            
            if ack_mode:
                sender.send("+",True) 
            if pack.command.split(":")[0] == "qSupported":
                sender.send("PacketSize=1000;QStartNoAckMode+;multiprocess-;")
                #sender.send("PacketSize=1000;qXfer:features:read+")
                #sender.send("")
            if pack.command == "QStartNoAckMode":
                sender.send("OK")
                ack_mode = False
            if pack.command == "Hg0" or pack.command == "Hc-1":  #select any thread or set target thread
                sender.send("OK")

            if pack.command == "?":
                sender.send("T05thread:01;")
                
            if pack.command == "qC": #current thread id. 
                sender.send("QC0")
                
            if pack.command == "qAttached": #attached ?
                sender.send("1")
            
            if pack.command == "qOffsets": #section reloc info
                sender.send("Text=0;Data=0;Bss=0")
            if pack.command == "g":
                sender.send("0100015c"*15)
            if pack.command == "pf":
                sender.send("342d0001")
            if pack.command == "qSymbol::":
                sender.send("OK")
            if pack.command == "qTStatus":
                #sender.send("tnotrun:0")
                sender.send("")
            #<ESC>if data == "+":
                #<ESC>continue
            #<ESC>if data == "-":
                #<ESC>sender.resend()
                #<ESC>continue
            #<ESC>conn.send("+")
            #<ESC>m = re.match(r'^\+?\$qSupported:.*',data)
            #<ESC>if m is not None: 
                #<ESC>sender.send("PacketSize=512")
            #<ESC>m = re.match(r'\+?\$Hg0.*',data)
            #<ESC>if m is not None:
                #<ESC>sender.send("OK")
