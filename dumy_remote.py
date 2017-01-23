
import socket
import re

from checksum import checksum



class Sender:
    def __init__(self,conn):
        self.conn = conn
        self.last_sent = ("",True)
    def send(self,data,need_checksum=True):
        print "<- %s" % data
        if need_checksum:
            self.conn.send("$%s#%s" % (data,checksum(data)))
        else:
            self.conn.send(data)
        self.last_sent = (data,need_checksum)
    def resend(self):
        self.send(self.last_sent[0],self.last_sent[1])

class Packet:
    packetRE = re.compile(r'([\+\-]*)\$([^#]+)#([0-9a-f]{2})');
    def __init__(self,raw_data):
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

if __name__ == "__main__":
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
