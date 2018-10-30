
import re
import socket

from checksum import checksum 
from threading import Thread,currentThread,activeCount

__DEBUG__ = True

class Stub_server(object):
    def __init__(self):
        self.socks = None
        self.last_send = None
        self.conn = None
        self.gdb_addr = None
        self.need_checksum = True


    def start(self,host="127.0.0.1",port=1234):
        self.host = host
        self.port = port
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind((self.host, self.port))
        s.listen(1)
        self.socks = s
        if __DEBUG__ is True:print "Server listenning %s:%d" % (self.host,self.port)
        self.conn,self.gdb_addr = s.accept()
        if __DEBUG__ is True:print "connet from:",self.gdb_addr
        while True:
            data = self.conn.recv(4096+8)
            if len(data) == 0:
                conn.close()
                print "connect lost."
                break
            #handle with multi-thread
            Thread(target = self.sequence_handle, args =(data,)).start()



    def send(self, data):
        self.last_send = data
        pass

    def resend(self):
        self.send(self.last_send)

    def send_cmd(self, cmd_string):
        self.send("$%s#%s" % (cmd_string,checksum(cmd_string)))

    def sequence_handle(self,buf):
        if buf is None or len(buf)==0:
            print "Waring: buf is None or empty."
            return
        while len(buf) > 0:    
            if buf[0]=='-':
                if __DEBUG__:print "Got -, resend."
                self.resend()
                buf = buf[1:]
                continue
            if buf[0]=="$":
                if __DEBUG__:print "Got cmd, %s" % buf
                mobj = re.match(r'^\$([^#]+)#([0-9a-f]{2}$)', buf)
                if mobj is None:
                    print "Waring: Bad format cmd found! cmd= %s" % buf
                    continue
                
                cmd = mobj.groups()[0]
                chk_sum_value = mobj.groups()[1]

                if __DEBUG__:print "cmd = %s, checksum = %s" % (cmd, chk_sum_value)
                
                if len("$") + len(cmd) + len("#") + len(chk_sum_value) != len(buf):
                    print "Waring: multi-cmd received! buf= %s" % (buf)

                if checksum(cmd) != chk_sum_value:
                    print "Waring: checksum mismatch! checksum(cmd) = %s, chk_sum_value = %s" % (checksum(cmd), chk_sum_value)
                    self.send("-") #request gdb to send commmand again.
                    break #ignore this pack.
                

                self.cmd_handle(cmd)

    def cmd_handle(self, cmd):
        if cmd is None or len(cmd) < 1:
            print "Waring: cmd is None or empty! cmd = %s" % cmd
            self.send("-")
            return
        
        #ack, cmd received.
        self.send("+")
         
        if cmd == "Supported:multiprocess+;qRelocInsn+":
            self.send_cmd("PacketSize=1000;qXfer:features:read+")
            return
        
        if cmd == "Hg0":
            self.send_cmd("OK")
            return
        
        m  = re.match(r'qXfer:features:read:(.*\.xml).*', "qXfer:features:read:aarch64-core.xml:0,ffb")
        if m is not None and len(m.groups()) > 0:
            read_xml = "l"
            target_file = m.groups()[0]
            with open(target_file,"r") as f:
                read_xml = read_xml + f.read();
            self.send_cmd(read_xml)
            return
         
        print "Waring: cmd not handled! cmd = %s" % cmd
        

if __name__ == "__main__":
    server = Stub_server()
    server.start()
