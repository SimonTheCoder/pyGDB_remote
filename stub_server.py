
import re
import socket

from checksum import checksum 
from threading import Thread,currentThread,activeCount

__DEBUG__ = True

class Stub_server(object):
    def __init__(self, machine):
        self.socks = None
        self.last_send = None
        self.conn = None
        self.gdb_addr = None
        self.need_checksum = True
        self.RECV_SIZE = 16388 
        self.machine = machine


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
            data = self.conn.recv(self.RECV_SIZE)
            if __DEBUG__:print "--> %s" % data
            if len(data) == 0:
                self.conn.close()
                print "connect lost."
                break
            ##handle with multi-thread
            #Thread(target = self.sequence_handle, args =(data,)).start()
            self.sequence_handle(data)


    def send(self, data):
        self.last_send = data
        if __DEBUG__:print "<-- %s" % data 
        self.conn.sendall(data)
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
            if buf[0]=="+":
                buf = buf[1:]
                continue
            if buf[0]=="\x03":
                if __DEBUG__:print "recv \\x03, break."
                buf = buf[1:]
                self.machine.run_break()
                #self.send_cmd("T02thread:01;")
                continue
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
                break

    def cmd_handle(self, cmd):
        if cmd is None or len(cmd) < 1:
            print "Waring: cmd is None or empty! cmd = %s" % cmd
            self.send("-")
            return
        
        #ack, cmd received.
        self.send("+")
        m = None 
        m = re.match(r'qSupported:(.*)',cmd) #qSupported:multiprocess+;qRelocInsn+":
        if m is not None:
            self.send_cmd("PacketSize=%x;qXfer:features:read+" % (self.RECV_SIZE - 4))
            return
        
        if cmd == "Hg0":
            self.send_cmd("OK")
            return
        m = None
        m = re.match(r'qXfer:features:read:(.*\.xml).*', cmd)
        if m is not None and len(m.groups()) > 0:
            read_xml = "l"
            target_file = m.groups()[0]
            with open(target_file,"r") as f:
                read_xml = read_xml + f.read();
            self.send_cmd(read_xml)
            return
        if cmd == "qAttached":
            self.send_cmd("1")
            return
        if cmd == "qOffsets":
            self.send_cmd("")
            return
        if cmd == "?":
            self.send_cmd("T05thread:01;")
            return
        if cmd == "Hc-1":
            self.send_cmd("OK")
            return
        if cmd == "qfThreadInfo":
            self.send_cmd("m1")
            return
        if cmd == "qsThreadInfo":
            self.send_cmd("l")
            return
        if cmd == "g":
           #self.send_cmd("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008100000000cd030040")
           #print len("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008100000000cd030040")
           self.send_cmd(self.machine.get_regs_as_hexstr())
           return
        m = re.match(r'G([0-9a-fA-F]+)',cmd)
        if m is not None:
            hexstr = m.groups()[0]
            self.machine.set_regs_with_hexstr(hexstr)

        m = re.match(r'm([a-fA-F0-9]+),([0-9a-fA-F]+)',cmd)
        if m is not None:
            if __DEBUG__:print "reading mem: %x size: %d" % (int(m.groups()[0],16), int (m.groups()[1],16))
            #self.send_cmd("00000000")
            read_str = self.machine.read_mem_as_hexstr(int(m.groups()[0],16), int (m.groups()[1],16))
            if read_str is None:
                self.send_cmd("E00")
            else:
                self.send_cmd(read_str)
            return
        m = re.match(r'M([a-fA-F0-9]+),([0-9a-fA-F]+):([0-9a-fA-F]+)',cmd)
        if m is not None:
            if __DEBUG__:print "write mem: %x size: %d" % (int(m.groups()[0],16), int (m.groups()[1],16))
            #self.send_cmd("00000000")
            write_res = self.machine.write_mem_as_hexstr(int(m.groups()[0],16), int (m.groups()[1],16),m.groups()[2] )
            if write_res is None:
                self.send_cmd("E00")
            else:
                self.send_cmd("OK")
            return
        
        m = re.match(r'c([0-9a-fA-F]*)',cmd)
        if m is not None:
            if __DEBUG__:print "continue!"
            addr = m.groups()[0]
            if addr is None or len(addr) == 0:
                addr = None
            else:
                addr = int(addr,16)
            def run_continue_thread_func():
                res = self.machine.run_continue(addr)
                if res is None:
                    self.send_cmd("E00")
                else:    
                    self.send_cmd("T05thread:01;")
            Thread(target = run_continue_thread_func, args=()).start()    
            return
        
        if cmd == "s":
            self.machine.set_single_inst()
            def run_continue_thread_func():
                res = self.machine.run_continue(None)
                if res is None:
                    self.send_cmd("E00")
                else:
                    self.send_cmd("T05thread:01;")
            Thread(target = run_continue_thread_func, args=()).start()
            return
        print "Waring: cmd not handled! cmd = %s" % cmd
        self.send_cmd("") 

if __name__ == "__main__":
    import unicorn_machine
    um = unicorn_machine.Unicorn_machine()
    server = Stub_server(um)
    server.start()
