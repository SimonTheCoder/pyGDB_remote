import binascii
import struct

__DEBUG__ = True

class Machine(object):
        

    def __init__(self):
        bit = self.get_machine_maxbits()
        if bit == 64 :self.reg_pack_char = "Q"
        if bit == 32 :self.reg_pack_char == "I"
    def _bin2hex(self,data):
        return binascii.b2a_hex(struct.pack(self.reg_pack_char,data))

    def get_machine_maxbits(self):
        return 64

    def read_reg(self,regnum):
        pass

    def get_regs(self):
        pass

    def write_reg(self,regnum,value):
        pass
    
    def read_mem(self,start,size):
        pass
    
    def write_mem(self,start,size,buf):
        pass

    def get_cpus(self):
        pass
    
    def get_cpu_info(self,cpunum):
        pass
    
    def run_break(self):
        pass
    
    def run_continue(self,addr):
        pass
     
    def run_single_step(self,addr):
        pass

    def set_single_inst(self):
        pass
        
    def read_mem_as_hexstr(self,addr,size):
        mem = self.read_mem(addr,size)
        if mem is None:
            return mem
        else:
            return binascii.b2a_hex(mem)

    def write_mem_as_hexstr(self,addr,size, buf):
        res = self.write_mem(addr,size,binascii.a2b_hex(buf))
        if res is None:
            return res
        else:
            return "OK"
    def read_reg_as_hexstr(self,regnum):
        reg = self.read_reg(regnum);
        return self._bin2hex(reg) 

    def get_regs_as_hexstr(self):
        regs = self.get_regs();
        hexstr = ""
        for reg in regs:
            hexstr = hexstr + self._bin2hex(reg)
        return hexstr
    def set_regs_with_hexstr(self,hexstr):
        binarr = binascii.a2b_hex(hexstr)
        binarr_split = [binarr[i:i+self.get_machine_maxbits()/8] for i in xrange(0,len(binarr),self.get_machine_maxbits()/8)]
        if __DEBUG__: print "@set_regs_with_hexstr: %d regs found. " % len(binarr_split)
        
        self.set_regs([struct.unpack(self.reg_pack_char,reg)[0] for reg in binarr_split])

class Dummy_machine(Machine):
    def __init__(self):
        super(Dummy_machine,self).__init__();

    
