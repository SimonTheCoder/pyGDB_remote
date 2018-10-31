from unicorn import *
from unicorn.arm64_const import *

import machine

__DEBUG__ = True

class Mem_map(object):
    def __init__(self):
        pass
    
    def find_region(start,size):
        pass


class Unicorn_machine(machine.Machine):
    uc_gen_regs = [
    unicorn.arm64_const.UC_ARM64_REG_X0,
    unicorn.arm64_const.UC_ARM64_REG_X1,
    unicorn.arm64_const.UC_ARM64_REG_X2,
    unicorn.arm64_const.UC_ARM64_REG_X3,
    unicorn.arm64_const.UC_ARM64_REG_X4,
    unicorn.arm64_const.UC_ARM64_REG_X5,
    unicorn.arm64_const.UC_ARM64_REG_X6,
    unicorn.arm64_const.UC_ARM64_REG_X7,
    unicorn.arm64_const.UC_ARM64_REG_X8,
    unicorn.arm64_const.UC_ARM64_REG_X9,
    unicorn.arm64_const.UC_ARM64_REG_X10,
    unicorn.arm64_const.UC_ARM64_REG_X11,
    unicorn.arm64_const.UC_ARM64_REG_X12,
    unicorn.arm64_const.UC_ARM64_REG_X13,
    unicorn.arm64_const.UC_ARM64_REG_X14,
    unicorn.arm64_const.UC_ARM64_REG_X15,
    unicorn.arm64_const.UC_ARM64_REG_X16,
    unicorn.arm64_const.UC_ARM64_REG_X17,
    unicorn.arm64_const.UC_ARM64_REG_X18,
    unicorn.arm64_const.UC_ARM64_REG_X19,
    unicorn.arm64_const.UC_ARM64_REG_X20,
    unicorn.arm64_const.UC_ARM64_REG_X21,
    unicorn.arm64_const.UC_ARM64_REG_X22,
    unicorn.arm64_const.UC_ARM64_REG_X23,
    unicorn.arm64_const.UC_ARM64_REG_X24,
    unicorn.arm64_const.UC_ARM64_REG_X25,
    unicorn.arm64_const.UC_ARM64_REG_X26,
    unicorn.arm64_const.UC_ARM64_REG_X27,
    unicorn.arm64_const.UC_ARM64_REG_X28,
    unicorn.arm64_const.UC_ARM64_REG_X29,
    unicorn.arm64_const.UC_ARM64_REG_X30,
    unicorn.arm64_const.UC_ARM64_REG_SP,
    unicorn.arm64_const.UC_ARM64_REG_PC
    ]

    uc_nzcv_reg = unicorn.arm64_const.UC_ARM64_REG_NZCV
    


    def __init__(self,write_auto_map = True):
        super(Unicorn_machine, self).__init__()
        self.mu = Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        self.write_auto_map = write_auto_map        
        if __DEBUG__:
            #map a test area
            self.mu.mem_map(0xfffffffffffff000, 4*1024)

    def read_reg(regnum):
        pass

    def write_reg(regnum,value):
        pass

    def get_regs(self):
        regs = list()
        for reg_name in Unicorn_machine.uc_gen_regs:
            regs.append(self.mu.reg_read(reg_name))
        
        nzcv = self.mu.reg_read(Unicorn_machine.uc_nzcv_reg)
        #TODO OR system status to nzcv to get a CPSR
        cpsr = nzcv | 0x0000000000000000
        regs.append(cpsr)
        return regs

    def set_regs(self,regs):
        cur_index = 0
        for reg_name in Unicorn_machine.uc_gen_regs:
            self.mu.reg_write(reg_name, regs[cur_index])
            cur_index = cur_index + 1
         
        self.mu.reg_write(Unicorn_machine.uc_nzcv_reg, regs[cur_index])

    def read_mem(self,start,size):
        try:
            mem = self.mu.mem_read(start,size)
        except UcError,e:
            print "Waring:[%s] read bad address=0x%x size=0x%x" % (e,start,size)
            return None
        return mem
    
    def write_mem(self,start,size,buf):
        try:
            self.mu.mem_write(start,buf)
        except UcError,e:
            print "Waring:[%s] write bad address=0x%x size=0x%x len(buf)=0x%x" % (e,start,size,len(buf))
            if self.write_auto_map:
                tunc_addr = start & 0xfffffffffffff000
                round_size = ((size+start-tunc_addr-1) & 0xfffffffffffff000)+0x1000;
                if __DEBUG__:print "But write_auto_map is on. let's map it automaticly. addr = 0x%x size = 0x%x" % (tunc_addr,round_size)
                try:
                    for i in self.mu.mem_regions():
                       if tunc_addr <= i[1] and tunc_addr >= i[0]:
                       #some area already mapped...
                           round_size = round_size - (i[1]-tunc_addr) - 1
                           tunc_addr = i[1] + 1
                           break
                    
                    if __DEBUG__:print "addjusted . addr = 0x%x size = 0x%x" % (tunc_addr,round_size)
                    if round_size < 4090:
                        print "Waring: no need to map!!!!"
                        #round_size = 4096
                    self.mu.mem_map(tunc_addr,round_size)
                except UcError,e:
                    print "Waring:[%s]  auto map failed can not write!!! " % e
                    for i in self.mu.mem_regions():
                        print "start 0x%x end 0x%x flag 0x%x" % i
                try:
                    self.mu.mem_write(start,buf)
                    return "OK"
                except UcError,e:
                    print "Waring:[%s] still can not write!!! " % e
                    return None
            return None
        return "OK"  
    
    def run_continue(self,start_addr):
        if start_addr is None:
            start_addr = self.mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        if __DEBUG__:print "unicorn i ki ma su. addr=0x%x" % start_addr    
        try:
            self.mu.emu_start(start_addr, 0xffffffffffffffff)
        except UcError,e:
            print "Waring:[%s] continue failed." % e
            return None
        return "OK"    
    def get_cpus():
        pass
    
    def get_cpu_info():
        pass

    def get_current_el():
        pass

if __name__ == "__main__":
    print "begin test."
    ma = Unicorn_machine()
    print "::::::::::::::::::::::"
    print "get_regs test start."
    ma.mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0,0x1122334455667788)
    print ma.get_regs()
    print ma.get_regs_as_hexstr()
    print len(ma.get_regs_as_hexstr())
    print "set_regs test start."
    hexstr = "00f0debc8a674523000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000"
    ma.set_regs_with_hexstr(hexstr)
    print ma.get_regs()
