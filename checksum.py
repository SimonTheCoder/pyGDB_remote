#!/usr/bin/python

def checksum(target):
    sum = 0;
    if target is None or len(target) == 0:
        return "00"
    for c in target:
        sum += ord(c);
    result= "%02x" %( sum % 256);
    return result


if __name__ == '__main__':
    #result should be '2a'
    print checksum("qSupported:multiprocess+;qRelocInsn+")

    #result should be '09'
    print checksum("Hc-1")
