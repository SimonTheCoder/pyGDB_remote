#!/usr/bin/python

def checksum(target):
    sum = 0;
    for c in target:
        sum += ord(c);
    result= "%2x" %( sum % 256);
    return result


if __name__ == '__main__':
    #result shoud be '2a'
    print checksum("qSupported:multiprocess+;qRelocInsn+")
