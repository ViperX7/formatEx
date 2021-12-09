# formatEx
This is a format string generator specifically to exploiting format string vulnerabilities in functions like printf/sprintf and such.
I wrote this a long time ago when i didn't know that pwntools provides a similar functionality. I still ocasionally maintain this script and use it for my
exploits you are welcome to use it for any purpose ,personally i think some parts of the code can be improved but it's surely a good example if you want to
study or automate your format string exploit generation.


# usage 
There are just three modes the first mode writes 4 bytes at a time,and the other two write 2 and 1 bytes respectively, which mode you want to use comes down to
what size of payload you want to generate and how much output you want the program to split

There are other handy arguments that you can use to calibrate for a concat operation and offsets
using `compact` or `safe` is recomended instead of `risky` if you want more stability
```python
import formatEx
pld = formatEx.write(content, shift=0, param_offset=7, context="risky")   
```
