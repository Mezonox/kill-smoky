#!/usr/bin/python



def Find(pat, text):
    import re
    match = re.search(pat,text)
    if match: print match.group()
    else: print 'not found! try again!'

if __name__ == "__main__":
    import sys
    Find((sys.argv[1]), sys.argv[2])