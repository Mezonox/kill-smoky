#!/usr/bin/python

import getopt
import sys

shortopts = "ho:v"
longopts = ["help", "output="]

def main():
    parseCommandLine()
    
def useage():
    print "Do it better!"    
    
def parseCommandLine():
    try: 
        opts,args = getopt.getopt(sys.argv[1:], shortopts , longopts)
    except getopt.GetoptError as err:
        #pint help info and exit
        print(err)
        useage()
        sys.exti(2)
    output = None
    verbose = False
    for o,a in opts:
        if o == "-v":
            verbose = True
        elif o in ("-h", "--help"):
            useage()
            sys.exit()
        elif o in ("-o", "--output"):
            output = a
        else:
            assert False, "unhandled option"
                    


if __name__ == '__main__':
    main()