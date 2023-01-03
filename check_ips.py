import sys
import getopt
import os

from check_ips_funcs import checkIPsFromFile, eprint

def printHelp():
    eprint("py check_ips.py -i <filename> [--throttle] [--output <filename>]")
    
def genFilename(input_file):
    name_list = input_file.split('.')[:-1]
    return ''.join(name_list) + "_filtered.txt"

# Parse command-line arguments
def main(argv):
    limited = False
    input_file = None
    output_file = None
    
    try:
        opts, args = getopt.getopt(argv, "hto:i:", ["help", "throttle", "input=", "output="])
    except getopt.GetoptError:
        printHelp()
        eprint(argv)
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp()
        elif opt in ("-t", "--throttle"):
            limited = True
        elif opt in ("-i", "--input"):
            input_file = os.path.normpath(arg)
        elif opt in ("-o", "--output"):
            output_file = os.path.normpath(arg)
    
    # Need input file
    if input_file == None:
        eprint("ERROR: No input file given")
        printHelp()
        exit(2)
    
    # If no output file is specified, generate one based on the input file.
    if output_file==None:
        output_file = genFilename(input_file)
    
    with open(output_file, "w") as f:
        checkIPsFromFile(input_file, limited=limited, ostream=f)
    

if __name__ == "__main__":
   main(sys.argv[1:])
   
