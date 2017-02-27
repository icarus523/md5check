import hashlib
import sys
import os
import getopt

class md5sigsverify:
	
    # input: file to be hashed using sha1()
    # output: hexdigest of input file    
    def dohash_sha1(self, fname, chunksize=8192): 
        m = hashlib.sha1()         

        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                block = f.read(chunksize)
                if not block: break
                m.update(block)    

        return m.hexdigest()
            
    def stripfile(self, fname, outfile="tmp.txt"):
        with open(fname,'r') as oldfile, open (outfile, 'w+') as newfile:
            for line in oldfile:
                if line.startswith('#'):
                    continue # skip 
                newfile.write(line)
        return outfile
    
    def processfile(self, fname):
        # 1. Strip file
        # 2. Hash file
        h = self.dohash_sha1(self.stripfile(fname))
        # 3. Print generated hash
        print("Filename: " + fname)
        print("SHA1 Hash Recalculated: " + str(h).upper())
    
    def __init__(self):
        self.filepath_sigs = ''
        
        try:
            opts, args = getopt.getopt(sys.argv[1:], "i:",["input="])
            
            for opt, arg in opts:
                if opt == '-h':
                    print('Usage: md5sigverify.py --input <input filename>')
                    print('    where: --input or -i      the .sigs file to be verified')
                    sys.exit(0)
                elif opt in ("-i", "--input"):
                    self.filepath_sigs = arg
            
            if (os.path.isfile(self.filepath_sigs)):
                self.processfile(self.filepath_sigs)
            else: 
                print('Error. Expected a file, check your input parameters')
                sys.exit(1)

        except getopt.GetoptError:
            print('try: md5sigverify.py --input <input filename>')
            sys.exit(2)

def main():
    if (len(sys.argv) < 1):
        print('not enough parameters passed - try -h for more info')
        sys.exit(2)
    else: 
        app = md5sigsverify()

if __name__ == "__main__": main()