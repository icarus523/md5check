import hashlib
import sys
import os
import zipfile
import getopt
import getpass
from tkinter import filedialog
from collections import namedtuple
from datetime import datetime
from threading import Thread

MAXIMUM_BLOCKSIZE_TO_READ = 65535
p_reset = "\x08"*8

class md5check:

    def do_md5(self, file, blocksize=2**20): # optimal block size for md5sum
        m = hashlib.md5()
        done = 0
        size = os.path.getsize(file)
        with open(file, "rb" ) as f: # binary important
            while True:
                buf = f.read(blocksize)
                done += blocksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not buf:
                    break
                m.update( buf )
        return m.hexdigest()

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

    def pprinttable(self, rows, outfile="default_signed_output.txt"):
        if len(rows) > 1:
            headers = rows[0]._fields
            lens = []
            for i in range(len(rows[0])):
                lens.append(len(max([x[i] for x in rows] + [headers[i]],key=lambda x:len(str(x)))))
            formats = []
            hformats = []
            for i in range(len(rows[0])):
                if isinstance(rows[0][i], int):
                    formats.append("%%%dd" % lens[i])
                else:
                    formats.append("%%-%ds" % lens[i])
                    hformats.append("%%-%ds" % lens[i])
            pattern = " | ".join(formats)
            hpattern = " | ".join(hformats)
            separator = "-+-".join(['-' * n for n in lens])
            if (self.signfile == True):
                with open (outfile, 'w') as f:
                    f.write("File generated on: " + str(datetime.now()) + " by: " + getpass.getuser() + "\n")
                    f.write(hpattern % tuple(headers) + "\n")
                    f.write(separator + "\n")
            else:
                print(hpattern % tuple(headers))
                print(separator)
            for line in rows:
                if (self.signfile == True):
                    with open (outfile, 'a') as f:
                        f.write(pattern % tuple(line) + "\n")
                else: 
                    print(pattern % tuple(line))
        elif len(rows) == 1:
            row = rows[0]
            hwidth = len(max(row._fields,key=lambda x: len(x)))
            for i in range(len(row)):
                if (self.signfile == True):
                    with open (outfile, 'a') as f:
                        f.write(("%*s = %s" % (hwidth,row._fields[i],row[i])))
                else:    
                    print ("%*s = %s" % (hwidth,row._fields[i],row[i]))

    def compareresult(self, text):
        strcompare = str(text).upper().strip(' ')
        with open(os.path.join(self.currentdir, self.filename_md5), 'r') as f:
            md5text = f.read().upper().strip(' ,\n,\r')
            textfixed = str(text).upper().strip(' ')
            
            Row = namedtuple('Row',['Filename','Expected_md5_checksum','Calculated_md5_checksum'])
            self.data = Row(self.filename_md5, md5text, textfixed)
            self.dataempty = Row("-", "-", "-")
            self.pprinttable([self.data, self.dataempty], os.path.join(self.currentdir, self.signfilename))

            if textfixed == md5text:
                return True
            else:
                return False

    def processfile(self):
        #NUMBER_OF_BYTES_TO_READ = 128
        h = self.do_md5(self.filepath_zip, MAXIMUM_BLOCKSIZE_TO_READ)
        matches = self.compareresult(h)

        if (matches):
            print("Matches!")
        else:
            print("Doesn't match! - Abort!")
            sys.exit(1)

        # Unzip archive
        if (self.unzipflag == True):
            print("Unzipping file...Please Wait.")
            #Thread(target=self.unzip(self.filepath_zip, self.currentdir)).start()
            self.unzip(self.filepath_zip, self.currentdir)
        # Add SHA1 hash calc over the generated file     
        if (self.signfile == True):
            print("Signing file..." + self.signfilename)
            self.signfileoutput(os.path.join(self.currentdir, self.signfilename), os.path.join(self.currentdir, self.signfilename))

    def signfileoutput(self, infile, outfile):
        h = self.dohash_sha1(infile)
        if h:
            self.appendfileoutput(h, outfile)

    def appendfileoutput(self, signature, outfile):                
        with open (outfile, 'a') as f:
            f.write("#---8<---------------------------------START--------------------------------------------\n")
            f.write("# Remove this section to verify hash for: " + os.path.basename(outfile) + "\n")
            f.write("# SHA1 hash: " + signature.upper() + "\n")
            f.write("# IMPORTANT! To reconcile make sure there's an empty line at the bottom of this text file\n")
            f.write("# ---------------------------------------END------------------------------------->8------")

    def unzip(self, source_filename, dest_dir):
        with zipfile.ZipFile(source_filename) as zf:          
            uncompress_size = sum((file.file_size for file in zf.infolist())) 
            extracted_size = 0
            #print('uncompressed size: ' + str(uncompress_size) + ' bytes')
            
            for file in zf.infolist():
                extracted_size += file.file_size
                percentage = extracted_size * 100/uncompress_size
		#self.pBar["value"] = percentage
                print("%6.2f %%\r" % (float(percentage)))
                zf.extract(file, dest_dir)
    
    def handlearguments(self):       
        if (os.path.isfile(self.filepath_zip)):
            if (self.runverify == False):
                self.filename_zip =  os.path.basename(self.filepath_zip)
                self.filename_md5 = self.filename_zip.rstrip("zip") + "md5"
                self.currentdir = os.path.dirname(self.filepath_zip)
                print("Processing: " + self.filename_zip +
                       " and " + self.filename_md5)
                self.signfilename = self.filename_zip[:-4] + '_signed_output.sigs'
                # Start Thread for ProcessFile()
                Thread(target=self.processfile()).start()
            else:
                self.currentdir = os.path.dirname(self.filepath_zip)
                # Start Thread for Verify File()
                Thread(target=self.verifyfile(self.filepath_zip)).start()
        else:
            print("Expecting to read file: <" + self.filepath_zip + "> " + 
                "Please confirm input parameters.")
            sys.exit(2)

    def stripfile(self, fname, outfile="tmp.txt"):
        
        with open(fname,'r') as oldfile, open (os.path.join(self.currentdir, outfile), 'w+') as newfile:
            for line in oldfile:
                if line.startswith('#'):
                    continue # skip 
                newfile.write(line)
        return os.path.join(self.currentdir,outfile)

    def verifyfile(self, fname):
        if (fname.upper().endswith('.SIGS')):
            h = self.dohash_sha1(self.stripfile(fname))
            print("Filename: " + os.path.basename(fname))
            print("SHA1 Hash Recalculated: " + str(h).upper())
        else:
            print("Expected a .sigs file, verify input file")
            sys.exit(2)

    def askforfile(self):
        tmp = filedialog.askopenfile(initialdir='.')
        if tmp:
            self.filepath_zip = tmp.name
            self.filename_zip = os.path.basename(self.filepath_zip)
            self.currentdir = os.path.dirname(self.filepath_zip)
            self.filename_md5 = self.filename_zip.rstrip("zip") + "md5"
            if (self.runverify == True):
                print("Verifying: " + self.filepath_zip)
            else: 
                print("Processing: " + self.filename_zip + " and " + self.filename_md5)

        self.signfilename = self.filename_zip[:-4] + '_signed_output.sigs'

        if (self.runverify == True):
            #Thread(target=self.verify(self.filepath_zip)).start()
            self.verify(self.filepath_zip)
        else:
            Thread(target=self.processfile()).start()

    def __init__(self):
        self.filename_zip = ''
        self.filepath_zip = ''
        self.filename_md5 = ''
        self.signfile = False
        self.rungui = False
        self.unzipflag = False
        self.runverify = False
        
        try:
            opts, args = getopt.getopt(sys.argv[1:], "v:i:zgsh",["verify=","input=","unzip","gui","sign_out"])
            
            for opt, arg in opts:
                if opt == '-h':
                    print('Usage: md5check.py --unzip --gui --sign_out --input <input filename> --verify <input filename>')
                    print('    where: --unzip or -z      will attempt to unzip input file')
                    print('           --gui or -g        will display a File Chooser window to select the file')
                    print('           --sign_out or -s   generates a SHA1 hash file output')
                    print('           --input or -i      the ZIP file to be processed')
                    print('           --verify or -v     will attempt to verify the sigs file')
                    sys.exit()
                elif opt in ("-i", "--input"):
                    self.filepath_zip = arg
                elif opt in ("-z", "--unzip"):
                    self.unzipflag = True
                elif opt in ("-g", "--gui"):
                    self.rungui = True
                elif opt in ("-s", "--sign_out"):
                    self.signfile = True
                elif opt in ("-v", "--verify"):
                    self.filepath_zip = arg
                    self.runverify = True

            if self.rungui == True:
                Thread(target=self.askforfile()).start()
            else:
                self.handlearguments()

        except getopt.GetoptError:
            print('try: md5check.py -h for more info or')
            print ('md5check.py --unzip --gui --sign_out --input <input filename>')
            sys.exit(2)

def main():
    if (len(sys.argv) < 1):
        print('not enough parameters passed - try -h for more info')
        sys.exit(2)
    else: 
        app = md5check()

if __name__ == "__main__": main()

