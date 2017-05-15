import hashlib
import sys
import os
import zipfile
import getopt
import getpass
import logging

from collections import namedtuple
from datetime import datetime
from threading import Thread

from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

MAXIMUM_BLOCKSIZE_TO_READ = 65535
p_reset = "\x08"*8
VERSION="1.1 (GUI version)" # GUI version

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

    def processfile(self, filepath_zip):
        #h = self.do_md5(self.filepath_zip, MAXIMUM_BLOCKSIZE_TO_READ)
        h = self.do_md5(filepath_zip, MAXIMUM_BLOCKSIZE_TO_READ)
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
            self.unzip(filepath_zip, self.currentdir)
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
        Submission = {}
        self.SubmissionList = list()
        for item in self.filepath_zip:
            logging.debug("Item is: " + item + ". Filepath_zip is: " + self.filepath_zip)
            if (os.path.isfile(str(item))):
                if (self.runverify == False):
                    self.filename_zip =  os.path.basename(item)
                    submission = {
                        'filename_zip' : os.path.basename(item),
                        'filename_md5' : os.path.basename(item).rstrip("zip") + "md5",
                        'currentdir' : os.path.dirname(self.filepath_zip)
                    }
                    self.SubmissionList.append(submission)
                    #self.filename_md5 = self.filename_zip.rstrip("zip") + "md5"
                    #self.currentdir = os.path.dirname(self.filepath_zip)
                    #print("Processing: " + self.filename_zip +
                    #       " and " + self.filename_md5)
                    logging.info("Processing: " + submission[filename_zip] +
                           " and " + submission[filename_md5])
                    self.signfilename = self.filename_zip[:-4] + '_signed_output.sigs'
                    # Start Thread for ProcessFile()
                    Thread(target=self.processfile(item)).start()
                else:
                    self.currentdir = os.path.dirname(item)
                    # Start Thread for Verify File()
                    Thread(target=self.verifyfile(item)).start()
            else:
                logging.error("Expecting to read file: <" + item + "> " + 
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

        for item in self.filename_zip: # handle multiple inputs
            #self.signfilename = self.filename_zip[:-4] + '_signed_output.sigs'
            self.signfilename = item[:-4] + '_signed_output.sigs'

            if (self.runverify == True):
            #Thread(target=self.verify(self.filepath_zip)).start()
                #self.verify(self.filepath_zip)
                self.verify(self.filepath_zip)
            else:
                Thread(target=self.processfile(item)).start()

    def __init__(self):
        self.filename_zip = ''
        self.filepath_zip = ''
        self.filename_md5 = ''
        self.signfile = False
        self.rungui = False
        self.unzipflag = False
        self.runverify = False
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')
        logging.debug('Start of md5check')

        self.root = Tk()
        self.setupGUI()

##        try:
##            opts, args = getopt.getopt(sys.argv[1:], "v:i:zgsh",["verify=","input=","unzip","gui","sign_out"])
##            
##            for opt, arg in opts:
##                if opt == '-h':
##                    print('Usage: md5check.py --unzip --gui --sign_out --input <input filename> --verify <input filename>')
##                    print('    where: --unzip or -z      will attempt to unzip input file')
##                    print('           --gui or -g        will display a File Chooser window to select the file')
##                    print('           --sign_out or -s   generates a SHA1 hash file output')
##                    print('           --input or -i      the ZIP file to be processed')
##                    print('           --verify or -v     will attempt to verify the sigs file')
##                    sys.exit()
##                elif opt in ("-i", "--input"):
##                    self.filepath_zip = arg
##                elif opt in ("-z", "--unzip"):
##                    self.unzipflag = True
##                elif opt in ("-g", "--gui"):
##                    self.rungui = True
##                elif opt in ("-s", "--sign_out"):
##                    self.signfile = True
##                elif opt in ("-v", "--verify"):
##                    self.filepath_zip = arg
##                    self.runverify = True
##
##            if self.rungui == True:
##                Thread(target=self.askforfile()).start()
##            else:
##                self.handlearguments()
##
##        except getopt.GetoptError:
##            print('try: md5check.py -h for more info or')
##            print ('md5check.py --unzip --gui --sign_out --input <input filename>')
##            sys.exit(2)

    def setupGUI(self):
        self.root.wm_title("md5check v" + VERSION)
        self.root.resizable(0,0)

        ################ Top Frame ################
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = TOP, fill=X, expand=False)
        frame_toparea.config(relief = RIDGE, borderwidth = 3)
        
        ttk.Label(frame_toparea, justify=LEFT,
                  text = 'This script verifies the MD5 Hashes of XML Submissions').grid(row = 0, columnspan=2, padx=3, pady=3)

        # Button to Select Archive Files
        button_Choose_TAB_delimited_file = ttk.Button(frame_toparea, text = "Select Archive Files...",
                                                      command = lambda: self.handleButtonPress('__tab_delimited_file__'))                                             
        button_Choose_TAB_delimited_file.grid(row=1, column=0, padx=3, pady=3, sticky='w')

        # Text Area - Archive File List
        self.archive_filelist_tf = Text(frame_toparea, width = 50, height=10)
        self.archive_filelist_tf.grid(row=2, column=0)

        ################ Bottom FRAME ##############
        frame_bottombuttons = ttk.Frame(self.root)
        frame_bottombuttons.pack(side=BOTTOM, fill=X, expand = False)
        frame_bottombuttons.config(relief = RIDGE, borderwidth = 3)
               
        # Check Button - Unzip Archive
        self.unzipcheck = IntVar()
        self.unzipcheck.set(0)
        self.cb_unzipcheck = Checkbutton(frame_bottombuttons, 
            text="Unzip Archive", 
            justify=LEFT, 
            variable = self.unzipcheck, 
            onvalue=1, 
            offvalue=0)
        self.cb_unzipcheck.grid(row=0, column=0, sticky='e',)

        # Check Button - Sign Archive
        self.signcheck = IntVar()
        self.signcheck.set(1)
        self.cb_signcheck = Checkbutton(frame_bottombuttons, 
            text="Sign Output", 
            justify=LEFT, 
            variable = self.signcheck, 
            onvalue=1, 
            offvalue=0)
        self.cb_signcheck.grid(row=0, column=1, sticky='e',)

        # Check Button - Verify
        self.verifycheck = IntVar()
        self.verifycheck.set(0)
        self.cb_verifycheck = Checkbutton(frame_bottombuttons, 
            text="Verify Signature Archives", 
            justify=LEFT, 
            variable = self.verifycheck, 
            onvalue=1, 
            offvalue=0)
        self.cb_verifycheck.grid(row=0, column=2, sticky='e',)

##        # Text Entry       
##        self.current_tsl_filename_tf = ttk.Entry(self.root, width = 50)
##        self.current_tsl_filename_tf.grid(row=2, column=1)
##
##        ttk.Label(self.root, text = 'Enter new TSL filename: ').grid(row = 3, column=0, sticky='e', padx=3, pady=3)
##
##        self.v = StringVar()
##        self.v.set("qcas_2015_05_v02.tsl")
##        self.new_tsl_filename_tf = ttk.Entry(self.root, width = 50, textvariable=self.v)
##        self.new_tsl_filename_tf.grid(row=3, column=1, padx=3, pady=3)
##
##        # Button
##        button_start = ttk.Button(self.root, text = "Start...",
##                                  command = lambda: self.handleButtonPress('__start__'))
##        button_start.grid(row=4, columnspan=2, sticky='se', padx=5, pady=5)        
        self.root.mainloop()

def main():
    if (len(sys.argv) < 1):
        print('not enough parameters passed - try -h for more info')
        sys.exit(2)
    else: 
        app = md5check()

if __name__ == "__main__": main()

