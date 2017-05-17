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
            # Display Results
            logging.info(hpattern % tuple(headers))
            logging.info(separator)

            if (self.signfile.get() == 1):
                with open (outfile, 'w') as f:
                    f.write("File generated on: " + str(datetime.now()) + " by: " + getpass.getuser() + "\n")
                    f.write(hpattern % tuple(headers) + "\n")
                    f.write(separator + "\n")

            for line in rows:
                logging.info(pattern % tuple(line))
                if (self.signfile.get() == 1):
                    with open (outfile, 'a') as f:
                        f.write(pattern % tuple(line) + "\n")
                        
        elif len(rows) == 1:
            row = rows[0]
            hwidth = len(max(row._fields,key=lambda x: len(x)))
            for i in range(len(row)):
                logging.info ("%*s = %s" % (hwidth,row._fields[i],row[i]))
                if (self.signfile.get() == 1):
                    with open (outfile, 'a') as f:
                        f.write(("%*s = %s" % (hwidth,row._fields[i],row[i])))

    def compareresult(self, text, currentdir, filename_md5, signfilename):
        strcompare = str(text).upper().strip(' ')
        with open(os.path.join(currentdir, filename_md5), 'r') as f:
            md5text = f.read().upper().strip(' ,\n,\r')
            textfixed = str(text).upper().strip(' ')
            
            Row = namedtuple('Row',['Filename','Expected_md5_checksum','Calculated_md5_checksum'])
            self.data = Row(filename_md5, md5text, textfixed)
            self.dataempty = Row("-", "-", "-")
            self.pprinttable([self.data, self.dataempty], os.path.join(currentdir, signfilename))

            if textfixed == md5text:
                return True
            else:
                return False

    def processfile(self, filepath_zip, currentdir, signfilename, filename_md5):
        h = self.do_md5(filepath_zip, MAXIMUM_BLOCKSIZE_TO_READ)
        
        matches = self.compareresult(h, currentdir, filename_md5, signfilename)

        if (matches):
            messagebox.showinfo("Expected Hash Matches", "Calculated MD5 Hash: " + h.upper() + "\nMatches with expected MD5 Hash!")
            logging.debug("Matches!")
        
             # Unzip archive
            if (self.unzipflag.get() == 1):
                logging.info("Unzipping file..." + filepath_zip)
                Thread(target=self.unzip(filepath_zip, currentdir)).start()
                #self.unzip(filepath_zip, currentdir) # Too slow remove threading
        
            # Add SHA1 hash calc over the generated file     
            if (self.signfile.get() == 1):
                logging.info("Signing file..." + signfilename)
                self.signfileoutput(os.path.join(currentdir, signfilename), os.path.join(currentdir, signfilename))
        else:
            messagebox.showinfo("Expected Hash Did Not Match!", "Calculated MD5 Hash:" + h + ", Failed when compared with expected MD5 Hash!")
            logging.critical("Doesn't match! - Abort!")
            #sys.exit(0)

       

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
            logging.debug('uncompressed size: ' + str(uncompress_size) + ' bytes')
            
            for file in zf.infolist():
                extracted_size += file.file_size
                percentage = extracted_size * 100/uncompress_size #file.filename + 
                logging.info("%-30s %6.2f %%\r" % ( file.filename, float(percentage)))
                zf.extract(file, dest_dir)
    
    def handlearguments(self):
        for item in self.archive_filelist:
            logging.debug("Processing File: " + item)
            if (os.path.isfile(str(item))):
                if (self.signfile.get() == 1):
                    filename_zip =  os.path.basename(item)
                    filename_md5 = filename_zip.rstrip("zip") + "md5"
                    currentdir = os.path.dirname(item)

                    logging.info("Processing: " + filename_zip +
                           " and " + filename_md5)
                    
                    signfilename = filename_zip[:-4] + '_signed_output.sigs'

                    # Start Thread for ProcessFile()
                    Thread(target=self.processfile(item, currentdir, signfilename, filename_md5)).start()
                
                if self.runverify.get() == 1:
                    logging.info("Verifying SIGS file Mode")
                    # Verify SIGS
                    self.currentdir = os.path.dirname(item)
                    # Start Thread for Verify File()
                    Thread(target=self.verifyfile(item)).start()
            else:
                logging.critical("Expecting to read file: <" + item + "> " + 
                    "Please confirm file input.")

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
            logging.info("Filename: " + os.path.basename(fname))
            logging.info("SHA1 Hash Recalculated: " + str(h).upper())
            # We uppercase in Written SIGS file, make sure you uppercase before comparing
            if h.upper() in open(os.path.basename(fname)).read(): # HAX0Rs
                messagebox.showinfo("SIGS File Verified!", "Calculated SHA1 Hash:" + h.upper() 
                    + ",\nMatches with expected Hash in SIGS file")
                logging.info("SIGS file: Verified")
            else: 
                messagebox.showinfo("SIGS File Unverifiable!", "Calculated SHA1 Hash:" 
                    + h.upper() + ",\nDid not matches with expected Hash in SIGS file!\n\nFAIL!")
                logging.info("SIGS file: Verified")    
        else:
            logging.error("Expected a .SIGS file, If verifying mode make sure to select a SIGS file instead.")

    def __init__(self):
        self.filename_zip = ''
        self.filepath_zip = ''
        self.filename_md5 = ''
        self.rungui = False
        self.Archive_Filename_List = list()
        self.logging_choice = logging.DEBUG

        logging.basicConfig(level= self.logging_choice, format=' %(asctime)s - %(levelname)s- %(message)s')
        logging.debug('Start of md5check.py')

        self.root = Tk()
        self.setupGUI()

    def setupGUI(self):
        self.root.wm_title("md5check v" + VERSION)
        self.root.resizable(0,0)

        ################ Top Frame ################
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = TOP, padx = 3, pady=3,  fill=X, expand=False)
        frame_toparea.config(relief = FLAT, borderwidth = 3)
        
        ttk.Label(frame_toparea, justify=CENTER,
                  text = 'This script verifies the MD5 Hashes of LTFO XML Submissions').pack(side=TOP, padx=3, pady=3, fill=X, expand=True, anchor='n')        

        # Radio Button modes
        MODES = [
            ("Generate SIGS File", "1"),
            ("Verify SIGS File","2"),
        ]
        self.vars_rb_mode = IntVar()
        self.vars_rb_mode.set(1)
        self.runverify = IntVar()
        self.runverify.set(0)
        self.signfile = IntVar()
        self.signfile.set(1)


        frame_mode = ttk.Frame(frame_toparea)
        frame_mode.pack(side=TOP, fill=X, expand = True)
        frame_mode.config(relief=FLAT, borderwidth=3)
        Label(frame_mode, text="1. Select Mode: ").pack(side = LEFT, anchor="w", padx=3, pady = 3, fill=X, expand=False) 
        for text, mode in MODES:
            b = ttk.Radiobutton(frame_mode, text=text, variable=self.vars_rb_mode, value=mode, command=self.HandleRadioButton)
            b.pack(side = LEFT, anchor="w")

        frame_Header = ttk.Frame(frame_toparea)
        frame_Header.pack(side = TOP, padx = 3, pady=3, fill=X, expand =True)
        frame_Header.config(relief=RIDGE, borderwidth=3)

        ttk.Label(frame_Header, justify=CENTER,
            text ='If Generating SIGS file: Select ZIP archive,\nIf Verifying SIGS file: select SIGS file,\nthen Press Start').pack(side = TOP, anchor='w', padx=3, pady = 3, fill=X, expand=True) 

        # Button to Select Archive Files
        button_Selectfiles = ttk.Button(frame_Header, text = "2. Select Files...",
                                                      command = lambda: self.handleButtonPress('__select_files__'))                                             
        button_Selectfiles.pack(side = TOP, padx = 3, pady = 3, expand = True, anchor="w")

        frame_Body = ttk.Labelframe(frame_Header, text ='Files Selected:')
        frame_Body.pack(side = LEFT, padx = 3, pady=3, fill=X, expand =True)

        # Text Area - Archive File List
        self.archive_filelist_tf = Text(frame_Body, width = 50, height=5)
        S = Scrollbar(frame_Body, command=self.archive_filelist_tf.yview)
        S.pack(side=RIGHT, fill=Y)
        self.archive_filelist_tf.configure(yscrollcommand=S.set)
        self.archive_filelist_tf.pack(side=LEFT, fill=BOTH, expand=True)


        ################ Bottom FRAME ##############
        frame_bottombuttons = ttk.Frame(self.root)
        frame_bottombuttons.pack(side=BOTTOM, padx = 3, pady=3, fill=X, expand = True)
        frame_bottombuttons.config(relief = RIDGE, borderwidth = 0)

        frame_Options = ttk.Frame(frame_bottombuttons)
        frame_Options.pack(side=TOP, padx = 3, pady=3, fill=X, expand = True)
        #grid(row=0,columnspan=4)
        #
        frame_Options.config(relief = RIDGE, borderwidth = 0)

        ttk.Label(frame_Options, justify=LEFT,
                  text = '3. Select Options:').pack(side = LEFT, padx = 3, pady = 3, fill=X, expand = True, anchor='w')
     
        # Check Button - Unzip Archive
        self.unzipflag = IntVar()
        self.unzipflag.set(0)
        self.cb_unzipcheck = Checkbutton(frame_Options, 
            text="Unzip Archive", 
            justify=LEFT, 
            variable = self.unzipflag, 
            onvalue=1, 
            offvalue=0)
        self.cb_unzipcheck.pack(side = LEFT, padx = 3, pady = 3, fill=X, expand = True, anchor='w')

        ttk.Label(frame_Options, justify=LEFT,
                  text = 'Log Level:').pack(side=LEFT, padx=3, pady=3, fill=X, expand = True, anchor='w')
        #grid(row = 1, column=0, padx=3, pady=3, sticky = 'e')
        Logging_Levels = [ 'DEBUG', 'INFO', 'WARNING', 'ERROR' ]

        # Combo Box for Logging Details
        self.cbLogging = StringVar()
        self.combobox_cbLogging = ttk.Combobox(frame_Options, justify=LEFT, textvariable=self.cbLogging, width = 10, state='normal')
        self.combobox_cbLogging.pack(side=LEFT, padx=3, pady=3, fill=X, expand = True, anchor='s')
        #grid(row = 1, column=2, sticky = 'w', pady=3, padx=3)
        self.combobox_cbLogging.set('DEBUG')
        self.combobox_cbLogging['values'] = Logging_Levels # generate values based on Template List
        self.combobox_cbLogging.bind('<<ComboboxSelected>>', self.handleComboBoxChanges_Logging)

        # Button to Start MD5 Hash
        frame_bottomelements = ttk.Frame(frame_bottombuttons)
        frame_bottomelements.pack(side=BOTTOM, padx = 3, pady=3, fill=X, expand = True)
        frame_bottomelements.config(relief = FLAT, borderwidth = 0)

        button_Selectfiles = ttk.Button(frame_bottomelements, text = "4. Start Processing",
            command = lambda: self.handleButtonPress('__start__'))                                             
        button_Selectfiles.pack(side = BOTTOM, padx = 3, pady = 3, fill=X, expand = True, anchor='w')

        self.root.mainloop()

    def HandleRadioButton(self): 
        if self.vars_rb_mode.get() == 1: #  Generate Signature File
            self.signfile.set(1)
            self.runverify.set(0)
        elif self.vars_rb_mode.get() == 2: # Verify
            self.runverify.set(1)
            self.signfile.set(0)
        else:
            logging.error("We got here somehow")

    def handleComboBoxChanges_Logging(self, event):
    
        logging_level_choice = self.combobox_cbLogging.get()
        if logging_level_choice == "DEBUG":
            self.logging_choice = logging.INFO
        elif logging_level_choice == "INFO":
            self.logging_choice = logging.WARNING
        elif logging_level_choice == "WARNING":
            self.logging_choice = logging.ERROR
        elif logging_level_choice == "ERROR":
            self.logging_choice = logging.CRITICAL            
        else: 
            self.logging_choice = logging.INFO
            
        logging.basicConfig(level=self.logging_choice, format=' %(asctime)s - %(levelname)s- %(message)s')

    def handleButtonPress(self, myButtonPress):
        if myButtonPress == '__select_files__':
            if (os.name == 'nt'): # Windows OS
                tmp = filedialog.askopenfilenames(initialdir='.')
            elif (os.name == 'posix'): # Linux OS
                tmp = filedialog.askopenfilenames(initialdir='.')
            else: 
                tmp = filedialog.askopenfilenames(initialdir='.')

            if tmp:
                self.archive_filelist_tf.delete(1.0, END)
                self.archive_filelist = tmp
                for fname in self.archive_filelist:
                    fname_basename = os.path.basename(fname)
                    self.Archive_Filename_List.append(fname_basename) #used only on GUI
                    self.archive_filelist_tf.insert(1.0, fname_basename + "; ")

        if myButtonPress == '__start__':
            self.handleComboBoxChanges_Logging("this")
            #logging.disable(self.logging_choice)

            self.HandleRadioButton()
            self.handlearguments()

def main():
    if (len(sys.argv) < 1):
        print('not enough parameters passed - try -h for more info')
        sys.exit(2)
    else: 
        app = md5check()

if __name__ == "__main__": main()

