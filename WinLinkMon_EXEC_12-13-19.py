# Python 3 WinLink PACTOR I, II, and III Message Decompression Monitoring System
# Engineer: John Trites
# Date: 12-13-19   Fix (2) Problems:
# 1) 'PAYLOAD2:_' vs 'PAYLOAD2:' problem in openComDelTextFile lines 480 - 491. Status = Corrected.
# 2) Some captured files that converted to PAYLOAD2 hex bytes containing 'x8D' or 'x9D' fail to convert in this program but actually create a Uncompressed file that can be read in Notepad++ showing corrupted decompressed text.  Status = Work in Progress but not resolved for this release Version 1.1

# Verbose Checkbox = Checked logs logging.warning and above.

# Version:  Release Version 1.1
# Corrects: executing PAYLOAD2 to DecompMSG original V1.0 line 1886 runbindeclen = int(stderr[0:-1]) with V1.1 code:
# stderr_run = stderr.lstrip().rstrip('\n')
# runbindeclen = int(stderr_run)

            

# Replaced all print() functions with logging() to prevent crashing windows WinLinkMon.exe execuable application program.

# logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')

# os - operating sytem package to inspect the file/directory system and control processes.
import os
from os import system
import sys
import re
import struct
import binascii
from binascii import unhexlify, hexlify
import codecs

from WinLinkMon_GUI_12_12_19 import Ui_MainWindow
# added 11-26-19 aboutDialog
from WinLinkMon_About import Ui_aboutDialog
from WinLinkMon_Docs import Ui_docsDialog

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QClipboard

from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTextEdit,
    QCheckBox,
    QAction,
    QFileDialog,
    QPushButton,
    QWidget,
    QMessageBox
)

# 11-30-19 added QtPrint Support
from PyQt5.QtPrintSupport import QPrintDialog, QPrinter

# import linux subprocess - documentation at:
# https://stackoverflow.com/questions/89228/calling-an-external-command-in-python
import subprocess as s
from subprocess import run

# (9/17/19) import logging modules
import coloredlogs, logging
from coloredlogs import ColoredFormatter, parse_encoded_styles
from pprint import pprint

# ---------------- Global Variables -----------------------
pmon_fctp_match = "4643454D"    # FC message, EM - ?
binstart_match = "003000"       # binary Start of File (SOF) pattern
FBBPacketStart = "02FA"         # FBB Packet Starting pattern
bin025B_match = "025B"          # binary "025B" match
FBBPacketStart_Val = "02"       # FBB Packet Start Value = "02"
DefBinLength = "8703"           # Default Binary Length
binstart_offset = (6, 2)        # binstart_offset= (6, 2)
lzhuflen_offset = (8, 14)       # LZHUF binlength = 8-bytes loc offset 
VERSION = 1.0  
PRECHECK = True     # run precheck FCN if True
PADINSERT = False   # insert "00000000" padding if True
STRIP025B = False   # strip "025B" if True
STRIP16 = False     # strip (16) bytes of padded binlength if True
ENDOFFILE = False   # strip EOF = "04" if True
BINMATCH = True    # split ascii from binary msg sections if True
OPENBIN = False     # Added 10-3-19 to open binary (as fname8) or comma delimited text file (as in PAYLOAD2 messages as in fname4)
RUNPOPEN = True     # Added 12-4-19 Default = True executes RunDecompress() FCN, False executes RunPOpenDecompress() FCN

# if TESTLOGGER = True execute (5) Test Logger messages, else skip
TESTLOGGER = True
# added 12-3-19 if GUILOGGER = True execute new class GuiLogger()
GUILOGGER = True
# if SUBRUN = True, execute subprocess.Run() Decompression code, else skip it.
SUBRUN = True
# if SUBPOPEN = True, execute subprocess.Popen() Decompression code, else skip it.
SUBPOPEN = True
# added 12-6-19 VERBOSE logging/logger = False  
VERBOSE = False
# added 12-4-19 FILTER used in new dumphex() FCN
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

# --------------------------------------------------------------
"""Set up the logging."""
def setup_logging(logfilename, log_level=logging.DEBUG):

    coloredlogs.CAN_USE_BOLD_FONT = True

    # Initialize coloredlogs.DEFAULT_LEVEL_STYLES
    coloredlogs.DEFAULT_LEVEL_STYLES = dict(
        spam=dict(color="green", faint=True),
        debug=dict(color="green", bold=True),
        verbose=dict(color="blue"),
        info=dict(color="white", bold=True),
        notice=dict(color="white"),
        warning=dict(color="yellow", bold=True),
        exception=dict(color="magenta", bold=True),
        error=dict(color="red", bold=True),
        critical=dict(color="red", bold=True)
    )

    # Initialize coloredlogs.DEFAULT_FIELD_STYLES
    coloredlogs.DEFAULT_FIELD_STYLES = dict(
        asctime=dict(color='green', bold=True),
        hostname=dict(color='magenta'),
        levelname=dict(color='white', bold=True),
        programname=dict(color='cyan'),
        name=dict(color='blue', bold=True)
    )


    # Run coloredlogs.install
    coloredlogs.install(
        level=log_level,
        # level="DEBUG",
        fmt="%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s"
    )

    # Set logging.getLogger == "<logfilename>.log"
    logger = logging.getLogger(logfilename)

    return logger

# --------------------------------------------------------------
def ColorText(text, color):
        CEND = "\033[0m"
        CTEXT = "\033[37m"
        # CBOLD = "\033[1m"
        CINFO = "\033[37;1;40m"
        CDEBUG = "\033[32;1;40m"
        CWARNING = "\033[30;4;103m"
        CEXCEPTION = "\033[35;1m"
        CERROR = "\033[31;1m"
        CCRITICAL = "\033[37;1;101m"

        if color == "info":
            return CINFO + text + CEND
        elif color == "debug":
            return CDEBUG + text + CEND
        elif color == "warning":
            return CWARNING + text + CEND
        elif color == "exception":
            return CEXCEPTION + text + CEND
        elif color == "error":
            return CERROR + text + CEND
        elif color == "critical":
            return CCRITICAL + text + CEND
        else:
            return CTEXT + text + CEND


# added 12-4-19 Convert Selected Buffer to 3-Column Hex Dump
def hex_dump(src, length = 16):
    N = 0
    result = ''
    while src:
        s, src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
        N += length
    return result


def paddinginsert(str, position, insertion):
    length = len(str)
    if position > length or position < 0:
        return str

    logging.debug(
        "The string %s was inserted between %s and %s"
        % (insertion, str[:position], str[position:]))
    return str[:position] + insertion + str[position:]

# --------------- LZHUF_WriteBin FCN - Step 11C ----------------
# Call LZHUF_WriteBin(recvCompBinFile, lzhuf_binary)
# Writes LZHUF binary portion in (Steps 1 - 11) processed lzhuf_data[1] hexbytes to an intermediate compressed binary file for LZHUF Decompression
# save_bindata = binascii_unhexlify(lzhuf_binary) - converts hexbytes to binary data
# saveStatus = saveFile(recvCompBinFile, save_bindata)
# Return:
#   saveStatus = True (if saveFile() FCN successful)
#   save_bindata = the compressed binary data

def LZHUF_WriteBin(recvCompBinFile, lzhuf_bindata):
    saveStatus = -1         # initialize to Fail.
    # wfname = fname
    # recvCompBinFile = wfname.rsplit(".", 1)[0] + "_LZHUF.bin"
    # recvTextFile = wfname.rsplit(".", 1)[0] + "_Uncomp.txt"
    try:
            
        save_bindata = binascii.unhexlify(lzhuf_bindata)
        
    except:
        logging.error("binascii.unhexlify failed!")

    # Write and Save Binary File with save_bindata
    saveStatus = saveBinFile(recvCompBinFile, save_bindata)

    # recvCompBinFile = "encode_text.bin"
    # recvTextFile = "decode2_bin.txt"

    if saveStatus:
        # if write to wfname_LZHUF.bin file was successful, execute LZHUF DECODE program
        logging.debug("Write File: %s Successfully Saved." % (recvCompBinFile))
        # subprocess.run list of arguments method - WORKS!!!
        # Execute compiled LZHUF.c program to decode

        # recvCompBinFile = "encode_text.bin"     # default file works.
        return saveStatus, save_bindata

    # process writing binary file failed.
    else:
        # Write to wfname_LZHUF.bin file was unsuccessful.
        logging.critical("Writing to File: %s was unsuccessful!" % (recvCompBinFile))
        saveStatus = False
        return saveStatus, save_bindata

# Save LZHUF Binary File Function
def saveBinFile(wfname, wrdata):

    try:
        # hexbytes = ""  # 16 hex byte buffer
        # hexoutbuffer = ""  # hex byte output buffer
        with open(wfname, "w+b") as wf:
            # wrnumbytes = 0
            logging.debug("File %s was opened as write binary" % (wfname))

            # group = 16  # Sixteen 8-bit hex bytes per line
            offset = 0  # starting file seek offset
            wf.seek(offset, 0)  # Go to beginning of the file
            # hexbytes = bytes(wrdata, encoding='utf-8')  # convert wrdata passed in to hexbytes
            try:
                # Write bytes utf-8 encoded wrdata to file wf returning the number of written bytes in wrnumbytes
                # wrnumbytes = wf.write(struct.pack('h', hexbytes))
                wrnumbytes = wf.write(wrdata)

                # hexdata = f.read(group).hex().upper()

                # while hexdata:
                #     # hexbytes = "" # init hexbytes as empty string
                #     hexbytes = ""
                #     # process 16 bytes from offset using range([start], stop[, step])
                #     for inbyte in range(0, len(hexdata), 2):
                #         # process 16 hex bytes per line
                #         hexbytes += hexdata[inbyte] + hexdata[inbyte + 1]
                #         #  + ' '

                #     # Concatenate 16 byte hex strings in hexoutbuffer
                #     hexoutbuffer += hexbytes

                #     # for debug: offset increments 16 bytes per loop
                #     offset += group

                #     # check for EOF
                #     if len(hexdata) < 32:
                #         break
                #     else:
                #         # Read the next 16 hex bytes per line
                #         hexdata = f.read(group).hex().upper()

            finally:
                wf.close()
                logging.debug("File %s was closed." % (wfname))
                # return number of binary bytes written in 1st parameter of tubple wrnumbytes
                return wrnumbytes

    except FileNotFoundError:
        logging.debug("File %s was not found!" % (wfname))

    # Open Binary File Function
def openBinFile(rfname):

    try:
        hexbytes = ""  # 16 hex byte buffer
        hexoutbuffer = ""  # hex byte output buffer
        with open(rfname, "rb") as f:
            logging.debug("File %s was opened as read binary" % (rfname))

            group = 16  # Sixteen 8-bit hex bytes per line
            offset = 0  # starting file seek offset
            f.seek(offset, 0)  # Go to beginning of the file
            hexbytes = ""  # init hexbytes as empty string
            try:
                # Read 16 hex bytes per line from rfname
                hexdata = f.read(group).hex().upper()

                while hexdata:
                    # hexbytes = "" # init hexbytes as empty string
                    hexbytes = ""
                    # process 16 bytes from offset using range([start], stop[, step])
                    for inbyte in range(0, len(hexdata), 2):
                        # process 16 hex bytes per line
                        hexbytes += hexdata[inbyte] + hexdata[inbyte + 1]
                        #  + ' '

                    # Concatenate 16 byte hex strings in hexoutbuffer
                    hexoutbuffer += hexbytes

                    # for debug: offset increments 16 bytes per loop
                    offset += group

                    # check for EOF
                    if len(hexdata) < 32:
                        break
                    else:
                        # Read the next 16 hex bytes per line
                        hexdata = f.read(group).hex().upper()

            finally:
                f.close()
                logging.debug("%s File was closed." % (rfname))

                # return string of hexadecimal bytes whose count is 2 times a hexdump routine's addressing
                return hexoutbuffer

    except FileNotFoundError:
        logging.error(" %s File was not found!" % (rfname))


def openDecompMsg(self, lzhuf_status, recvTextFile):
    global currecv_tab

    if lzhuf_status == True:
    # open recvTextFile and write to recv_decompmsg buffer if lzhuf_status indicates good decompressed message from either Run or POpen method
        try:
            with open(recvTextFile, 'r') as rf:
                try:
                    with rf:
                        rdata = rf.read()

                        self.editor()

                        # QTabWidget method to set current RX Tab to 3rd tab
                        self.ui.recv_tabWidget.setCurrentIndex(2)
                        currecv_tab = self.ui.recv_tabWidget.currentIndex()
                        # currecv_tab = 2
                        self.ui.recv_decompmsg.setText(rdata)
                        # update buffer
                        self.buffer_decompmsg = self.ui.recv_decompmsg.toPlainText()
                    
                        return self.buffer_decompmsg

                except Exception as e:
                    QMessageBox.warning(None, 'Cannot open file', 'Can not open file {}:\n{}'.format(recvTextFile, e))
                    self.buffer_decompmsg = ''
                    return self.buffer_decompmsg

        except IOError:
            # rfname = ''
            self.buffer_decompmsg = ''
            return self.buffer_decompmsg



# -------------- openComDelTextFile FCN - Step 1 ---------------
# Open WinLink PACTOR III Modem Capture Text File:
#   a) captured_data = openComDelTextFile(fname)
#   b) Open Comma Delimited Text File and reads in line by line Storing the ASCII Header parameters of each payload with matching PAYLOAD1: {TYPE: int} sequentially in a dictionary.

# original - def openComDelTextFile(rfname):
# new - def openComDelTextFile(buffer_pmon): 
# passes in buffer_pmon in recv_tabWidget(currecv_tab = 0)
def openComDelTextFile(rfname):
    delims = '\n'
    payload1 = {}
    try:
        hexbytes = ''
        hexbuffer = ''
        with open(rfname, "r") as rcdtf:
            logging.debug("File %s was opened as read only comma delimited text file" % (rfname))

            # read line by line and process payload(s) into dictionary - passed (10/4)
            comment = '#'       # x20
            skipstr1 = 'Ã¾Ãº'
            skipstr2 = 'þú'
            skipstr3 = 'þ'
            endoffile = 'EOF'
            newline = '\n'      # x0A

            seq = {'PLISTEN', 'STATUS', 'PAYLOAD1', 'PAYLOAD2'}
            payload_dict = {}   # initialize empty dictionary

            payload_dict = payload_dict.fromkeys(seq)
            pmon_list = []      # initialize empty list
            pmon_binlen = 0     # initialize pmon binary total length
            
            # initial condition for reading PAYLOAD2's as ascii,
            # True indicates reading PAYLOAD2 as comma delimited hexbyte pairs to be stripped of delimiters into hexbyte_array.
            # Each PAYLOAD2 that contains hexbyte pairs shall be appended into hexbyte_array until last chunk that contains EOF == "04" (2nd to last byte)

            # moved 12-7-19 to here 
            FCEM_pattern = "FC EM"
            FCEM_status = False
            hexbyte_array = ''      # init empty hexbyte_array

            # original -  for line in rcdtf:
            for line in rcdtf:

                # originally was the starting if statement
                if not line.isspace() and not line.startswith((skipstr1, skipstr2, skipstr3)):
                    # strip one or more # chars at beginning
                    line = line.lstrip(comment)
                    # strip newline char '\n' at end
                    line = line.rstrip(newline)

                    # print(f"line = {line} \n")
                    logging.debug("line = %s" % (line))

                    # remove colons and commas to process ascii header
                    pmon_list = re.split(': |, |:', line)

                    # print(f"pmon_list = {pmon_list} \n")
                    logging.debug("pmon_list = %s" % (pmon_list))

        # ------- process additional lines in rfname for PAYLOAD2 --------    
                    if pmon_list[0] == 'PLISTEN':
                        # Delete the PLISTEN key (1st element)
                        pmon_dict2 = {pmon_list[1] : pmon_list[2]}
                        # write new dictionary in payload_dict for PLISTEN
                        payload_dict['PLISTEN'] = pmon_dict2

                    elif pmon_list[0] == 'STATUS':
                        # Delete the 'STATUS' key (1st element)
                        del pmon_list[0:1]
                        # print(f"STATUS : pmon_list = {pmon_list} \n")
                        logging.debug("STATUS : pmon_list = %s" % (pmon_list))

                        # added 12-9-19 for debugging missing 916 hexbytes
                        status_frnr = int(pmon_list[17].strip())
                        # print(f"status_frnr = {status_frnr} \n")

                        # i - iterator over pmon_list
                        i = iter(pmon_list)
                        # create new dictionary using:
                        pmon_dict3 = dict(zip(i, i))

                        # write new dictionary in payload_dict for STATUS
                        payload_dict['STATUS'] = pmon_dict3

                    elif pmon_list[0] == 'PAYLOAD1':
                        # Delete the 'PAYLOAD1' key (1st element)
                        pmon_dict4 = {pmon_list[1] : pmon_list[2], pmon_list[3] : pmon_list[4]}
                        # store pmon_len for processing PAYLOAD2
                        pmon_len = int(pmon_list[2].strip())
                        # print(f"PAYLOAD1 : pmon_len = {pmon_len} \n")
                        logging.debug("PAYLOAD1 : pmon_len = %s" % (pmon_len))

                        # store pmon_type for processing PAYLOAD2
                        pmon_type = int(pmon_list[4].strip())
                        # print(f"PAYLOAD1 : pmon_type = {pmon_type} \n")
                        logging.debug("PAYLOAD1 : pmon_type = %s" % (pmon_type))

                        if pmon_type == 8:
                            # increment pmon_binlen by #hexbytes (after removing comma delimiters) indicated in PAYLOAD1:LEN for each payload.
                            pmon_binlen += pmon_len
                            # print(f"pmon_binlen = {pmon_binlen} \n")
                            

                        # write new dictionary in payload_dict for PAYLOAD1
                        payload_dict['PAYLOAD1'] = pmon_dict4
                        # print(f"payload_dict['PAYLOAD1'] = {payload_dict['PAYLOAD1']} \n")
                        

                    elif pmon_list[0] == 'PAYLOAD2':
                        # strip PAYLOAD2 and store in payload2_list
                        payload2_list = pmon_list[1:]
            
                        # print(f"PAYLOAD2 : pmon_list = {pmon_list} \n")
                        logging.debug("PAYLOAD2 : payload2_list = %s" % (payload2_list))

                        # pmon_acclen is the accumulated length of the current PAYLOAD2 payload.
                        pmon_acclen = 0

                        # read next line(s) after PAYLOAD2 until PAYLOAD_END and check for "FC EM"
                        # original - for line in rcdtf:
                        for line in rcdtf:
                            # if not line.isspace() and not line.startswith((skipstr1, skipstr2, skipstr3)):
                            # 12-9-19 deleted line.isspace() and capturefile1529.txt passed
                            if not line.startswith((skipstr1, skipstr2, skipstr3)):

                                line = line.lstrip(comment)
                                line = line.rstrip(newline)
                                # strip space(s) after 1st word
                                pmon_list = line.strip()

                                # print(f"PAYLOAD2 : pmon_list = {pmon_list} \n")

                                logging.debug("PAYLOAD2 : pmon_list = %s" % (pmon_list))


                            if pmon_list == 'PAYLOAD_END':
                                # print(f"PAYLOAD_END : pmon_list = {pmon_list} \n")
                                break

                            # ORIGINAL CODE PASSED for pmoncapture.cap but FAILS for capturefile1529.txt
                            # elif FCEM_status != True and re.search(FCEM_pattern, pmon_list):
                            
                            elif FCEM_status != True:
                            
                                if re.search(FCEM_pattern, pmon_list):                           
                                    # check next PAYLOAD2's with same TYPE: X for binary msg chunks. Append chunks in payload2_list.  
                                    FCEM_status = True
                                    # print(f"PAYLOAD2 : FCEM_status = {FCEM_status} \n")
                                    logging.debug("PAYLOAD2 : FCEM_status = %s" % (FCEM_status))
                            # original conditional used pmon_acclen < (2*pmon_binlen)
                            elif FCEM_status == True and pmon_type == 8 and pmon_acclen < (2*pmon_binlen):

                            # new 12-10-19 conditional used pmon_acclen < (2*pmon_len)  
                            # elif FCEM_status == True and pmon_type == 8 and pmon_acclen < (2*pmon_len):

                                # process comma delimited hexbyte pairs into new hexbyte_array, appending each row for all PAYLOADS until last payload that includes EOF == "04" (2nd to last byte)
                                hexbyte_array += pmon_list.replace(',', '')
                                # print(f"hexbyte_array: {hexbyte_array} \n")
                                            
                            else:
                                pass

                            pmon_acclen = len(hexbyte_array)
                            # print(f"status_frnr: {status_frnr} \n")
                            # print(f"pmon_binlen: {pmon_binlen} \n")
                            # print(f"pmon_acclen: {pmon_acclen} \n")
                            # print('\n')
                                                            
                        # i - iterator over payload2_list
                        i = iter(payload2_list)
                        # create new dictionary using:
                        pmon_dict5 = dict(zip(i, i))
                        # write new dictionary in payload_dict for PAYLOAD2
                        payload_dict['PAYLOAD2'] = pmon_dict5
                                    
                        # print(f"PAYLOAD2 : payload_dict = {payload_dict} \n")
                        logging.debug("PAYLOAD2 : payload_dict = %s" % (payload_dict))

                    # 12-6-19 added break if endofile ('#EOF') found
                    # elif line.startswith(endoffile):
                    elif pmon_list[0] == endoffile:
                        break

                    else:
                        # print("PAYLOAD_END \n")
                        logging.debug("PAYLOAD_END \n")

                    # print(f"PAYLOAD : payload_dict = {payload_dict} \n")
                    logging.debug("PAYLOAD : payload_dict = %s" % (payload_dict))

                            
                # print pmon_binlen and hexbyte_array contents on each pass
                # print(f"PAYLOAD : pmon_binlen = {pmon_binlen} \n")
                logging.debug("PAYLOAD : pmon_binlen = %s" % (pmon_binlen))

                # print(f"PAYLOAD : hexbyte_array = {hexbyte_array} \n")
                logging.debug("PAYLOAD : hexbyte_array = %s" % (hexbyte_array))

    except FileNotFoundError:
        logging.error(" %s Comma Delimited Text File was not found!" % (rfname))
        hexoutbuffer = ""

    finally:
        rcdtf.close()
        logging.debug("%s File was closed." % (rfname))
        hexoutbuffer = hexbyte_array
        # print(f"Capture File processed! hexoutbuffer = {hexoutbuffer} \n")
        logging.debug("Capture File processed! hexoutbuffer = %s" % (hexoutbuffer))

        # return string of hexadecimal byte pairs with no delimiters whose count is 2 times a hexdump routine.
        # 12-10-19 added return str(pmon_binlen)
        return hexoutbuffer, pmon_binlen


# ----------------- BinMatch FCN - Step 2 ----------------------
# Call BinMatch(hexbyte_array, logger)
# Find the binstart_match pattern that separates the LZHUF_ascii header from the LZHUF_binary hexbyte message
# Returns:
#   binmatch_status = True (found binmatch_pattern = "003000") / False (not found)
#   binmatch_loc = tuple(start, end) of binmatch_pattern location

def BinMatch(captured_data, logger):
    # check for binstart_match == "003000" in captured_data
    global binstart_match, binstart_offset

    binmatch_status = False

    if re.search(binstart_match, captured_data):
        # binstart_match pattern was found:
        m = re.search(binstart_match, captured_data, flags=0)
        binmatch_loc = m.span()
        # logger - uses ColorText function and coloredlogs module:
        binstart_matchmsg = ColorText("The binstart_match pattern: %s was found at %s" % (binstart_match, m.span()), "info")
        logger.debug(binstart_matchmsg)
        # logging - uses Python logging module:
        logging.debug("The binstart_match pattern: %s was found at %s" % (binstart_match, m.span()))

        binmatch_status = True
        return binmatch_status, binmatch_loc

    else:
        binstart_matchmsg = ColorText("The binstart_match pattern: %s was not found!!!" % (binstart_match), "info")
        logger.warning(binstart_matchmsg)
        # logging - uses Python logging module:
        logging.warning("The binstart_match pattern: %s was not found!!!" % (binstart_match))

        binmatch_loc = False
        binmatch_status = False
        return binmatch_status, binmatch_loc

# ----------------- BinStart FCN - Step 3 ----------------------
# Call BinStart(binmatch_status, captured_data, logger)
# Find the FBBPacketStart (e.g. "02FA"), _Val = "02" and its Tuple(start, end) location.
# Returns:
#   binstart_status = True (found binstart_loc pattern == "02") 
#   binstart_loc = Tuple(start, end) of binstart_loc pattern

def BinStart(binmatch_status, captured_data, logger):
    global FBBPacketStart, FBBPacketStart_Val

    binstart_status = False

    # 10-3-19 changed re.search to FBBPacketStart_Val 
    if binmatch_status == True and re.search(FBBPacketStart_Val, captured_data):
        # if binstart_loc contains the FBBPacketStart_Val pattern = (e.g."02FA"), log and return binstart_loc

        # New Method searches for FBBPacketStart_Val = "02"
        fbb = re.search(FBBPacketStart_Val, captured_data, flags=0)
        binstart_loc = fbb.span()

        binstartloc_msg = ColorText("The binstart_loc was found at %s" % str(binstart_loc), "info")
        logger.debug(binstartloc_msg)
        logging.debug("The binstart_loc == 02FA was found at %s" % str(binstart_loc))

        binstart_status = True
        return binstart_status, binstart_loc

    else:
        # binstart_match pattern was not found! Return default binstart_loc = (0,2)
        binstart_loc = (0, 2)
        binstartloc_failmsg = ColorText("The binstart_loc was not found.  Setting default binstart_loc == %s"
            % str(binstart_loc), "warning")
        logger.warning(binstartloc_failmsg)
        logging.warning(
            "The binstart_loc was not found.  Setting default binstart_loc == %s"
            % str(binstart_loc))
            
        binstart_status = False
        return binstart_status, binstart_loc

# ----------------- LZHUF_Packet FCN - Step 4 ------------------
# Call LZHUF_Packet(binstart_loc, captured_data, logger)
# Check for patterns:
#   binstart_match = "003000"
#   FBBPacketStart = e.g. "02FAxxxx", FBBPacketStart_Val = "02"
# Returns:
#   packet_status= True (found e.g. 8703)
#   lzhufdeclen = Decimal Value of hexbyte message data
#   binlength_loc = Tuple(start, end) pf 8-byte binlength (e.g. 87030000)

def LZHUF_Packet(binstart_loc, captured_data, logger):

    global FBBPacketStart_Val, lzhuflen_offset
    lzhufdeclen = 0             # initialize to zero/empty

    if captured_data[binstart_loc[0] : binstart_loc[1]] == FBBPacketStart_Val:
        
        # process if FBBPacketStart_Val = "02" found
        binlength_loc = tuple(map(sum, zip(binstart_loc, lzhuflen_offset)))

        # FBBPackStart_valmsg = ColorText("The FBBPacketStart_Val == 02 was found at %s" % (binstart_loc[0]), "info")
        # logger.info(FBBPackStart_valmsg)

        logging.debug("The FBBPacketStart_Val == 02 was found at %s" % (binstart_loc[0]))

        lzhufbinlen = captured_data[binlength_loc[0] : binlength_loc[1]]
        lzhufbinlen_msg = ColorText("The lzhufbinlen == %s was found at %s" % (lzhufbinlen, binlength_loc), "info")
        logger.debug(lzhufbinlen_msg)

        logging.debug(
            "The lzhufbinlen == %s was found at %s" % (lzhufbinlen, binlength_loc)
            )
        packet_status = True

    elif captured_data[binstart_loc[0] : binstart_loc[1]] != FBBPacketStart_Val and re.search(DefBinLength, captured_data):
        # default location if FBBPacketStart_Val not found but DefBinLength = "8703" found

        # New Method searches for FBBPacketStart_Val = "02"
        dbl = re.search(DefBinLength, captured_data, flags=0)
        binlength_loc = dbl.span()

        lzhufbinlen = captured_data[binlength_loc[0] : binlength_loc[1]]

        logging.warning(
            "The FBBPacketStart_Val = '02' was not found but lzhufbinlen == %s was found at %s" % (lzhufbinlen, binlength_loc)
        )

        logging.warning(
            "The LZHUF Compressed Packet Decimal Length lzhufdeclen pattern was not found!!!"
        )

        packet_status = True

    else:
        binlength_loc = (0, 2)      
        # default = beginning of string
        packet_status = False

    if packet_status == True:
        # Three methods to Convert Little Endian N hexbyte LZHUF compressed binary length and return a reversed decimal value:

        # Method 1 - hard-coded 2-byte with space
        lzhufdeclen = int("".join("ED 00".split()[::-1]), 16)

        # Method 2 - hard-coded 2-byte with no spaces
        lzhufdeclen = struct.unpack("<H", codecs.decode("ED00", "hex"))[0]
        lzhufdeclen = struct.unpack("<hh", codecs.decode("ED000000", "hex"))[0]

        # Method 3 - 2-byte no spaces lzhufbinlen converted!
        # convert lzhufbinlen from big endian to little endian
        bigendianlist = []
        for i in range(0, len(lzhufbinlen), 2):
            bigendianlist.insert(0, lzhufbinlen[i:i+2])
        # convert from list to string
        # lzhufbinlen = str(bigendianlist)
        lzhufbinlen = "".join(str(x) for x in bigendianlist)
        # convert little endian to decimal value
        lzhufdeclen = int(lzhufbinlen, 16)
        # lzhufdeclen = struct.unpack("<hh", codecs.decode(lzhufbinlen, "hex"))[0]
    
        logging.debug(
            "The LZHUF Compressed Packet Decimal Length lzhufdeclen %s pattern was found."
            % (lzhufdeclen)
        )

        return packet_status, lzhufdeclen, binlength_loc

    else:
        lzhufbinlen = 0   # default if FBBPacketStart_Val not found
        lzhufdeclen = 0
        binlength_loc = (0, 5)
        packet_status= False
        logging.warning("The LZHUF Compressed Packet Decimal Length lzhufdeclen pattern was NOT found.")

        return packet_status, lzhufdeclen, binlength_loc

    # ----------------- LZHUF_Split FCN - Step 5 -------------------
    # Call LZHUF_Split(binmatch_loc, captured_data, logger)
    # Splits the LZHUF_ascii hexbyte header portion of the hexbyte_array from the LZHUF_binary hexbyte message portion 
    # Returns:
    #   binsplit_status = True (successfully split hexbyte_array header from message data)
    #   lzhuf_header_len = length of header lzhuf_data[0]
    #   lzhuf_compdata_len = length of hexbyte message lzhuf_data[1]
    #   lzhuf_data[0] = lzhuf_ascii hexbyte header portion
    #   lzhuf_data[1] = lzhuf_binary hexbyte message portion

def LZHUF_Split(binmatch_loc, captured_data, logger):
    # Method 2 - split() method works using binstart_match pattern = "003000"
    global binstart_match

    binsplit_status = False

    if binmatch_loc:
        # binstart_matchmsg = ColorText("The binstart_match pattern: %s was found at %s" % (binstart_match, binmatch_loc), "info")
        # logger.info(binstart_matchmsg)

        logging.debug(
            "The binstart_match pattern: %s was found at %s"
            % (binstart_match, binmatch_loc)
        )

        # Split the captured_data ascii portion stored in lzhuf[0] from the binary portion stored in lzhuf_data[1]:
        lzhuf_data = captured_data.split(binstart_match)

        # lzhuf_data[0] contains the Header portion of the Packet stored in captured_data starting before the binstart_match pattern:
        lzhuf_header_len = len(lzhuf_data[0])
        logging.debug(
            "The Beginning Packet Header portion is lzhuf_header_len %s bytes long."  % (lzhuf_header_len))
        logging.debug("The Packet Header lzhuf_header_len contains: %s" % (lzhuf_data[0]))

        # lzhuf_data[1] contains the Compressed binary portion of the packet stored in captured_data starting after the binstart_match pattern
        lzhuf_compdata_len = len(lzhuf_data[1])
        logging.debug("The Compressed Binary Packet portion is lzhuf_compdata_len %s bytes long." % (lzhuf_compdata_len))
        logging.debug("The Compressed Binary Packet contains: %s" % (lzhuf_data[1]))

        # return lzhuf_ascii = lzhuf_data[0] and lzhuf_binary = lzhuf_data[1]
        binsplit_status = True
        return binsplit_status, lzhuf_compdata_len, lzhuf_data[0], lzhuf_data[1]

    else:
        binsplit_status = False
        lzhuf_compdata_len = 0

        logging.warning("NO BinStart_Match == '003000' Found!")
        return binsplit_status, lzhuf_compdata_len, lzhuf_data[0], lzhuf_data[1]
    


# -------------- LZHUF_StripFBB FCN - Step 6 -------------------
# Call LZHUF_StripFBB(binstart_status, binlength_loc, lzhuf_binary, logger)
# Strips the 8-byte FBB Header before the binlength_loc
# Returns:
#   stripfbb_status = True (successfully strips 1st 8-bytes up to binlength_loc)
#   lzhuf_stripfbb_len = new length of lzhuf_binary data
#   lzhuf_stripfbb = lzhuf_binary data stripped of 1st 8-bytes
def LZHUF_StripFBB(binstart_status, binlength_loc, lzhuf_binary, logger):

    stripfbb_status = False

    if binstart_status:
        lzhuf_stripfbb = lzhuf_binary[8:]
        lzhuf_stripfbb_len = len(lzhuf_stripfbb)

        logging.debug(
            "The LZHUF Compressed PBinary Packet portion Stripped of 8-byte FBB Header before the binlength_loc is %s bytes long."
            % (lzhuf_stripfbb_len)
        )

        stripfbb_status = True
        logging.debug("Returned Patterns: stripfbb_status = %s, lzhuf_stripfbb_len = %s, lzhuf_stripfbb = %s" % (stripfbb_status, lzhuf_stripfbb_len, lzhuf_stripfbb))

        return stripfbb_status, lzhuf_stripfbb_len, lzhuf_stripfbb

    else:
        # binlength_loc not found.  Copy lzhuf_uncomp_paddata to lzhuf_comp_paddata:
        lzhuf_stripfbb = lzhuf_binary[:]
        lzhuf_stripfbb_len = len(lzhuf_stripfbb)

        logging.debug("Returned Patterns: stripfbb_status = %s, lzhuf_compdata_len = %s, lzhuf_compdata = %s" % (stripfbb_status, lzhuf_stripfbb_len, lzhuf_stripfbb))

        logging.warning(
            "binlength_loc not found.  Copy lzhuf_binary to lzhuf_compdata."
        )

        stripfbb_status = False
        return stripfbb_status, lzhuf_stripfbb_len, lzhuf_stripfbb

# -------------- LZHUF_Padding FCN - Step 7 --------------------
# (optional) Call LZHUF_Padding(stripfbb_status, binlength_loc, lzhuf_binary, logger)
# Inserts 8-bytes "00000000" of padding after FBBPacketLen (e.g. "87 03") in lzhuf_data[1] Compressed binary portion:
# Returns:
#   lzhufpad_status = True (successfully padded binlength, now 16-bytes)
#   lzhuf_paddata_len = new length of 8-zero's padded lzhuf_binary data_
#   lzhuf_paddata = lzhuf_binary data padded with 8-zero's
def LZHUF_Padding(stripfbb_status, binlength_loc, lzhuf_binary, logger):
    lzhufpad_status = False

    if stripfbb_status == True:
        lzhuf_paddata = paddinginsert(lzhuf_binary, binlength_loc[0]+8, "00000000")
        lzhuf_paddata_len = len(lzhuf_paddata)
        # lzhuf_comp_paddata_len_msg = ColorText("The LZHUF Compressed Padded Binary Packet is lzhuf_comp_paddata_len %s bytes long." % (lzhuf_comp_paddata_len), "info")
        # logger.info(lzhuf_comp_paddata_len_msg)

        logging.debug(
            "The LZHUF Compressed Padded Binary Packet is lzhuf_comp_paddata_len %s bytes long."
            % (lzhuf_paddata_len)
        )
        logging.debug("Returned Patterns: lzhuf_pad_status = %s, lzhuf_comp_paddata_len = %s, lzhuf_comp_paddata = %s" % (lzhufpad_status, lzhuf_paddata_len, lzhuf_paddata))

        lzhufpad_status = True
        return lzhufpad_status, lzhuf_paddata_len, lzhuf_paddata

    else:
        # The input file contains no ASCII packet portion, continue to process the Binary packet portion.
        lzhuf_paddata = lzhuf_binary
        lzhuf_paddata_len = len(lzhuf_paddata)

        logging.warning(
            "The LZHUF Compressed Non-Padded Binary Packet is lzhuf_comp_paddata_len %s bytes long."
            % (lzhuf_paddata_len)
        )

        # Do Not Insert Padding "00 00 00 00" after FBBPacketLen e.g. "87 03" in lzhuf_data Compressed binary portion because FBBPacketLen not found:
            
        logging.warning(
            "The LZHUF Compressed Non-Padded Binary Packet is lzhuf_uncompdata_len %s bytes long."
            % (lzhuf_paddata_len)
        )

        lzhufpad_status = False
        return lzhufpad_status, lzhuf_paddata_len, lzhuf_paddata

# -------------- LZHUF_Strip025B FCN - Step 8 ------------------
# (optional) Call LZHUF_Strip025B(lzhuf_binary)
# # Strip the Compressed Padded Binary string of bin025B_match if it exists from from lzhuf_binary, otherwise return original lzhuf_binary data
#  ---  for some odd reason not defined!!!
# Return:
#   bin025B_status = True (successfully found and striped these 4-hexbytes)
#   bin025B_loc = Tuple(start, end) location of the bin025B pattern
#   lzhuf_bindata_len = length of strip025B lzhuf_binary data
#   lzhuf_bindata = strip025B lzhuf_binary data

def LZHUF_Strip025B(lzhuf_binary):
    global bin025B_match

    # loop through LZHUF Compressed Padded Binary data for bin025B_match
    strip025B_status = False
    for bytepair_count in range(0, len(lzhuf_binary), 2):
        # If the bin025B_match == 025B is not found, break and return "bin025B_match is not found"
        bytepair = (bytepair_count, bytepair_count+4)
        bin025B_loc = tuple(bytepair)

        if (lzhuf_binary[bin025B_loc[0] : bin025B_loc[1]] == bin025B_match):
            # bin025B_match == "025B" found!
            # Strip "02 5B" from lzhuf_comp_paddata and concatenate 2 strings to lzhuf_bindata
            lzhuf_bindata = (
                lzhuf_binary[: bin025B_loc[0]]
                + lzhuf_binary[bin025B_loc[1] :]
            )
            lzhuf_bindata_len = len(lzhuf_bindata)

            # log bin025B match found and stripped
            logging.debug(
                "The bin025B == %s Start pattern was found at %s and stripped."
                % (bin025B_match, bin025B_loc)
            )
                    
            strip025B_status = True
            break

    if strip025B_status == True:
        # bin025B_match found
        bin025B_status = True
        logging.debug(
            "The LZHUF Compressed Padded Binary Packet portion with 025B removed is: %s lzhuf_bindata_len bytes long."
            % (lzhuf_bindata_len)
            )

    else:
        # bin025B_match not found
        bin025B_status = False
        lzhuf_bindata = lzhuf_binary[:]
        lzhuf_bindata_len = len(lzhuf_bindata)

        logging.warning(
            "The LZHUF Compressed Padded Binary Packet portion bin025B_match was not found.  All bytes copied to lzhuf_bindata which is: %s bytes long."
            % (lzhuf_bindata_len)
            )

        # bin025B_loc = tuple(0, 2)
        # bin025B_match_status = False

    return bin025B_status, bin025B_loc, lzhuf_bindata_len, lzhuf_bindata

# ---------------- LZHUF_Strip16 FCN - Step 9 ------------------
# (optional) Call LZHUF_Strip16(stripfbb_status, lzhuf_binary)
# Only strip the 1st 16-hexbytes before the start of LZHUF Compressed Binary File
#   if lzhuf_pad_status and stripfbb_status == True
# Return:
#   strip16_status = True (successfully stripped these 16-hexbytes)
#   lzhuf_strip16data_len = length of strip16 lzhuf_binary data 
#   lzhuf_strip16data = strip16 lzhuf_binary data 
# Example: Strip the 1st 16 bytes "87 03 00 00 00 00 00 00" before actual start of LZHUF Compressed Binary Data

def LZHUF_Strip16(stripfbb_status, lzhuf_binary):

    strip16_status = False

    if stripfbb_status == True:
        lzhuf_strip16data = lzhuf_binary[16:]
        lzhuf_strip16data_len = len(lzhuf_strip16data)
        logging.debug(
            "The LZHUF Compressed Padded Binary Packet portion with uncompressed 1st 16 bytes removed is %s bytes long"
            % (len(lzhuf_strip16data))
        )

        strip16_status = True
        return strip16_status, lzhuf_strip16data_len, lzhuf_strip16data
        
    else:
        lzhuf_strip16data = lzhuf_binary[:]
        lzhuf_strip16data_len = len(lzhuf_strip16data)

        strip16_status = False
        return strip16_status, lzhuf_strip16data_len, lzhuf_strip16data

# ------------------ LZHUF_CheckEOF FCN - Step 10 -------------------
# (optional) Call LZHUF_CheckEOF(lzhuf_binary_len, lzhuf_binary)
# Strip the End of File hexbyte = "04" (2nd last byte of lzhuf_binary before last CRC byte)
# Returns:
#   lzhuf_checkeof_status = True (successfully found and stripped)
#   lzhuf_eofdata_len = length of strip eof lzhuf_binary data 
#   lzhuf_eofdata = stripped eof lzhuf_binary data 

def LZHUF_CheckEOF(lzhuf_binary_len, lzhuf_binary):

    lzhuf_checkeof_status = False

    lzhuf_eof = (
        lzhuf_binary[lzhuf_binary_len - 4] 
        + lzhuf_binary[lzhuf_binary_len - 3]
    )

    # Strip EOF == "04" if found   
    if lzhuf_eof  == "04":
        lzhuf_compdata_noeof = (
            lzhuf_binary[:(lzhuf_binary_len - 4)]
            + lzhuf_binary[(lzhuf_binary_len - 2):]
        )
            

        logging.debug(
            "lzhuf_compdata_noeof was found and removed at: %s"
            % (lzhuf_binary_len - 4))

        lzhuf_checkeof_status = True
        return lzhuf_checkeof_status, lzhuf_eof, lzhuf_compdata_noeof

    else:
        # print("The EOF = 04 does not exist in this file!")
        logging.warning("lzhuf_compdata_noeof was not found!")

        lzhuf_compdata_noeof = lzhuf_binary[:]
        lzhuf_checkeof_status = False
        return lzhuf_checkeof_status, lzhuf_eof, lzhuf_compdata_noeof

# ------------ LZHUF_RunDecompress FCN - Step 11A --------------
# (optionally) run if SUBRUN == True
#   Call LZHUF_RunDecompress(wfname, lzhuf_compdata_noeof)
#   a) Converts the wfname into two filenames:
#       wfname + _Run_LZHUF.bin is used to call LZHUF_WriteBin() 
#       to write lzhuf_binary data as in the input in the s.run() command
#       wfname + _Run_Uncomp.txt is the output of the s.run() command
#   b) try subprocess.run("lzhuf.exe", "d", wfname_Run_LZHUF.bin, wfname_Run_Uncomp.txt) to execute an external LZHUF.exe Windows 10 Program to Decompress a binary file if SUBRUN = True (enabled)
# Returns:
#   lzhuf_status1 = True if s.run() successfully completed
#   rc = s.run() returncode
#   stdout = s.run() standard output
#   stderr = s.run() standard error (# binary bytes decompressed)

def LZHUF_RunDecompress(wfname, lzhuf_compdata_noeof):
    global currecv_tab    
    # recvCompBinFile is the processed intermediate binary file
    recvCompBinFile = wfname.rsplit(".", 1)[0] + "_Run_LZHUF.bin"
    # recvTextFile is the LZHUF Decompressed text file   
    recvTextFile = wfname.rsplit(".", 1)[0] + "_Run_Uncomp.txt"

    # Write intermediate binary file for LZHUF Decompression
    save_bindata = LZHUF_WriteBin(recvCompBinFile, lzhuf_compdata_noeof)

    if SUBRUN == True:

        try:
            lzhuf_status1 = s.run(
                ["lzhuf.exe", "d", recvCompBinFile, recvTextFile],
                check=True,
                universal_newlines=True,
                stdout=s.PIPE,
                stderr=s.PIPE,
                shell=False,
                timeout=5,
            )

            logging.debug("LZHUF program using s.run() Passed! %s" % (lzhuf_status1))

            rc = lzhuf_status1.returncode
            logging.debug("LZHUF program using s.run()  Passed! returncode = %d" % (rc))

            stdout = lzhuf_status1.stdout
            logging.debug("LZHUF program using s.run() Passed! stdout = %s" % (stdout))

            stderr = lzhuf_status1.stderr
            logging.debug("LZHUF program using s.run() Passed! stderr = %s" % (stderr))

        except:
            lzhuf_status1 = False
            rc = -1
            stdout = False
            stderr = False
            logging.debug("LZHUF program using s.run() Failed! lzhuf_status1 = %s" % (lzhuf_status1))

        if rc >= 0 and rc <= 1:
            logging.debug("LZHUF Decompression using subprocess.run was successful!")
            return lzhuf_status1, rc, stdout, stderr, recvTextFile

        else:
            logging.warning(
                "LZHUF Decompression using subprocess.run was NOT successful!!!"
            )
            return lzhuf_status1, rc, stdout, stderr, recvTextFile

    else:
        rc = -2
        lzhuf_status1 = False
        stdout = False
        stderr = False
        logging.warning("sub.run() Decompression was not executed because it was disabled!")
        return lzhuf_status1, rc, stdout, stderr, recvTextFile

# ------------ LZHUF_PopenDecompress FCN - Step 11B ------------
# (optionally run if SUBPOPEN == True) 
#   Call LZHUF_PopenDecompress(wfname, lzhuf_compdata_noeof)
#   a) Converts the wfname into two filenames:
#       wfname + _Popen_LZHUF.bin is used to call LZHUF_WriteBin() 
#       to write lzhuf_binary data as in the input in the s.run() command
#       wfname + _Popen_Uncomp.txt is the output of the s.run() command
#   b) Executes external program s.run("lzhuf.exe", "d", wfname_Popen_LZHUF.bin, wfname_Popen_Uncomp.txt)
# Returns:
#   lzhuf_status2 = True if s.Popen() successfully completed
#   rc = s.Popen() returncode
#   output = s.run() standard output
#   errors = s.run() standard errors (# binary bytes decompressed)

def LZHUF_PopenDecompress(wfname, lzhuf_compdata_noeof):

    # recvCompBinFile is the processed intermediate binary file
    recvCompBinFile = wfname.rsplit(".", 1)[0] + "_Popen_LZHUF.bin"
    # recvTextFile is the LZHUF Decompressed text file
    recvTextFile = wfname.rsplit(".", 1)[0] + "_Popen_Uncomp.txt"

    # Write intermediate binary file for LZHUF Decompression
    save_bindata = LZHUF_WriteBin(recvCompBinFile, lzhuf_compdata_noeof)

    if SUBPOPEN == True:
            
        try:
            lzhuf_status2 = s.Popen(
                ["lzhuf.exe", "d", recvCompBinFile, recvTextFile],
                stdout=s.PIPE,
                stderr=s.PIPE,
                shell=False,
            )

            output, errors = lzhuf_status2.communicate(None, timeout=5)
            rc = lzhuf_status2.returncode

            logging.debug("LZHUF program using s.Popen() Passed! lzhuf_status2 = %s, output = %s, errors = %s, returncode = %s" % (lzhuf_status2, output, errors, rc))

        except ValueError:
            logging.error("LZHUF program using s.Popen() Failed due to Invalid Arguments!!")
            rc = 3
            output = "None"
            errors = "Failed!"

        except TimeoutError:
            logging.error("LZHUF program using s.Popen() Failed due to Timeout Error!!")
            rc = 4
            output = "None"
            errors = "Failed!"

        except OSError:
            logging.error("LZHUF program using s.Popen() Failed because of Operating System Error! %s" % (lzhuf_status2))
            rc = 5
            output = "None"
            errors = "Failed!"

        except:
            if lzhuf_status2.stderr_thread._exc_info == True:
                ident = lzhuf_status2.stderr_thread.ident
                stop = lzhuf_status2.stderr_thread.stop_reason
            else:
                ident = 12345
                stop = 678
            rc = 2
            output = "None"
            errors = "Failed!" 
            logging.error("LZHUF program using s.Popen() Failed! id = %s, retcode = %s, output = %s, errors = %s, stop_reason = %i" % (ident, rc, output, errors, stop))

        if rc == 0:
            logging.debug(
                "LZHUF Decompression using subprocess.Popen was successful!  Output = %s, Errors = %s"
                % (output, errors)
            )
            return lzhuf_status2, rc, output, errors, recvTextFile

        else:
            logging.error(
                "LZHUF Decompression using subprocess.Popen was NOT successful!!!"
                )
            return lzhuf_status2, rc, output, errors, recvTextFile

    else:
        logging.debug("sub.Popen() Decompression was not executed because it was disabled!")
        return lzhuf_status2, rc, output, errors, recvTextFile

# --------------------------------------------------------------
# ----------- New class 12-3-19 GuiLogger() --------------------
class GuiLogger(logging.Handler):
    def emit(self, record):
        # implementation of append_line omitted
        self.edit.append(self.format(record))


# --------------------------------------------------------------
# ----------- New class MainWindow_EXEC() function -------------
class MainWindow_EXEC(object):

    def __init__(self):
        super(MainWindow_EXEC, self).__init__()

        # Global Variables - rfname ?
        global rfname, currecv_tab, logger, buffer_log, buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump
        # initialize (5) buffers to empty
        buffer_pmon = ""
        buffer_payload2 = ""
        buffer_decompmsg = ""
        buffer_hexdump = ""
        buffer_log = ""

        # Initialize Main Window from WinLinkMon_GUI
        app = QtWidgets.QApplication(sys.argv)
        MainWindow = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(MainWindow)

        # Initalize all checkboxes to their default values
        self.verbose = VERBOSE
        self.padinsert = PADINSERT
        self.strip025B = STRIP025B
        self.strip16 = STRIP16
        self.stripeof = ENDOFFILE
        self.binmatch = BINMATCH
        self.openbin = OPENBIN
        self.runpopen = RUNPOPEN

        # Initalize the matching pattern vars
        self.binmatch_loc = ""           # binary match starting location
        # bin025B_match = "025B"      # binary "025B" match
        self.bin025B_match_loc = ""      # binary "025B" starting location 
        # FBBPacketStart_Val = "02"   # FBB Packet Start Value = "02"
        self.FBBPacketStart_Loc = ""     # FBB Packet Val Start Location
        self.FBBPacketLen = ""           # FBB Packet Length = 0xFA (250) Max
        self.FBBTest = ""                

        # initialize tuple location of binstart_loc and binstart_offset
        self.binstart_loc = ""
        # init empty binlength location
        self.binlength_loc = ""
        # LZHUF compressed binary file length is located at hex byte offset (8, 10) from "02" binstart_loc location.
        self.lzhufbinlen = 0                 # LZHUF binary file length

        # lzhuflen_offset = (12, 15) for 0x00 00 00 values
        self.lzhuf_ascii = ""                # starting ascii empty string
        self.lzhuf_binary = ""               # starting binary empty string

    # ------------ Create Instance of GuiLogger class ----------
        if GUILOGGER == True:
            h = GuiLogger()
            h.edit = self.ui.logTextEdit
            logging.getLogger().addHandler(h)
            logging.debug("GuiLogger Test Message.")


    # ------------- Initialize recv_tabWidget ----------------------
        # QTabWidget method to set current RX Tab to 1st tab
        self.ui.recv_tabWidget.setCurrentIndex(0)
        currecv_tab = self.ui.recv_tabWidget.currentIndex()

        # Call method when an Recv(Rx) tab is selected
        self.ui.recv_tabWidget.currentChanged.connect(self.chkrecv_tabIndex)



    # --------- Initialize Editor ------------------------------
        # Add openRecvText Sender
        self.openRecvText = QtWidgets.QAction("&Editor")
        # Connect openRecvText Sender's .triggered Signal to Receiver Slot self.editor
        self.openRecvText.triggered.connect(self.editor)

    # --------- File Signal and Slots --------------------------
        # Connect newFile Sender's .triggered Signal to currecv_tab Receiver's Slot = fileNewDialog function
        # self.ui.newFile.triggered.connect(fileNewDialog)
    
        # Connect openFile Sender's .triggered Signal to currecv_tab Receiver's Slot = openFileDialog fucntion
        self.ui.openFile.triggered.connect(self.openFileDialog, currecv_tab)
    
        # Disabled in Release Version 1.0 12-5-19
        # Connect saveFile Sender's .triggered Signal to currecv_tab Receiver's Slot = saveFileDialog function
        # self.ui.saveFile.triggered.connect(self.saveFileDialog, currecv_tab)

        # Disabled in Release Version 1.0 12-5-19
        # Connect saveFile_As Sender's .triggered Signal to currecv_tab Receiver's Slot = saveAsFileDialog function
        # self.ui.saveFile_As.triggered.connect(self.saveFileDialog, currecv_tab)
    
        # Connect printText (text buffer) Sender's .triggered Signal to currecv_tab Receiver's Slot = printTextBuffer() function
        self.ui.printText.triggered.connect(self.printTextBuffer)
        # Connect printLog (text) Sender's .triggered Signal to Receiver's Slot = printLogBuffer() function
        self.ui.printLog.triggered.connect(self.printLogBuffer)

        # Connect actionReset Sender's .triggered Signal to clear the contents of the (4) Text Buffer, one per tab, and the log buffer.  Then selects the PMON Capture tab as the currecv_tab.
        self.ui.actionReset.triggered.connect(self.reset_clear)

    # --------- Edit Signals & Slots ---------------------------
        # Connect currecv_tab's QTextEdit Sender's .triggered Signal to Receiver's Slot = currecv_tab(QTextEdit) - commented out until errors resolved!
        # self.ui.actionCut.triggered.connect(self.cut_text)
        # self.ui.actionCopy.triggered.connect(self.copy_text)
        # self.ui.actionPaste.triggered.connect(self.paste_text)

        # Connect clipboard's QClipBoard Sender's .dataChanged Signal to Receiver's Slot = clipBoardChanged() - commented out until errors resolved!
        # QApplication.clipboard().changed.connect(self.clipboardChanged)

    # --------- Conversion Signals & Slots ---------------------
        # Connect recvPmon_to_Payload2 Sender's .triggered Signal to Receiver's Slot = recvpmon2payload2() function
        self.ui.recvPmon_to_Payload2.triggered.connect(self.recvpmon2payload2)
        
        # Connect recvPayload2_to_DecompMsg Sender's .triggered Signal to Receiver's Slot = recvpayload2decompmsg() function
        self.ui.recvPayload2_to_DecompMsg.triggered.connect(self.recvpayload2decompmsg)

        # Connect recvPmon_to_DecompMsg Sender's .triggered Signal to Receiver's Slot = recvpmon2decompmsg() function
        self.ui.recvPmon_to_DecompMsg.triggered.connect(self.recvpmon2decompmsg)

    # ----------- Assembly Signals & Slots ---------------------
        # Connect assyCapture Sender's .triggered Signal to Receiver's Slot = assy_capture() function
        self.ui.assyCapture.triggered.connect(self.assy_capture)

        # Connect assyPayload2 Sender's .triggered Signal to Receiver's Slot = assy_payload2() function
        self.ui.assyPayload2.triggered.connect(self.assy_payload2)

    # ------------- HexDump Signals & Slots ---------------------
        # Connect recvCapture_HexDump Sender's .triggered Signal to Receiver's Slot = recv_capture_hexdump() function
        self.ui.recvCapture_HexDump.triggered.connect(self.recv_capture_hexdump)

        # Connect recvPayload2_HexDump Sender's .triggered Signal to Receiver's Slot = recv_payload2_hexdump() function
        self.ui.recvPayload2_HexDump.triggered.connect(self.recv_payload2_hexdump)

        # Connect recvDecomp_HexDump Sender's .triggered Signal to Receiver's Slot = recv_decomp_hexdump() function
        self.ui.recvDecomp_HexDump.triggered.connect(self.recv_decomp_hexdump)

    # ---------------- Help Signals & Slots ---------------------
        # Connect about_WinLinkMon Sender's .triggered Signal to Receiver's Slot = about_winlinkmon() function
        self.ui.about_WinLinkMon.triggered.connect(self.about_winlinkmon)

        # Connect about_Documentation Sender's .triggered Signal to Receiver's Slot = winlinkmon_docs() function
        self.ui.documentation.triggered.connect(self.winlinkmon_docs)

    # ----------- Initialize Checkboxes Signal and Slots -------
        # Connect (9) QCheckBox Sender's .triggered Signal(s) to (1) Receiver Slot using lambda function(s) to call write_checkboxes(n).  n - determines which QCheckBox's State was changed.
        self.ui.chk_verbose.stateChanged.connect(lambda: self.write_checkboxes(1))
        self.ui.chk_openbin.stateChanged.connect(lambda: self.write_checkboxes(2))
        self.ui.chk_binmatch.stateChanged.connect(lambda: self.write_checkboxes(3))
        self.ui.chk_padinsert.stateChanged.connect(lambda: self.write_checkboxes(4))
        self.ui.chk_strip025B.stateChanged.connect(lambda: self.write_checkboxes(5))
        self.ui.chk_strip16.stateChanged.connect(lambda: self.write_checkboxes(6))
        self.ui.chk_stripeof.stateChanged.connect(lambda: self.write_checkboxes(7))
        self.ui.chk_runpopen.stateChanged.connect(lambda: self.write_checkboxes(8))


# ------------------ End of Main Logic ------------------
        MainWindow.show()

        logging.warning("Program Ended, Check the logs!")
        logging.shutdown()

        sys.exit(app.exec_())

    # Initialize logger
    # 12-6-19 added self.verbose to arguments
    def init_logger(self, rfname):
        global logger, logfilename

        # create and print logfilename based on selected rfname file returned from the openFileDialog() function with .log extension
        logfilename = rfname.rsplit(".", 1)[0] + ".log"
        # print("The log file is: ", logfilename)

        # Call python 3 setup_logging() FCN
        if self.verbose == True:
            logger = setup_logging(logfilename, log_level=logging.DEBUG)
        else:
            logger = setup_logging(logfilename, log_level=logging.WARNING)
        
        # print("The Logger object == ", logger)
        #  log Start off Program
        start_prog = ColorText("Start of Test Program.", "")
        # print(start_prog)

        if TESTLOGGER == True:
            # Log (5) Test Logger Messages using their new default sytles
            # print("TESTLOGGER == True, run 5 test messages")
            logger.debug("this is a debug message.")
            logger.info("this is an informational message.")
            logger.warning("this is a warning message.")
            logger.error("this is an error message.")
            logger.critical("this is a critical message.")
            # logger.exception("this is an exception message.")

        # print style.BOLD + 'This is my text string.' + style.NOBOLD
        start_msg = ColorText("Start of Test Logging Messages.", "info")
        logger.info(start_msg)

        # Log the fname selected
        fname_msg = ColorText("Filename selected rfname: %s" % (rfname), "info")
        logger.debug(fname_msg)
        logging.debug("Filename selected rfname: %s" % (rfname))

        # Return hard-coded opened filename and logging filename
        return logger, logfilename


    # ----------------- File Open Dialog Box Method ----------------

    # File Open File Dialog Method
    def openFileDialog(self):
        global rfname, currecv_tab, logger, logfilename, buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fname = QtWidgets.QFileDialog.getOpenFileName(None, "Open File Dialog", "All Files (*)", options=options)[0]
        # rfname = QtWidgets.QFileDialog.getOpenFileName(self, "All Files", options=options)
        # determine the type of file opened is text, hex or binary
        head, tail = os.path.splitext(fname)
        filename = os.path.basename(fname)

        if (tail=='.txt' or tail=='.cap' or tail=='.py'):
            # open file in the current Recv selected Tab and save filename in rfname
            rfname = fname
            # print("rfname: %s", (rfname))
            logging.debug("rfname: %s" % (rfname))


        # ----------- Initialize Variables, Logger(s) -------------
            # *** 12-6-19 added MainWindow_EXEC. in front of init_logger which allowed this function to be moved into the MainWindow_EXEC() FCN without errors! **** ---
            logger, logfilename = MainWindow_EXEC.init_logger(self, rfname)

            if rfname is '':
                rdata = ''
                return rfname, rdata
            try:
                with open(rfname, 'r') as rf:
                    try:
                        with rf:
                            rdata = rf.read()

                            # call the Editor to read the captured text file into the last selected currecv_tab(0..3) text box
                            self.editor()

                            # check which Recv Tab is currently selected
                            if currecv_tab == 0:
                                self.ui.recv_pmoncap.setText(rdata)
                                buffer_pmon = self.ui.recv_pmoncap.toPlainText()

                            elif currecv_tab == 1:
                                self.ui.recv_payload2.setText(rdata)
                                buffer_payload2 = self.ui.recv_payload2.toPlainText()

                            elif currecv_tab == 2:
                                self.ui.recv_decompmsg.setText(rdata)
                                buffer_decompmsg = self.ui.recv_decompmsg.toPlainText()

                            elif currecv_tab == 3:
                                self.ui.recv_hexdump.setText(rdata)
                                buffer_hexdump = self.ui.recv_hexdump.toPlainText()

                            else:
                                logging.warning("Wrong Tab Selected!")

                            self.ui.capfileLineEdit.setText(filename)

                            return rfname, rdata

                    except Exception as e:
                        QMessageBox.warning(None, 'Cannot open file', 'Can not open file {}:\n{}'.format(rfname, e))
                        rdata = ''
                        return rfname, rdata
            
            except IOError:
                rfname = ''
                rdata = ''
                return rfname, rdata
        
        else:
            rdata = ''
            return rfname, rdata


    #  Open PMON Text Editor Window Method - within Main Window
    def editor(self):
        global buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump

        self.textEdit = QtWidgets.QTextEdit()
        # self.setCentralWidget(self.textEdit)




    # --------------------------------------------------------------
 

    # Method to cut text in any QTextEdit buffer
    def cut_text(self):
        pass

    # Method to copy text in any QTextEdit buffer
    def copy_text(self):
        pass

    # Method to paste text in any QTextEdit buffer
    def paste_text(self):
        pass

    def clipboardChanged(self):
        global buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump

        text = QApplication.clipboard().text()
        # print(text)
        logging.debug("text = %s" % (text))

        if currecv_tab == 0:
            buffer_pmon = self.ui.recv_pmoncap.toPlainText()
        elif currecv_tab == 1:
            buffer_payload2 = self.ui.recv_payload2.toPlainText()
        elif currecv_tab == 2:
            buffer_decompmsg = self.ui.recv_decompmsg.toPlainText()
        elif currecv_tab == 3:
            buffer_hexdump = self.ui.recv_hexdump.toPlainText()
       
        # self.b.insertPlainText(text + '\n')


    # Method to update the (4) recvTabWidget global buffers whenever actionCut, actionCopy or action Paste is .triggered
    def update_buffers(self):
        global currecv_tab, buffer_log, buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump

        # check which Recv Tab is currently selected
        buffer_pmon = self.ui.recv_pmoncap.toPlainText()
        buffer_payload2 = self.ui.recv_payload2.toPlainText()
        buffer_decompmsg = self.ui.recv_decompmsg.toPlainText()
        buffer_hexdump = self.ui.recv_hexdump.toPlainText()
        buffer_log = self.ui.logTextEdit.toPlainText()

        # debug print current state of global vars.
        logging.debug("buffer_pmon contains: %s" % (buffer_pmon))
        logging.debug("buffer_payload2 contains: %s" % (buffer_payload2))
        logging.debug("buffer_decompmsg contains: %s" % (buffer_decompmsg))
        logging.debug("buffer_hexdump contains: %s" % (buffer_hexdump))
        logging.debug("buffer_log contains: %s" % (buffer_log))
       

    # Method to return which Recv Tab was selected for the Open Dialog functions
    def chkrecv_tabIndex(self):
        global currecv_tab, buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump
        currecv_tab = self.ui.recv_tabWidget.currentIndex()

        # debug print current state of global vars.
        logging.debug("currecv_tab selected: %s" % (currecv_tab))
        self.update_buffers()

    # --------------------------------------------------------------
 

    def assy_capture(self):
        pass

    def assy_payload2(self):
        pass


    # ---------------------------------------------------------------
    # Convert PMON Capture buffer to hex dump
    def recv_capture_hexdump(self):
        self.pmoncap = self.ui.recv_pmoncap.toPlainText()
        self.pmoncap_hexdump = hex_dump(self.pmoncap, length=16)
        self.ui.recv_hexdump.setText(self.pmoncap_hexdump)
        # QTabWidget method to set currecv_tab to 4th Hexdump tab        
        buffer_hexdump = self.ui.recv_hexdump.toPlainText()  
        self.ui.recv_tabWidget.setCurrentIndex(3)
        currecv_tab = self.ui.recv_tabWidget.currentIndex()



    # Convert PAYLOAD2 buffer to hex dump
    def recv_payload2_hexdump(self):
        self.payload2 = self.ui.recv_payload2.toPlainText()
        self.payload2_hexdump = hex_dump(self.payload2, length = 16)
        self.ui.recv_hexdump.setText(self.payload2_hexdump)

        # QTabWidget method to set currecv_tab to 4th Hexdump tab
        buffer_hexdump = self.ui.recv_hexdump.toPlainText()
        self.ui.recv_tabWidget.setCurrentIndex(3)
        currecv_tab = self.ui.recv_tabWidget.currentIndex()


    # Convert Decompressed buffer to hex dump
    def recv_decomp_hexdump(self):
        self.decompmsg = self.ui.recv_decompmsg.toPlainText()
        self.decompmsg_hexdump = hex_dump(self.decompmsg, length = 16)
        self.ui.recv_hexdump.setText(self.decompmsg_hexdump)

        # QTabWidget method to set currecv_tab to 4th Hexdump tab
        buffer_hexdump = self.ui.recv_hexdump.toPlainText()
        self.ui.recv_tabWidget.setCurrentIndex(3)
        currecv_tab = self.ui.recv_tabWidget.currentIndex()
       

    # ---------------------------------------------------------------

    # ------- About WinLink Monitor help dialog ----------------
    def about_winlinkmon(self):
        # Python GUI Programming Recipes Using PyQt5:
        # Calling Dialogs from the Main Window by Packt
        About = QtWidgets.QDialog()
        aui = Ui_aboutDialog()
        aui.setupUi(About)
        About.show()
        About.exec_()

    # ------- About WinLink Monitor Documentation dialog -------
    def winlinkmon_docs(self):
        Docs = QtWidgets.QDialog()
        dui = Ui_docsDialog()
        dui.setupUi(Docs)
        Docs.show()
        Docs.exec_()
      


    # ---------------------------------------------------------------

    # ------- Print Currently Selected Tab Text Buffer --------------
    def printTextBuffer(self):
        global currecv_tab, buffer_pmon, buffer_payload2, buffer_decompmsg, buffer_hexdump

        printer = QPrinter(QPrinter.HighResolution)
        
        if currecv_tab == 0:
            buffer_pmon = QPrintDialog(printer)
            if buffer_pmon.exec_() == QPrintDialog.Accepted:
                self.ui.recv_pmoncap.print_(printer)

        elif currecv_tab == 1:
            buffer_payload2 = QPrintDialog(printer)
            if buffer_payload2.exec_() == QPrintDialog.Accepted:
                self.ui.recv_payload2.print_(printer)

        elif currecv_tab == 2:
            buffer_decompmsg = QPrintDialog(printer)
            if buffer_decompmsg.exec_() == QPrintDialog.Accepted:           
                self.ui.recv_decompmsg.print_(printer)

        elif currecv_tab == 3:
            buffer_hexdump = QPrintDialog(printer)
            if buffer_hexdump.exec_() == QPrintDialog.Accepted:           
                self.ui.recv_hexdump.print_(printer)

    # ------- Print Log Text Buffer FCN -----------------------------
    def printLogBuffer(self):
        global buffer_log
        printer = QPrinter(QPrinter.HighResolution)
        buffer_log = self.ui.logTextEdit.toPlainText()
        buffer_log = QPrintDialog(printer)

        if buffer_log.exec_() == QPrintDialog.Accepted:
            self.ui.logTextEdit.print_(printer)

    # ------- Reset and Clear FCN -----------------------------------
    def reset_clear(self):
        # clear all tab QTextEdit buffers
        self.pmoncap = self.ui.recv_pmoncap.clear()
        self.payload2 = self.ui.recv_payload2.clear()
        self.decompmsg = self.ui.recv_decompmsg.clear()
        self.buffer_hexdump = self.ui.recv_hexdump.clear()
        self.buffer_log = self.ui.logTextEdit.clear()

        # select 1st tab
        self.ui.recv_tabWidget.setCurrentIndex(0)
        currecv_tab = self.ui.recv_tabWidget.currentIndex()


    # Convert recvPmon Capture File in Tab 1 to recvPayload2 in Tab 2
    def recvpmon2payload2(self):
        global buffer_pmon, rfname

        logging.warning("********** Received PMON CAPTURE to PAYLOAD2 Binary Data ********** \n")

        # Step 1: Call openComDelTextFile FCN ------------------
        # Open WinLink PACTOR III Modem Capture Text File:
        #   a) captured_data = openComDelTextFile(fname)
        #   b) Open Comma Delimited Text File and reads in line by line Storing the ASCII Header parameters of each payload with matching PAYLOAD1: {TYPE: int} sequentially in a dictionary.

        if buffer_pmon:
            self.captured_data, self.pmon_binlen = openComDelTextFile(rfname)
            self.ui.recv_payload2.setText(self.captured_data)
            logging.debug("PMON Capture to Compressed PAYLOAD2 Finished!")

            # added 12-10-19 write pmon_binlen to GUI PAYLOAD2 tab
            self.ui.payload2LineEdit.setText(str(self.pmon_binlen))

            # QTabWidget method to set current RX Tab to 2nd tab
            self.ui.recv_tabWidget.setCurrentIndex(1)
            currecv_tab = self.ui.recv_tabWidget.currentIndex()

            recvpmon2payload2_status = True

        else:
            recvpmon2payload2_status = False
            logging.debug("buffer_pmon is empty!")

        # return recvpmon2payload2_status


    # Convert recvPayload2 in Tab 2 to Decompressed Message in Tab 3
    def recvpayload2decompmsg(self):
        global buffer_payload2

        logging.warning("********** Received PAYLOAD2 to Decompressed Message ********** \n")

        buffer_payload2 = self.ui.recv_payload2.toPlainText()
        captured_data = buffer_payload2

        # Step 2: Call BinMatch FCN ----------------------------
        # Call BinMatch(captured_data, logger)
        # Find the binstart_match pattern that separates the LZHUF_ascii header from the LZHUF_binary hexbyte message
        # Returns:
        #   binmatch_status = True (found binmatch_pattern = "003000") / False (not found)
        #   binmatch_loc = tuple(start, end) of binmatch_pattern location

        if buffer_payload2:     # check buffer_payload2 is not empty
            logging.debug("Compressed PAYLOAD2 contains Hexbyte array to Decompress \n")

            binmatch_status, binmatch_loc = BinMatch(captured_data, logger)
            logging.debug("Returned Patterns: binmatch_status = %s,  binmatch_loc = %s" % (binmatch_status, binmatch_loc))
        
        else:
            logging.warning("Payload2 Buffer is empty!")

        # Step 3: Call BinStart FCN ----------------------------
        # Call BinStart(binmatch_status, captured_data, logger)
        # Find the FBBPacketStart (e.g. "02FA"), _Val = "02" and its Tuple(start, end) location.
        # Returns:
        #   binstart_status = True (found binstart_loc pattern == "02") 
        #   binstart_loc = Tuple(start, end) of binstart_loc pattern

        if binmatch_status:
            # binstart_status, binstart_loc = winlinkmon_binstartloc(self, binmatch_status, captured_data, logger)
            binstart_status, binstart_loc = BinStart(binmatch_status, captured_data, logger)
            logging.debug("Returned Patterns: binstart_status = %s, binstart_loc = %s" % (binstart_status, binstart_loc))
        else:
            pass

        # Step 4: Call LZHUF_Packet FCN ------------------------
        # Call LZHUF_Packet(binstart_loc, captured_data, logger)
        # Check for patterns:
        #   binstart_match = "003000"
        #   FBBPacketStart = e.g. "02FAxxxx", FBBPacketStart_Val = "02"
        # Returns:
        #   packet_status= True (found e.g. 8703)
        #   lzhufdeclen = Decimal Value of hexbyte message data
        #   binlength_loc = Tuple(start, end) pf 8-byte binlength (e.g. 87030000)
        # packet_status, lzhufdeclen, binlength_loc

        if binstart_status == True:
            # packet_status, lzhufdeclen, binlength_loc = winlinkmon_packet(self, binstart_loc, captured_data, logger)
            packet_status, lzhufdeclen, binlength_loc = LZHUF_Packet(binstart_loc, captured_data, logger)
            logging.debug("Returned Patterns: packet_status= %s, lzhufdeclen = %s" % (packet_status, lzhufdeclen))
        else:
            pass

        # Step 5: Call LZHUF_Split FCN -------------------------
        # Call LZHUF_Split(binmatch_loc, captured_data, logger)
        # Splits the LZHUF_ascii hexbyte header portion of the hexbyte_array from the LZHUF_binary hexbyte message portion 
        # Returns:
        #   binsplit_status = True (successfully split hexbyte_array header from message data)
        #   lzhuf_header_len = length of header lzhuf_data[0]
        #   lzhuf_compdata_len = length of hexbyte message lzhuf_data[1]
        #   lzhuf_data[0] = lzhuf_ascii hexbyte header portion
        #   lzhuf_data[1] = lzhuf_binary hexbyte message portion

        # if packet status check not in original working program
        if packet_status == True:
            if self.binmatch == True and binmatch_status == True:
                # binstart_match == "003000"
                binsplit_status, lzhuf_binary_len, lzhuf_ascii, lzhuf_binary = LZHUF_Split(binmatch_loc, captured_data, logger)
                logging.debug("Returned Patterns: binsplit_status = %s, lzhuf_binary_len = %s, lzhuf_data[0] = %s, lzhuf_data[1] = %s" % (binsplit_status, lzhuf_binary_len, lzhuf_ascii, lzhuf_binary))

            else:
                # binstart_match not found or lzhuf_binlen not found
                lzhuf_binary = captured_data
                lzhuf_binary_len = len(lzhuf_binary)
                logging.error("packet_status= False, Binary Length not found!, Abort further processing!")
                logging.debug("Returned Patterns: lzhuf_binary = %s" % (lzhuf_binary))
                # lzhuf_compdata_len = ???
                binsplit_status = False
        else:
            pass

        # Step 6: Call LZHUF_StripFBB FCN ----------------------
        # Call LZHUF_StripFBB(binstart_status, binlength_loc, lzhuf_binary, logger)
        # Strips the 8-byte FBB Header before the binlength_loc
        # Returns:
        #   stripfbb_status = True (successfully strips 1st 8-bytes up to binlength_loc)
        #   lzhuf_stripfbb_len = new length of lzhuf_binary data
        #   lzhuf_stripfbb = lzhuf_binary data stripped of 1st 8-bytes

        if binsplit_status == True:
            if  binstart_status == True:
                # binstart pattern (e.g. "02FA") was found
                stripfbb_status, lzhuf_binary_len, lzhuf_binary = LZHUF_StripFBB(binstart_status, binlength_loc, lzhuf_binary, logger)
            else:   
                lzhuf_binary_len = len(lzhuf_binary)
                stripfbb_status = False
        else:
            pass

        # Step 7: Call LZHUF_Padding FCN -----------------------
        # def winlinkmon_padinsert(self, stripfbb_status, binlength_loc, lzhuf_binary_len, lzhuf_binary):
        # (optional) Call LZHUF_Padding(stripfbb_status, binlength_loc, lzhuf_binary, logger)
        # Inserts 8-bytes "00000000" of padding after FBBPacketLen (e.g. "87 03") in lzhuf_data[1] Compressed binary portion:
        # Returns:
        #   lzhufpad_status = True (successfully padded binlength, now 16-bytes)
        #   lzhuf_paddata_len = new length of 8-zero's padded lzhuf_binary data_len
        #   lzhuf_paddata = lzhuf_binary data padded with 8-zero's
        # Note: FBB Packet Length may be more than 2 hexbyte pairs long!!

        if self.padinsert == True and stripfbb_status == True:
            lzhufpad_status, lzhuf_binary_len, lzhuf_binary = LZHUF_Padding(stripfbb_status, binlength_loc, lzhuf_binary, logger)
            
        elif self.padinsert == True and stripfbb_status == False:
            
            logging.debug("PADINSERT = %s, stripfbb_status = %s, Binary Length not found!, Abort further processing!" % (self.padinsert, stripfbb_status))
            lzhufpad_status = False       

        else:
            # PADINSERT == False and packet_status== False

            logging.error("PADINSERT = %s, packet_status= %s, Either PADINSERT == False OR Binary Length not found!" % (self.padinsert, stripfbb_status))
            lzhufpad_status = False

        # Step 8: Call LZHUF_Strip025B FCN ---------------------
        # (optional) Call LZHUF_Strip025B(lzhuf_binary)
        # Strip the Compressed Padded Binary string of bin025B_match if it exists from from lzhuf_binary, otherwise return original lzhuf_binary data
        #  ---  for some odd reason not defined!!!
        # Return:
        #   bin025B_status = True (successfully found and striped these 4-hexbytes)
        #   bin025B_loc = Tuple(start, end) location of the bin025B pattern
        #   lzhuf_bindata_len = length of strip025B lzhuf_binary data
        #   lzhuf_bindata = strip025B lzhuf_binary data
        if self.strip025B == True:
            bin025B_status, bin025B_loc, lzhuf_binary_len, lzhuf_binary = LZHUF_Strip025B(lzhuf_binary)
            logging.debug("Returned Patterns: bin025B_status = %s, bin025B_loc = %s, lzhuf_binary_len = %s, lzhuf_binary = %s" % (bin025B_status, bin025B_loc, lzhuf_binary_len, lzhuf_binary))

        else:
            # lzhuf_bindata = lzhuf_binary
            lzhuf_binary_len = len(lzhuf_binary)
            bin025B_status = False

        # Step 9: Call LZHUF_Strip16 FCN -----------------------
        # Call LZHUF_Strip16(stripfbb_status, lzhuf_binary)
        # Only strip the 1st 16-hexbytes before the start of LZHUF Compressed Binary File
        #   if lzhuf_pad_status and stripfbb_status == True
        # Return:
        #   strip16_status = True (successfully stripped these 16-hexbytes)
        #   lzhuf_strip16data_len = length of strip16 lzhuf_binary data 
        #   lzhuf_strip16data = strip16 lzhuf_binary data 
        # Example: Strip the 1st 16 bytes "87 03 00 00 00 00 00 00" before actual start of LZHUF Compressed Binary Data
        if self.strip16 == True:
            strip16_status, lzhuf_binary_len, lzhuf_binary = LZHUF_Strip16(stripfbb_status, lzhuf_binary)
            logging.debug("Returned Patterns: strip16_status = %s, lzhuf_binary_len = %s, lzhuf_binary = %s" % (strip16_status, lzhuf_binary_len, lzhuf_binary))
        else:
            strip16_status = False
            logging.debug("Returned Patterns: strip16_status = %s, lzhuf_binary_len = %s, lzhuf_binary = %s" % (strip16_status, lzhuf_binary_len, lzhuf_binary))       
            
        # Step 10: Call LZHUF_CheckEOF FCN ---------------------
        # (optional) Call LZHUF_CheckEOF(lzhuf_binary_len, lzhuf_binary)
        # Strip the End of File hexbyte = "04" (2nd last byte of lzhuf_binary before last CRC byte)
        # Returns:
        #   lzhuf_checkeof_status = True (successfully found and stripped)
        #   lzhuf_eofdata_len = length of strip eof lzhuf_binary data 
        #   lzhuf_eofdata = stripped eof lzhuf_binary data 

        if self.stripeof == True:
            lzhuf_checkeof_status, lzhuf_eof, lzhuf_compdata_noeof = LZHUF_CheckEOF(lzhuf_binary_len, lzhuf_binary)
            logging.debug("Returned Patterns: lzhuf_checkeof_status = %s, lzhuf_eof = %s, lzhuf_compdata_noeof = %s" % (lzhuf_checkeof_status, lzhuf_eof, lzhuf_compdata_noeof))
        else:
            lzhuf_compdata_noeof = lzhuf_binary
            lzhuf_checkeof_status = False

        # Step 11A: Call LZHUF_RunDecompress FCN ---------------
        # (optionally) run if SUBRUN == True
        #   Call LZHUF_RunDecompress(wfname, lzhuf_compdata_noeof)
        #   a) Converts the wfname into two filenames:
        #       wfname + _Run_LZHUF.bin is used to call LZHUF_WriteBin() 
        #       to write lzhuf_binary data as in the input in the s.run() command
        #       wfname + _Run_Uncomp.txt is the output of the s.run() command
        #   b) try subprocess.run("lzhuf.exe", "d", wfname_Run_LZHUF.bin, wfname_Run_Uncomp.txt) to execute an external LZHUF.exe Windows 10 Program to Decompress a binary file if SUBRUN = True (enabled)
        # Returns:
        #   lzhuf_status1 = True if s.run() successfully completed
        #   rc = s.run() returncode
        #   stdout = s.run() standard output
        #   stderr = s.run() standard error (# binary bytes decompressed)

        if self.runpopen == True:
            logging.debug("lzhuf_compdata_noeof has %s bytes comprised of the following: %s" % (len(lzhuf_compdata_noeof), lzhuf_compdata_noeof))
            lzhuf_status1, rc, stdout, stderr, recvTextFile = LZHUF_RunDecompress(rfname, lzhuf_compdata_noeof)
            logging.debug("Returned Patterns: lzhuf_status1 = %s, rc = %s, stdout = %s, stderr = %s" % (lzhuf_status1, rc, stdout, stderr))

            stderr_run = stderr.lstrip().rstrip('\n')
            runbindeclen = int(stderr_run)

            # runbindeclen = int(stderr[0:-1])

            if runbindeclen == lzhufdeclen:
                logging.debug("subprocess.run successfully processed correct %s number of bytes" % (lzhufdeclen))
            else:
                logging.warning("subprocess.run resulted in runbindeclen = %s numbytes NOT MATCHING lzhufdeclen = %s numbytes" % (runbindeclen, lzhufdeclen))

            # if RunDecompress successful, open *.txt file and output to self.ui.recv_decompmsg (self.buffer_decompmsg)
            if lzhuf_status1.returncode == 0:
                lzhuf_status = True
                self.buffer_decompmsg = openDecompMsg(self, lzhuf_status, recvTextFile)
            else:
                lzhuf_status = False
                logging.error("subprocess.run was unsuccessful!")
                
            # commented out on 12-13-19 to remove bool error crashing compiled/executable program

            # return lzhuf_status

        # Step 11B: Call LZHUF_PopenDecompress FCN -------------
        # (optionally run if SUBPOPEN == True) 
        #   Call LZHUF_PopenDecompress(wfname, lzhuf_compdata_noeof)
        #   a) Converts the wfname into two filenames:
        #       wfname + _Popen_LZHUF.bin is used to call LZHUF_WriteBin() 
        #       to write lzhuf_binary data as in the input in the s.run() command
        #       wfname + _Popen_Uncomp.txt is the output of the s.run() command
        #   b) Executes external program s.run("lzhuf.exe", "d", wfname_Popen_LZHUF.bin, wfname_Popen_Uncomp.txt)
        # Returns:
        #   lzhuf_status2 = True if s.Popen() successfully completed
        #   rc = s.Popen() returncode
        #   output = s.run() standard output
        #   errors = s.run() standard errors (# binary bytes decompressed)

        if self.runpopen == False:
            logging.debug("lzhuf_compdata_noeof has %s bytes comprised of the following: %s" % (len(lzhuf_compdata_noeof), lzhuf_compdata_noeof))
            lzhuf_status2, rc, output, errors, recvTextFile = LZHUF_PopenDecompress(rfname, lzhuf_compdata_noeof)
            logging.debug("Returned Patterns: lzhuf_status2 = %s, rc = %s, output = %s, errors = %s" % (lzhuf_status2, rc, output, errors))

            if errors == "Failed!":
                popenbindeclen = -1
            else:
                popenbindeclen = int(errors.decode("utf-8")[0:-2])

            if popenbindeclen == lzhufdeclen:
                logging.debug("subprocess.Popen successfully processed correct %s number of bytes" % (lzhufdeclen))
            else:
                logging.warning("subprocess.Popen resulted in popenbindeclen = %s numbytes NOT MATCHING lzhufdeclen = %s numbytes" % (popenbindeclen, lzhufdeclen))

            # if POpenDecompress successful, open *.txt file and output to self.ui.recv_decompmsg (self.buffer_decompmsg)
            if rc == 0:
                lzhuf_status = True
                self.buffer_decompmsg = openDecompMsg(self, lzhuf_status, recvTextFile)
            else:
                lzhuf_status = False
                logging.error("subprocess.POpen was unsuccessful!")

            return lzhuf_status

    # Convert recvPmon Capture File in Tab 1 to Decompressed Message in Tab 3
    def recvpmon2decompmsg(self):
        pass
        # recvpmon2payload2()
        # recvpayload2decompmsg()


    # Method/FCN write_checkboxes pass in argument n that indicates which QCheckBox's State was changed.  WinLinkMon Logic Steps 1 - 11A/B execute based on the True State updated in this FCN.  All False State(s) shall not execute and are bypassed in the logic step sequence.
    def write_checkboxes(self, n):
        if (n == 1):
            self.verbose = bool(self.ui.chk_verbose.checkState())
            logging.debug("chk_verbose state changed to: %s" % (self.verbose))

        elif (n == 2):
            self.openbin = bool(self.ui.chk_openbin.checkState())
        elif (n == 3):
            self.binmatch = bool(self.ui.chk_binmatch.checkState())
        elif (n == 4):
            self.padinsert = bool(self.ui.chk_padinsert.checkState())
        elif (n == 5):
            self.strip025B = bool(self.ui.chk_strip025B.checkState())
        elif (n == 6):
            self.strip16 = bool(self.ui.chk_strip16.checkState())
        elif (n == 7):
            self.stripeof = bool(self.ui.chk_stripeof.checkState())
        elif (n == 8):
            self.runpopen = bool(self.ui.chk_runpopen.checkState())

        else:
            logging.debug("Error: No Checkboxes selected")


    # Save File Dialog Function - 11/25/19 TBD
    def saveFileDialog(self, wfname, wrdata):
        pass


    # The simple pre-check loop FCN searches for list patterns in a string read from the fileOpen call function. Must pass in logger object instance.
    # 10-5-19 changed all References of bindata2 to captured_data
    def precheck_patterns(self, captured_data, logger):
        # Two Hex Byte pairs search patterns
        # patterns = ["FC EM", "00 30 00", "02 FA", "87 03"]
        patterns = ["4643454D", "003000", "02FA", "8703", "025B"]
        patterns_found = []
        patterns_notfound = []

        for pattern in patterns:
            # Looking for (4) patterns in captured_data
            pattern_msg = ColorText("Looking for Pattern: %s in captured_data: " % (pattern), "info")
            logger.info(pattern_msg)
            logging.debug("Looking for Pattern: %s in captured_data: " % (pattern))

            # Search pattern in captured_data string
            if re.search(pattern, captured_data):
                # pattern match was found:
                m = re.search(pattern, captured_data, flags=0)
                pattern_msg = ColorText("Pattern: %s was found at %s" % (pattern, m.span()), "info")
                # logger.info(pattern_msg)
                logging.debug("Pattern: %s was found at %s" % (pattern, m.span()))
                patterns_found.append(pattern)

            else:
                # pattern was not found!!!
                # pattern_failmsg = ColorText("Pattern: %s was not found!" % (pattern), "error")
                # logger.error(pattern_failmsg)
                logging.error("Pattern: %s was not found!" % (pattern))
                patterns_notfound.append(pattern)
        # returns patterns found and not found to calling FCN 
        return patterns_found, patterns_notfound

    # ----------- WinLink Message Monitor Logic: -------------------


    #   Hard Coded Filenames to process
    def hardcoded_fname(self):
        fname1 = "2019-07-27_Message_2_Modem.bin"
        fname2 = "Message_2_Packet_01.bin"
        fname3 = "pmontransmission.cap"
        fname4 = "pmontest.cap"
        fname5 = "encode_text.bin"
        fname6 = "Message_2_Packet_All3.bin"
        fname7 = "ztemptest.bin"
        fname8 = "ztemptest_TxCompBinFile.bin"
        fname9 = "decode2_bin.txt"
        # ..Debugging Option:  Hardcode which filename is to be tested here.......
        hcfname = fname3
        # print("The test file is: ", hcfname)
        return hcfname


# ------------ New 12-13-19 Start of Main Program --------------
if __name__ == "__main__":
    MainWindow_EXEC()

