# WinLinkMon_1.0
WinLink Monitoring Program to Decompress PACTOR II, III and IV PMON Capture files to original Text Message

Dec. 12th, 2019 Initial Upload and 1st commit
@author: John Trites

WinLink Monitor Documentation
Version 1.0

The WinLink Monitoring Program is a Python 3.7.4 application using PyQt5 library components in a Qt Designer 5.11.2 Graphical User Interface (GUI).

Author:    John Trites
Date:    Dec. 12th, 2019

UPDATED DEC. 16TH, 2019 BY AUTHOR TO INSTRUCT USERS TO FIND THE (6) PMON Capture files in the "PMON Capture Files" root sub-folder (not the dist foider as was described in my 16-239 RESPONSE TO THE FEDERAL COMMUNICATIONS COMMISSION (FCC).

The author of this amateur radio WinLink Monitoring Program created for the sole purpose of demonstrating that a non-professional programmer with no prior knowledge or understanding of the details of the WinLink Messaging format, contents, compression and decompression algorithms, prior to August of 2019, successfully wrote a Python 3 program that correctly decompresses six(6) PMON captured files provided by a 3rd party from a PACTOR modem. 

The author also had no knowledge of Python 3, PyQt5, and Qt Designer prior to August of 2019.  The author also was not provided any help, useful information, answers to questions submitted to the WinLink Development team.

The WinLink Monitoring Program, Version 1.0, is provided "as is", without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose and noninfringement.  In no event shall the author or copyright holder be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use of other dealings in the software. 

The author categorially states there is no use, implementation, or execution of public or private encryption keys or user entered "keyless" input(s) to implement any encryption and decryption of any kind. 

Any subject matter expert can clearly demonstrate that all encryption systems require specific knowledge only known by the sender and receiver for public and/or private key systems or specific coded entries in a so called "keyless" encryption system in order for the system to work correctly in both directions.  No keys or specific coded entries means no encryption and no decryption!

Further, any claims of "effective encryption" by implementing publically available LZHUF.c compression and decompression algorithms used by ham radio operators running RMS Express and other forms of Windows, MAC or Linux WinLink messaging systems since 1986 is a flawed argument!  

LZHUF is the only decompression algorithm used in this WinLink Monitoring Version 1.0 application program.  WinLinkMon Ver.1.0 does not support compression of an original message.


Table of Contents
1.0 Menu Bar
    1.1 File Menu Functions:
        1.1.1 New File (not supported in Ver. 1.0)
        1.1.2 Open File - opens File using File Dialog in currently selected tab.
        1.1.3 Save File (not supported in Ver. 1.0)
        1.1.4 Save As File (not supported in Ver. 1.0)
        1.1.5 Print Log (Ctrl + L/l)
        1.1.6 Print Text Buffer (Ctrl + P/p)
        1.1.7 Close (not supported in Ver. 1.0)
        1.1.8 Quit - Quits/Exits WinLink Monitor
    1.2 Edit Menu Functions:
        1.2.1 Undo (Ctrl + U/u)
        1.2.2 Redo (Ctrl + R/r)
        1.2.3 Cut (Ctrl + X/x)
        1.2.4 Copy (Ctrl + C/c)
        1.2.5 Paste (Ctrl + V/v)
    1.3 Hex Dump Functions:
        1.3.1 PMON Capture to Hex Dump
        1.3.2 PAYLOAD2 to Hex Dump
        1.3.3 DecompMst to Hex Dump
    1.4 Assembly Functions: (not supported in Ver. 1.0)
    1.5 Conversion Functions:
        1.5.1 PMON Capture to PAYLOAD2
        1.5.2 PAYLOAD2 to DecompMsg
        1.5.3 PMON Capture to DecompMsg (not supported in Ver. 1.0)
    1.6 Help
        1.6.1 About
        1.6.2 Documentation
2.0 Checkboxes
    2.1 PRECHECK
    2.2 OPENBIN
    2.3 BINMATCH
    2.4 PADINSERT
    2.5 STRIP025B
    2.6 STRIP16
    2.7 STRIPEOF
    2.8 RUNPOPEN

3.0 Operations:
    3.1 Loading a PACTOR PMON Capture File
    3.2  Recv PMON Capture to Compressed PAYLOAD2
    3.3 Recv Compressed PAYLOAD2 to Decompressed MSG


Version 1.0 Release Documentation

1.1 File Menu Functions:

1.1.1 New File
This function is not supported in the Version 1.0 release.  When supported, it will create a new form dialog that will provide the user with a clean edit text box to create and save a custom PMON Capture file.

1.1.2 Open File
Opens a File Dialog box that provides the user with capabilities of selecting folder and filename to open into the currently selected tab. 
Only filenames with .txt, .cap, and .bin extenstion are supported in Version 1.0 release.

1.1.3 Save File
This function is not supported in the Version 1.0 release.  When supported, it will save the last opened filename with the contents of the currently selected tab or log edit box.

1.1.4 Save As File
This function is not supported in the Version 1.0 release.  When supported, it will open a Save File Dialog that will provide the user with capabilities of selecting folder and filename to save from the currently selected tab or log edit box.

1.1.5 Print Log Buffer
Clicking this menubar function or entering (Ctrl + L/l) on the keyboard Opens a Print Dialog box that provides the user with capabilities of selecting a printer from the user's available printers or PDF (if installed on this computer) and Printing the  Log buffer's contents.

1.1.6 Print Text Buffer
Clicking this menubar function or entering (Ctrl + P/p) on the keyboard Opens a Print Dialog box that provides the user with capabilities of selecting a printer from the user's available printers or PDF (if installed on this computer) and Printing the currently selected tab's contents.

1.1.7 Delete File
This function is not supported in the Version 1.0 release.  When supported, it will open a Delete File Dialog box that will provide the user with capabilities of selecting folder and filename to delete the selected file.

1.1.8 Quit
Quits/Exits the WinLink Monitor application program.
----------------------------------------------------------------------------------------------------------
1.2 Edit Menu Functions:

1.2.1 Undo
Clicking this menubar function or entering (Ctrl + U/u) on the keyboard will Undo the last entered Windows keystrokes and/or functions.

1.2.2 Redo 
Clicking this menubar function or entering (Ctrl + R/r) on the keyboard will Redo the last deleted Windows keystrokes and/or functions.

1.2.3 Cut 
Clicking this menubar function is not supported in the Ver. 1.0 release.  However, entering (Ctrl + X/x) on the keyboard will cut the selected text in the currently selected tab or log buffer.

1.2.4 Copy  
Clicking this menubar function is not supported in the Ver. 1.0 release.  However, entering (Ctrl + C/c) on the keyboard will copy the selected text in the currently selected tab or log buffer.

1.2.5 Paste
Clicking this menubar function is not supported in the Ver. 1.0 release.  However, entering (Ctrl + V/v) on the keyboard will paste the selected text in the currently selected tab or log buffer.

----------------------------------------------------------------------------------------------------------
1.3 Hex Dump Functions:

1.3.1 PMON Capture to Hex Dump
Converts the contents of the 1st PMON Capture tab text edit buffer to a 3-column hexadecimal dump of line numbers, 16 hexbyte pairs and ascii string into the 4th Hex Dump tab's text edit buffer.

1.3.2 PAYLOAD2 to Hex Dump
Converts the contents of the 2nd PAYLOAD2 tab text edit buffer to a 3-column hexadecimal dump of line numbers, 16 hexbyte pairs and ascii string into the 4th Hex Dump tab's text edit buffer.

1.3.3 DecompMst to Hex Dump
Converts the contents of the 3rd DecompMsg tab text edit buffer to a 3-column hexadecimal dump of line numbers, 16 hexbyte pairs and ascii string into the 4th Hex Dump tab's text edit buffer.
----------------------------------------------------------------------------------------------------------
1.4 Assembly Functions: (not supported in Ver. 1.0)
----------------------------------------------------------------------------------------------------------
1.5 Conversion Functions:

1.5.1 PMON Capture to PAYLOAD2
Process Step 1 Parses an opened PMON Capture file in the 1st tab, looks for PACTOR "FC EM" in PAYLOAD2, then concatenates all PAYLOAD2 hexbytes for PAYLOAD1 Type 8 messages (only) into one block and finally placin the concatentated hexbuffer into this application's PAYLOAD2 tab.

Process Step 1:
# -------------- openComDelTextFile FCN - Step 1 ---------------
# Open WinLink PACTOR III Modem Capture Text File:
#   a) captured_data = openComDelTextFile(fname)
#   b) Open Comma Delimited Text File and reads in line by line Storing the ASCII Header parameters of each payload with matching PAYLOAD1: {TYPE: int} sequentially in a dictionary.
# original - def openComDelTextFile(rfname):
# new - def openComDelTextFile(buffer_pmon): 
# passes in buffer_pmon in recv_tabWidget(currecv_tab = 0)


1.5.2 PAYLOAD2 to DecompMsg
Process Steps 2 through 11A/11B execute a sequence of functions on the concatentated hexbuffer located in the PAYLOAD2 tab, as a result of 1.5.1 PMON Capture to PAYLOAD2, that converts the hexbuffer data into the original Decompressed Message.

Process Steps 2 through 11A/11B include:
# ----------------- BinMatch FCN - Step 2 ----------------------
# Call BinMatch(hexbyte_array, logger)
# Find the binstart_match pattern that separates the LZHUF_ascii header from the LZHUF_binary hexbyte message
# Returns:
#   binmatch_status = True (found binmatch_pattern = "003000") / False (not found)
#   binmatch_loc = tuple(start, end) of binmatch_pattern location

# ----------------- BinStart FCN - Step 3 ----------------------
# Call BinStart(binmatch_status, captured_data, logger)
# Find the FBBPacketStart (e.g. "02FA"), _Val = "02" and its Tuple(start, end) location.
# Returns:
#   binstart_status = True (found binstart_loc pattern == "02") 
#   binstart_loc = Tuple(start, end) of binstart_loc pattern

# ----------------- LZHUF_Packet FCN - Step 4 ------------------
# Call LZHUF_Packet(binstart_loc, captured_data, logger)
# Check for patterns:
#   binstart_match = "003000"
#   FBBPacketStart = e.g. "02FAxxxx", FBBPacketStart_Val = "02"
# Returns:
#   packet_status= True (found e.g. 8703)
#   lzhufdeclen = Decimal Value of hexbyte message data
#   binlength_loc = Tuple(start, end) pf 8-byte binlength (e.g. 87030000)

# ----------------- LZHUF_Split FCN - Step 5 -------------------
# Call LZHUF_Split(binmatch_loc, captured_data, logger)
# Splits the LZHUF_ascii hexbyte header portion of the hexbyte_array from the LZHUF_binary hexbyte message portion 
# Returns:
#   binsplit_status = True (successfully split hexbyte_array header from message data)
#   lzhuf_header_len = length of header lzhuf_data[0]
#   lzhuf_compdata_len = length of hexbyte message lzhuf_data[1]
#   lzhuf_data[0] = lzhuf_ascii hexbyte header portion
#   lzhuf_data[1] = lzhuf_binary hexbyte message portion

# -------------- LZHUF_StripFBB FCN - Step 6 -------------------
# Call LZHUF_StripFBB(binstart_status, binlength_loc, lzhuf_binary, logger)
# Strips the 8-byte FBB Header before the binlength_loc
# Returns:
#   stripfbb_status = True (successfully strips 1st 8-bytes up to binlength_loc)
#   lzhuf_stripfbb_len = new length of lzhuf_binary data
#   lzhuf_stripfbb = lzhuf_binary data stripped of 1st 8-bytes

# -------------- LZHUF_Padding FCN - Step 7 --------------------
# (optional) Call LZHUF_Padding(stripfbb_status, binlength_loc, lzhuf_binary, logger)
# Inserts 8-bytes "00000000" of padding after FBBPacketLen (e.g. "87 03") in lzhuf_data[1] Compressed binary portion:
# Returns:
#   lzhufpad_status = True (successfully padded binlength, now 16-bytes)
#   lzhuf_paddata_len = new length of 8-zero's padded lzhuf_binary data_
#   lzhuf_paddata = lzhuf_binary data padded with 8-zero's

# -------------- LZHUF_Strip025B FCN - Step 8 ------------------
# (optional) Call LZHUF_Strip025B(lzhuf_binary)
# # Strip the Compressed Padded Binary string of bin025B_match if it exists from from lzhuf_binary, otherwise return original lzhuf_binary data
#  ---  for some odd reason not defined!!!
# Return:
#   bin025B_status = True (successfully found and striped these 4-hexbytes)
#   bin025B_loc = Tuple(start, end) location of the bin025B pattern
#   lzhuf_bindata_len = length of strip025B lzhuf_binary data
#   lzhuf_bindata = strip025B lzhuf_binary data

# ---------------- LZHUF_Strip16 FCN - Step 9 ------------------
# (optional) Call LZHUF_Strip16(stripfbb_status, lzhuf_binary)
# Only strip the 1st 16-hexbytes before the start of LZHUF Compressed Binary File
#   if lzhuf_pad_status and stripfbb_status == True
# Return:
#   strip16_status = True (successfully stripped these 16-hexbytes)
#   lzhuf_strip16data_len = length of strip16 lzhuf_binary data 
#   lzhuf_strip16data = strip16 lzhuf_binary data 
# Example: Strip the 1st 16 bytes "87 03 00 00 00 00 00 00" before actual start of LZHUF Compressed Binary Data

# ------------------ LZHUF_CheckEOF FCN - Step 10 -------------------
# (optional) Call LZHUF_CheckEOF(lzhuf_binary_len, lzhuf_binary)
# Strip the End of File hexbyte = "04" (2nd last byte of lzhuf_binary before last CRC byte)
# Returns:
#   lzhuf_checkeof_status = True (successfully found and stripped)
#   lzhuf_eofdata_len = length of strip eof lzhuf_binary data 
#   lzhuf_eofdata = stripped eof lzhuf_binary data 

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



1.5.3 PMON Capture to DecompMsg
Clicking this menubar function is not supported in the Ver. 1.0 release.  When supported, clicking this function will execute 1.5.1 PMON Capture to PAYLOAD2 immediately followed by 1.5.2 PAYLOAD2 to DecompMsg.
----------------------------------------------------------------------------------------------------------
    
1.6 Help Functions:

1.6.1 About
Opens a context dialog box that provides basic information about the WinLink Monitor application.  

1.6.2 Documentation
Opens a context dialog box that provides a User Manual on the supported functions in the WinLink Monitor Ver. 1.0 program.
----------------------------------------------------------------------------------------------------------
2.0 Check Boxes
Most of these are unnecessary and all should be operated in their default states which are correctly selected when first opening the program.  They were added to show flawed results when set to the wrong state.  

2.1 VERBOSE LOG (Optional / Default = Unchecked)
If checked, will execute a function to create a verbose log of all the process steps 1 through 11 shown in the Log Buffer.

2.2 OPENBIN (Optional / Default = Unchecked)
Clicking this menubar function is not supported in the Ver. 1.0 release.   When supported and if checked, will open a binary file in the currently selected tab.
  
2.3 BINMATCH (Optional / Default = Checked)
If checked, the LZHUF_ascii header is separated from the LZHUF_binary hexbyte message.

For WinLinkMon Ver. 1.0, this has been disabled from changing state.

2.4 PADINSERT (Optional / Default = Unchecked)
If checked, Inserts 8-bytes "00000000" of padding after the FBBPacketLength (e.g. "87 03") in lzhuf_data[1] Compressed Binary portion of PAYLOAD2

2.5 STRIP025B (Optional / Default = Unchecked)
If checked, Strips the Compressed Padded Binary string of bin025B_match = "02 5B", if it exists, from the lzhuf_binary string, otherwise returns original lzhuf_binary data.

2.6 STRIP16 (Optional / Default = Unchecked)
If checked and lzhuf_pad_status and stripfbb_status were both True, strips the first 16-hexbytes before the start of the LZHUF Compressed Binary File

2.7 STRIPEOF (Optional / Default = Unchecked)
If checked, strips the End of File hexbyte = "04" (2nd to last byte of lzhuf_binary before the last CRC hexbyte).

2.8 RUNPOPEN (Default = Checked)
If Checked, Executes the LZHUF_RunDecompress Function that converts the provides filename originally opened in the PMON Capture tab, calls the WriteBin FCN that converts the PAYLOAD2 hexbytes into a intermediate binary file, executes an external compiled 'c' LZHUF.exe program that converts intermediate binary file into the originally created Decompressed text message file, and places that text message file into the DecompMsg tab.

If Unchecked, Executes the LZHUF_POpenDecompress Function that converts the provides filename originally opened in the PMON Capture tab, calls the WriteBin FCN that converts the PAYLOAD2 hexbytes into a intermediate binary file, executes an external compiled 'c' LZHUF.exe program that converts intermediate binary file into the originally created Decompressed text message file, and places that text message file into the DecompMsg tab.

WinLinkMon Ver. 1.0 demonstrates minor differences between the two decompression functions is in the methods used to execute the external compiled LZHUF.exe program.
----------------------------------------------------------------------------------------------------------
3.0 Operations:

3.1 Loading a PACTOR PMON Capture File
The first step in decompressing a PMON Capture file output, saved from a PACTOR II, III, or IV modem, is to load the file with (.cap or .txt ) extensions into the 1st PMON Capture tab's Text Edit box.  This release does not support any other extensions at this time.

Menu Operations:
1) This is accomplished by clicking the menu bar File --> Open File which opens a File Dialog box. 
2) Select a PMON Capture file in the root folder or sub-folder and Click --> Open.  
3) Verify the opened PMON Capture file contains the correct information according to WinLink's message format.

3.2  Recv PMON Capture to Compressed PAYLOAD2
The second step (logic Step 1 listed in the code) in decompressing a PMON Capture file is to Strip all non-PAYLOAD2 information from the opened PMON Capture text in the PMON Capture 1st tab, Strip the comma delimiters from all PAYLOAD2 hex byte data pairs, and Concatenate all PAYLOAD2 message data into a single contiguous hex byte buffer.

Menu Operations:
1) This is accomplished by clicking the menu bar Conversion --> Recv PMON Capture to Compressed PAYLOAD2 which will execute decompression logic step 1 and output the compressed concatenated PAYLOAD2 hex byte data in the PAYLOAD2 2nd tab.
2) Verify the PAYLOAD2 buffer contains a concatenated version of ALL the PMON Capture PAYLOAD2 hex byte pairs with PAYLOAD1 in the same message showing a TYPE = 8.

3.3 Recv Compressed PAYLOAD2 to Decompressed MSG
The third step (logical Steps 2 through 11A/B listed in the code) in decompressing a PMON Capture file Strips the header portion from the data portion of the contiguous hex byte buffer in the 2nd PAYLOAD2 tab and executes an external compiled 'c' LZHUF.exe program that must reside in the same root folder of this WinLinkMon program.

Menu Operations:
1) This is accomplished by clicking the menu bar Conversion --> Recv Compressed PAYLOAD2 to Decompressed MSG which will execute decompression logic steps 2 through 11A (or 11B depending on state of the Run = checked / POpen = unchecked checkbox) and output the LZHUF uncompressed concatenated PAYLOAD2 hex byte data into the UncompMsg 3rd tab.
2) Verify the UncompMsg buffer contains the readable uncompressed text message originated by the sender.
