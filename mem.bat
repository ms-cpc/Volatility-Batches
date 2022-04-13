@echo off
cls
::Volatility Batch
:: ######################################################
:: VERSION 0.1.110303
:: SCRIPT: Volatility Batch
:: CREATION DATE: 2011-03-02
:: LAST MODIFIED: 2011-03-21
:: AUTHOR: Mark SOUTHBY
:: ######################################################
:: DESCRIPTION: Simple batch to extract System information from memory dumps and put them in text files.
:: ######################################################

::Check for volatility
:volchk
IF EXIST volatility goto begin
echo VOLATILITY NOT FOUND. PLEASE PLACE THIS BATCH IN YOUR VOLATILITY FOLDER
goto exit

:begin
::grab path1 and file name. Click
set /p path1=Full path to memory file [click and drag file from explorer to here and press enter]:
set /p exnum=FOLDER name for output [file-exhibit]:
:: Make folder 
md %exnum%

echo Extracting data from memory dump... 
echo To skip a command, press CTRL-C and select (N) to terminate batch.

echo Ident...
python vol.py ident -f %path1% >%exnum%\ident.txt

echo Connections...
python vol.py connections -f %path1% >%exnum%\connections.txt

echo DateTime...
python vol.py datetime -f %path1% >%exnum%\datetime.txt

echo Open Ports ConnScan2...
python vol.py connscan2 -f %path1% >%exnum%\connscan2.txt

echo DLL List...
python vol.py dlllist -f %path1% >%exnum%\dlllist.txt

echo Files...
python vol.py files -f %path1% >%exnum%\files.txt

echo Process List...
python vol.py pslist -f %path1% >%exnum%\pslist.txt

echo Checking for KeyBoard Buffer Plugin...
cd memory_plugins
IF EXIST keyboardbuffer.py goto kbb
echo KeyBoard Buffer not found, skipping...
cd..
goto chkps3

:kbb
echo KeyBoard Buffer (BIOS Password in ascii code)...
python vol.py keyboardbuffer -f %path1% >%exnum%\keyboardbuffer.txt

:chkps3
echo Checking for PSScan3 Plugin...
cd memory_plugins
IF EXIST psscan3.py goto pscan3
echo PSScan 3 not found, running PSScan2...
cd..
python vol.py psscan2 -f %path1% >%exnum%\psscan2.txt
goto reg

:pscan3
cd..
echo PSScan3 Found [This will take a while]...
python vol.py psscan3 -f %path1% >%exnum%\psscan3.txt

:reg
echo Registry Object Keys...
python vol.py regobjkeys -f %path1% >%exnum%\regobjkeys.txt

echo Socket Scan 2...
python vol.py sockscan2 -f %path1% >%exnum%\sockscan2.txt

echo Thread Scan...
python vol.py thrdscan2 -f %path1% >%exnum%\thrdscan2.txt

echo Registry HIVE Scan...
python vol.py hivescan -f %path1% >%exnum%\hivescan.txt

echo Module Objects 2...
python vol.py modscan2 -f %path1% >%exnum%\modscan2.txt

echo VAD Info...
python vol.py vadinfo -f %path1% >%exnum%\vadinfo.txt

echo VAD Walk...
python vol.py vadwalk -f %path1% >%exnum%\vadwalk.txt

:custom
set comnd=
echo Type custom plugin command or press ENTER to quit (Type LIST for list of commands).
echo.
set /p comnd=vol.py Command eg: python vol.py [COMMAND] -file MEMDUMP.dd:
if %comnd%== goto exit
if %comnd%==list goto list
if %comnd%==LIST goto list
python vol.py %comnd% -f %path1% >%exnum%\%comnd%.txt
goto custom

:list
echo	Supported Internel Commands:
echo		connections    	Print list of open connections
echo		connscan       	Scan for connection objects
echo		connscan2      	Scan for connection objects (New)
echo		datetime       	Get date/time information for image
echo		dlllist        	Print list of loaded dlls for each process
echo		dmp2raw        	Convert a crash dump to a raw dump
echo		dmpchk         	Dump crash dump information
echo		files          	Print list of open files for each process
echo		hibinfo        	Convert hibernation file to linear raw image
echo		ident          	Identify image properties
echo		memdmp         	Dump the addressable memory for a process
echo		memmap         	Print the memory map
echo		modscan        	Scan for modules
echo		modscan2       	Scan for module objects (New)
echo		modules        	Print list of loaded modules
echo		procdump       	Dump a process to an executable sample
echo		pslist         	Print list of running processes
echo		psscan         	Scan for EPROCESS objects
echo		psscan2        	Scan for process objects (New)
echo		raw2dmp        	Convert a raw dump to a crash dump
echo		regobjkeys     	Print list of open regkeys for each process
echo		sockets        	Print list of open sockets
echo		sockscan       	Scan for socket objects
echo		sockscan2      	Scan for socket objects (New)
echo		strings        	Match physical offsets to virtual addresses (may take a while, VERY verbose)
echo		thrdscan       	Scan for ETHREAD objects
echo		thrdscan2      	Scan for thread objects (New)
echo		vaddump        	Dump the Vad sections to files
echo		vadinfo        	Dump the VAD info
echo		vadwalk        	Walk the vad tree
echo.
echo	Supported Plugin Commands:
echo		cachedump      	Dump (decrypted) domain hashes from the registry
echo		cryptoscan     	Find TrueCrypt passphrases
echo		hashdump       	Dump (decrypted) LM and NT hashes from the registry
echo		hivedump       	Dump registry hives to CSV
echo		hivelist       	Print list of registry hives
echo		hivescan       	Scan for _CMHIVE objects (registry hives)
echo		keyboardbuffer 	Print BIOS keyboard buffer
echo		lsadump        	Dump (decrypted) LSA secrets from the registry
echo		memmap_ex_2    	Print the memory map
echo		printkey       	Print a registry key, and its subkeys and values
echo		pslist_ex_1    	Print list running processes
echo		pslist_ex_3    	Print list running processes
echo		pslist_ex_4    	Print list running processes
echo		psscan3        	scan for processes using evasion-resistant features
echo		usrdmp_ex_2    	Dump the address space for a process
echo.
goto custom

:exit

::NFAR CH
::ms-53384
