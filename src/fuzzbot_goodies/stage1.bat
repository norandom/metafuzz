=====================
rmdir /s /q c:\fuzzbot_code
ping -c 30 192.168.122.1
xcopy /d /y /s \\192.168.122.1\ramdisk\fuzzbot_code c:\fuzzbot_code\
c:\fuzzbot_code\compname /c BUGMINER-?8 
copy /y c:\fuzzbot_code\startfuzz.bat c:\AUTOEXEC.BAT && restart -r -f -t 0
