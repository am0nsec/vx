## Deus Somnum

Leverage the Windows Power Management API for code execution and defense evasion. <br>
Further information can be found here: https://vxug.fakedoma.in/papers/VXUG/Exclusive/AbusingtheWindowsPowerManagementAPI.pdf

### Assembling

Debug:
```
ml64.exe /c /Zi /Fo"DEUSSOMNUM.obj" /W3 /errorReport:prompt DEUSSOMNUM.ASM
```
Release:
```
ml64.exe /c /Fo"DEUSSOMNUM.obj" /W3 /errorReport:prompt DEUSSOMNUM.ASM
```

### Linking
Debug:
```
link.exe /ERRORREPORT:PROMPT /INCREMENTAL:NO /DEBUG /SUBSYSTEM:CONSOLE /OPT:NOREF /OPT:NOICF /ENTRY:"DEUSSOMNUM" /DYNAMICBASE /NXCOMPAT /MACHINE:X64 /SAFESEH:NO DEUSSOMNUM.obj
```

Release:
```
link.exe /ERRORREPORT:PROMPT /INCREMENTAL:NO /DEBUG:None /SUBSYSTEM:CONSOLE /OPT:NOREF /OPT:NOICF /ENTRY:"DEUSSOMNUM" /DYNAMICBASE /NXCOMPAT /MACHINE:X64 /SAFESEH:NO DEUSSOMNUM.obj
```
