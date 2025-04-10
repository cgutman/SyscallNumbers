# SyscallNumbers
Simple utility to print syscall numbers on Windows by analyzing DLLs containing syscall trampolines (ex: ntdll.dll, win32u.dll).

Usage: `SyscallNumbers.exe [dll name or path] ...`

The output is a TSV containing lines of:
`[EXPORT NAME]  [SYSCALL NUMBER]`

Export table parsing is performed by [Detours](https://github.com/microsoft/Detours) and disassembly is performed using [Capstone](https://www.capstone-engine.org/).

## Example
```
C:\> SyscallNumbers.exe ntdll.dll win32u.dll
NtAcceptConnectPort     2
NtAccessCheck   0
NtAccessCheckAndAuditAlarm      41
NtAccessCheckByType     99
NtAccessCheckByTypeAndAuditAlarm        89
NtAccessCheckByTypeResultList   100
NtAccessCheckByTypeResultListAndAuditAlarm      101
NtAccessCheckByTypeResultListAndAuditAlarmByHandle      102
NtAcquireCrossVmMutant  103
NtAcquireProcessActivityReference       104
...
NtBindCompositionSurface        4363
NtCloseCompositionInputSink     4364
NtCompositionInputThread        4365
NtCompositionSetDropTarget      4366
NtCompositorNotifyExitWindows   4367
NtConfigureInputSpace   4368
NtConfirmCompositionSurfaceIndependentFlipEntry 4369
NtCreateCompositionInputSink    4370
NtCreateCompositionSurfaceHandle        4371
NtCreateImplicitCompositionInputSink    4372
...
```

## Current Limitations
- x86 support is limited to the newer format trampoline used by Windows 10 that directly invokes SYSENTER
- The architecture of SyscallNumbers.exe must match the architecture of the DLLs being analyzed
- WOW64 DLLs are not supported
