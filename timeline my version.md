# Timeline 

## Investigation Timeline

| Time | Source | Activity | Result |
|---|---|---|---|
| Initial | WMI/CIM | Windows services enumerated | Service inventory collected |
| Initial | WMI/CIM | Broad unquoted-path filter applied | 251 candidates returned |
| Initial | DFIR Analysis | Candidate paths reviewed | Many false positives identified |
| Investigation | WMI/CIM | `WpnService` inspected | Running, Auto, LocalSystem |
| Investigation | WMI/CIM | `PrintWorkflowUserSvc_107314` inspected | `svchost.exe -k PrintWorkflow` identified |
| Investigation | File Analysis | Full `svchost.exe -k PrintWorkflow` string validated | File validation failed because arguments were included |
| Investigation | Parser Analysis | Executable separated from arguments | `svchost.exe` identified as executable |
| Investigation | PowerShell | Event ID 4104 searched | Relevant service-query events observed |
| Investigation | Sysmon | Event ID 1 searched | No useful WpnService attribution |
| Investigation | Sysmon | Event ID 3 reviewed | Network telemetry available |
| Investigation | System | Event ID 7045 reviewed | Historical service-installation events available |
| Final | DFIR Analysis | Detection logic assessed | Broad rule identified as overly noisy |

