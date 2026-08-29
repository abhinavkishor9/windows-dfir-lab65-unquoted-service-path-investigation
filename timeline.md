# Timeline — Lab 65 Unquoted Service Path Investigation

## Timeline Purpose

This timeline records the service enumeration, false-positive discovery, service-specific investigation, telemetry review, and refinement of the unquoted service path detection approach.

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

## Phase 1 — Service Enumeration

The Windows service inventory was collected using:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, StartName, PathName
```

This provided the service command lines used for analysis.

## Phase 2 — Broad Detection

The first unquoted-path filter identified:

```text
251
```

candidate services.

This was initially interpreted as a broad detection result rather than a confirmed vulnerability count.

## Phase 3 — False-Positive Analysis

The candidate results included standard Windows service commands such as:

```text
C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
```

The investigation established that:

```text
C:\Windows\system32\svchost.exe
```

was the executable and:

```text
-k LocalServiceNetworkRestricted -p
```

were arguments.

This demonstrated why the initial 251 count could not be treated as 251 vulnerabilities.

## Phase 4 — WpnService Investigation

`WpnService` was examined.

Observed configuration:

```text
Name      : WpnService
StartName : LocalSystem
State     : Running
StartMode : Auto
```

The service context increased the importance of understanding its configuration but did not establish malicious activity.

## Phase 5 — PrintWorkflow Investigation

The service:

```text
PrintWorkflowUserSvc_107314
```

returned:

```text
C:\Windows\system32\svchost.exe -k PrintWorkflow
```

The investigation attempted to validate the entire string as a file path.

That failed.

The command-line structure was then interpreted correctly:

```text
Executable:
C:\Windows\system32\svchost.exe

Argument:
-k PrintWorkflow
```

## Phase 6 — Service Installation Telemetry

System Event ID 7045 was reviewed.

An observed event occurred at:

```text
27-08-2026 06:37:57
```

Additional historical service-installation events were present.

The supplied event data was insufficient to connect any specific event directly to an exploitable unquoted service path.

## Phase 7 — PowerShell Telemetry

PowerShell Event ID 4104 results were observed at:

```text
28-08-2026 08:02:18
22-08-2026 07:00:33
```

The events were associated with investigation terms such as:

```text
Win32_Service
Get-CimInstance
CurrentControlSet\Services
ImagePath
```

These were treated as investigative activity.

## Phase 8 — Sysmon Process Telemetry

Sysmon Event ID 1 was searched for:

```text
WpnService
```

No useful matching process-creation evidence was established.

## Phase 9 — Sysmon Network Telemetry

Sysmon Event ID 3 was reviewed.

Network telemetry was available.

No specific connection was attributed to the service investigation.

## Phase 10 — Final Detection Assessment

The initial rule:

```text
Path contains whitespace
+
Path has no quotation mark
```

was determined to be insufficient.

The refined conceptual approach is:

```text
Service PathName
       |
       v
Separate Executable and Arguments
       |
       v
Evaluate Executable Path
       |
       v
Contains Spaces?
       |
       v
Quoted?
       |
       v
Executable Exists?
       |
       v
Potential Unquoted Service Path
```

## Final Evidence Summary

| Evidence | Result |
|---|---|
| Service enumeration | Successful |
| Initial candidate count | 251 |
| False-positive analysis | Required |
| WpnService | Running / Auto / LocalSystem |
| PrintWorkflow service | `svchost.exe -k PrintWorkflow` |
| Event ID 7045 | Available |
| Sysmon Event ID 1 | Available but no direct WpnService attribution |
| Sysmon Event ID 3 | Available |
| PowerShell Event ID 4104 | Investigation activity observed |
| Confirmed exploitable path | Not established |
| Exploitation | Not performed |

## Final Assessment

The main outcome of Lab 65 was the identification of a **detection-logic problem**, not a confirmed vulnerable service.

The initial broad filter generated 251 candidates because it did not distinguish executable paths from service arguments.

The investigation demonstrated that:

```text
Spaces in Service Command Line
        !=
Unquoted Service Path Vulnerability
```

## Investigation Conclusion

The lab successfully demonstrated how to investigate Windows service paths while avoiding a common analytical mistake.

Before a service can be classified as an unquoted service path vulnerability, the investigator must isolate the executable path, determine whether that path contains spaces, verify quotation, and assess whether the resulting path is actually ambiguous.

No exploitation or malicious persistence was established from the supplied evidence.
