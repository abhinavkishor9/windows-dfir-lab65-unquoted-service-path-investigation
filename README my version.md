# windows-dfir-lab65-unquoted-service-path-investigation

## Overview

Concept

Consider this service path:

C:\Program Files\Example App\service.exe

A properly quoted path is:

"C:\Program Files\Example App\service.exe"

Without quotes, Windows may interpret the path ambiguously when starting the service. This can create opportunities for unintended executable resolution.

Conceptually:

Unquoted path
     ↓
Path contains spaces
     ↓
Windows resolves possible executable locations
     ↓
Unexpected executable may be selected

The important DFIR question is:

Does a Windows service have an executable path containing spaces without the required quotation marks?

An unquoted path is a configuration weakness, not automatic proof of exploitation.

This lab investigates Windows service executable paths to determine whether they contain a genuine unquoted service path condition or merely appear suspicious because the service command line contains spaces.

The investigation began with a broad service enumeration and an initial filter looking for service paths containing spaces without quotation marks. That search produced 251 results. Further investigation demonstrated that many of these results were normal Windows service command lines such as:

C:\Windows\system32\svchost.exe -k netsvcs -p

In these cases, the spaces belong to command-line arguments rather than an ambiguous executable path.

The investigation therefore emphasized an important DFIR and detection-engineering lesson:

> A service command line containing spaces is not automatically an exploitable unquoted service path.

The lab also examined the `WpnService` service and a `PrintWorkflowUserSvc_107314` service entry using `svchost.exe -k PrintWorkflow`. Attempts to pass the entire command-line string to file-oriented commands failed because the executable path and its arguments had not been separated.

Windows Service Event ID 7045 was available and contained historical service-installation events. Sysmon Event ID 1 and Event ID 3 were available. PowerShell Event ID 4104 returned service-investigation activity. The supplied evidence did not establish a confirmed exploitable unquoted service path or exploitation of one.

## Investigation Objectives

- Identify Windows services whose PathName values contain spaces and may initially appear to be unquoted.
- Determine whether the spaces belong to the executable path or only to command-line parameters.
- Examine the WpnService configuration, including its service account, state, and startup mode.
- Investigate PrintWorkflowUserSvc_107314 and interpret its svchost.exe -k PrintWorkflow command line correctly.
- Verify service executable paths before using file-analysis commands such as Test-Path or Get-AuthenticodeSignature.
- Compare service configuration with the corresponding Registry ImagePath.
- Review Event ID 7045 for service-installation context.
- Examine available Sysmon, PowerShell, and Security telemetry for supporting evidence.
- Identify why the initial detection logic returned a large number of false positives.
- Improve the investigation approach by separating executable paths from arguments.
- Determine whether the available evidence supports a genuine unquoted service path condition.

## Investigation Scenario

A Windows workstation is being reviewed for possible weaknesses in its service configurations. An initial scan identifies a large number of service command lines containing spaces without quotation marks, raising concern about potential unquoted service path vulnerabilities.

Further examination shows that many of the results involve normal Windows services using svchost.exe with parameters such as -k and -p. The analyst therefore needs to determine whether the apparent unquoted paths are genuine vulnerabilities or simply false positives caused by command-line arguments.

The investigation focuses on:

- Service configuration and startup context.
- The actual executable portion of each PathName.
- Quotation around paths containing spaces.
- Registry ImagePath values.
- Service-installation evidence.
- Process and PowerShell telemetry.
- Network context.

The investigation must ultimately determine whether the workstation contains a genuine unquoted service path condition or whether the initial findings are primarily false positives caused by incomplete path parsing.

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Investigation Type | Windows DFIR / Service Configuration |
| Primary Service Query | `Get-CimInstance Win32_Service` |
| Registry Service Location | `HKLM:\SYSTEM\CurrentControlSet\Services` |
| Service Investigated | `WpnService` |
| Additional Service Example | `PrintWorkflowUserSvc_107314` |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| PowerShell Event ID 4104 | Relevant service-query events observed |
| Security Event ID 4688 | Query performed |
| System Event ID 7045 | Available |

## Initial Service Enumeration

The service inventory was collected with:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, StartName, PathName
```

This provided:

- Service name
- Display name
- State
- Start mode
- Service account
- Configured command line

## Initial Unquoted-Path Filter

The initial detection logic used:

```powershell
$Unquoted = Get-CimInstance Win32_Service |
Where-Object {
    $_.PathName -and
    $_.PathName -match "\s" -and
    $_.PathName -notmatch '"'
}

$Unquoted.Count
```

The result was:

```text
251
```

This was an intentionally broad result.

Further analysis demonstrated that the query generated substantial false positives.

## False-Positive Example

A typical result included:

```text
C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
```

The executable is:

```text
C:\Windows\system32\svchost.exe
```

The remaining portion:

```text
-k LocalServiceNetworkRestricted -p
```

contains command-line arguments.

The spaces therefore do not make the executable path itself an unquoted path with embedded spaces.

## WpnService Investigation

The service was examined using:

```powershell
Get-CimInstance Win32_Service |
Where-Object {
    $_.Name -eq "WpnService"
} |
Select-Object Name, StartName, State, StartMode
```

Observed configuration:

```text
Name      : WpnService
StartName : LocalSystem
State     : Running
StartMode : Auto
```

This established that the service was running automatically under `LocalSystem`.

The service itself was not classified as malicious merely from these properties.

## PrintWorkflow Service Investigation

The service:

```text
PrintWorkflowUserSvc_107314
```

returned:

```text
C:\Windows\system32\svchost.exe -k PrintWorkflow
```

The executable portion is:

```text
C:\Windows\system32\svchost.exe
```

and:

```text
-k PrintWorkflow
```

is a command-line argument.

This was an important example of why service arguments must be separated before evaluating an unquoted-path condition.

## Path Parsing Problem

An attempt was made to validate:

```text
C:\Windows\system32\svchost.exe -k PrintWorkflow
```

directly with:

```powershell
Get-AuthenticodeSignature "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

The command failed because PowerShell interpreted the complete string as a file path.

The same problem occurred with:

```powershell
Test-Path "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

The correct approach is to extract:

```text
C:\Windows\system32\svchost.exe
```

before using file-oriented commands.

## Genuine Unquoted Service Path Logic

A service should only be treated as a genuine unquoted-path candidate when the executable portion itself:

1. Contains spaces.
2. Is not surrounded by quotation marks.
3. Resolves to an executable path.
4. Is configured as a Windows service executable path.
5. Creates a meaningful ambiguity in executable resolution.

For example:

```text
C:\Program Files\Example Service\service.exe
```

is a genuine candidate.

By contrast:

```text
C:\Windows\system32\svchost.exe -k netsvcs -p
```

is not an unquoted path merely because the command line contains spaces.

## Service Account and Start Mode

Service context was considered during investigation.

For `WpnService`:

```text
StartMode : Auto
StartName : LocalSystem
State     : Running
```

These characteristics increase the importance of investigating the service configuration, but they do not prove exploitability or compromise.

## Registry Validation

Windows service configuration can be examined under:

```text
HKLM:\SYSTEM\CurrentControlSet\Services
```

The relevant property is generally:

```text
ImagePath
```

The investigation should compare the Registry value with the `PathName` reported by `Win32_Service`.

This allows the analyst to confirm whether both sources describe the same service command line.

## Service Creation Event ID 7045

The System log contained Event ID 7045 records.

An example observed event occurred at:

```text
27-08-2026 06:37:57
```

Additional historical 7045 events were present on earlier dates.

The existence of Event ID 7045 establishes that service-installation telemetry is available, but the supplied evidence does not establish that a specific 7045 event created an exploitable unquoted service path.

## Sysmon Event ID 1

Sysmon Event ID 1 was queried for `WpnService`.

The supplied search did not return a relevant result.

The absence of a matching Event ID 1 event was treated as a telemetry limitation rather than proof that the service could not execute.

## Sysmon Event ID 3

Sysmon Event ID 3 was available and returned numerous network connection events.

No specific network activity was attributed to an unquoted service path condition.

## PowerShell Event ID 4104

PowerShell Event ID 4104 returned service-related investigation activity at:

```text
28-08-2026 08:02:18
22-08-2026 07:00:33
```

The events matched terms such as:

```text
Win32_Service
Get-CimInstance
CurrentControlSet\Services
ImagePath
```

These records primarily demonstrate the investigative commands and should not automatically be interpreted as attacker activity.

## Security Event ID 4688

Security Event ID 4688 was queried for `WpnService`.

No relevant result was returned in the supplied evidence.

Therefore, Security Event ID 4688 did not provide direct process attribution for the service investigation.

## Evidence Correlation

The correct workflow is:

```text
Service
   |
   v
PathName
   |
   v
Separate Executable From Arguments
   |
   v
Determine Whether Executable Path Contains Spaces
   |
   v
Check Quotation
   |
   v
Verify Executable
   |
   v
Registry ImagePath
   |
   v
Start Mode / Service Account
   |
   v
Event ID 7045
   |
   v
Process Telemetry
   |
   v
Network Telemetry
   |
   v
Final Assessment
```

## MITRE ATT&CK Relevance

Potentially relevant techniques in a real incident include:

**T1574.009 — Path Interception by Unquoted Path**

Relevant when an attacker exploits an ambiguous unquoted executable path.

**T1543.003 — Windows Service**

Relevant when a Windows service is used for persistence or execution.

The controlled investigation did not establish either technique as an active attack.

