# Troubleshooting Notes — Lab 65 Unquoted Service Path Investigation

## 1. Initial Unquoted Path Query Returned 251 Results

### Observation

The query returned:

```text
251
```

candidate services.

### Problem

The number was much larger than expected.

### Cause

The filter treated any whitespace in `PathName` as evidence that the executable path contained spaces.

### Example

Normal Windows service:

```text
C:\Windows\system32\svchost.exe -k netsvcs -p
```

The spaces are command-line separators.

They do not indicate that the executable path itself contains spaces.

### DFIR Lesson

Detection logic must parse the command line before identifying a genuine unquoted executable path.

## 2. Missing Pipeline Operator

An earlier service-specific command was malformed and caused PowerShell to enumerate services instead of correctly applying the intended filter.

The corrected pattern was:

```powershell
Get-CimInstance Win32_Service |
Where-Object {
    $_.Name -eq "WpnService"
} |
Select-Object Name, StartName, State, StartMode
```

### DFIR Lesson

Pipeline structure is important when building repeatable investigation commands.

## 3. Full Service Command Line Used as a File Path

### Problem

The following was attempted:

```powershell
Get-AuthenticodeSignature "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

### Result

PowerShell reported that the file could not be found.

### Cause

The complete service command line was treated as a literal filename.

### Resolution

Separate:

```text
C:\Windows\system32\svchost.exe
```

from:

```text
-k PrintWorkflow
```

before using file-analysis commands.

## 4. Test-Path Produced False

### Problem

The following was tested:

```powershell
Test-Path "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

Result:

```text
False
```

### Cause

There is no file with that entire string as its filename.

### Correct Interpretation

The executable is:

```text
C:\Windows\system32\svchost.exe
```

The remainder is an argument.

## 5. WpnService Does Not Automatically Represent a Vulnerability

### Observation

`WpnService` was:

```text
Running
Auto
LocalSystem
```

### Interpretation

These properties describe service execution context.

They do not prove that the service has an unquoted-path vulnerability or that it was exploited.

## 6. Event ID 7045 Was Available

### Observation

System Event ID 7045 contained service-installation events.

### Limitation

The supplied output did not expose complete details for every event.

### Resolution

The events were treated as supporting service-installation telemetry.

No specific 7045 event was attributed to the investigated service.

## 7. Sysmon Event ID 1 Was Not Useful for WpnService

### Observation

The search for `WpnService` did not return a useful process-create event.

### Interpretation

The process-creation telemetry did not provide direct attribution.

### DFIR Lesson

A service configuration investigation does not always produce a directly searchable process-creation record using the service name.

## 8. PowerShell Event ID 4104 Was Available

### Observation

The service queries generated relevant 4104 events.

### Limitation

These were investigation commands rather than evidence of attacker behavior.

### DFIR Lesson

The same event can be valuable for documenting analyst actions while being irrelevant to the original security hypothesis.

## 9. Sysmon Event ID 3 Was Available

### Observation

Network events were present.

### Limitation

No network connection was established as being caused by the investigated service.

## 10. No Exploitation Was Performed

The lab did not:

- Create a vulnerable service.
- Place a rogue executable in an ambiguous path.
- Restart a service to trigger path interception.
- Modify Windows service startup behavior.

### Reason

The goal was to investigate and refine detection logic safely.

## Troubleshooting Summary

| Observation | Resolution |
|---|---|
| 251 candidates returned | Identified false positives from command-line arguments |
| Service filter syntax issue | Corrected pipeline structure |
| Full command line failed `Get-AuthenticodeSignature` | Separated executable from arguments |
| Full command line failed `Test-Path` | Treated arguments separately |
| WpnService running as LocalSystem | Used as context, not malicious evidence |
| Event ID 7045 available | Used as supporting service-installation telemetry |
| Sysmon Event ID 1 not useful for WpnService | Documented attribution limitation |
| PowerShell 4104 available | Used to document investigation activity |
| Sysmon Event ID 3 available | Used for network context |
| No exploitation performed | Preserved safe lab boundaries |

## Final Troubleshooting Lesson

The central troubleshooting lesson is:

```text
Naive Detection
    |
    v
251 Candidates
    |
    v
False Positive Analysis
    |
    v
Parse Executable
    |
    v
Evaluate Actual Path
    |
    v
Better Detection
```

A reliable unquoted service path detector must distinguish the **executable path** from its **arguments** before declaring a service vulnerable.
