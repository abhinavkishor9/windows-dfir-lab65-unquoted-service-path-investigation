# Investigation Notes 

## Initial Service Enumeration

Windows services were queried using `Get-CimInstance Win32_Service`.

The investigation collected:

- Name
- DisplayName
- State
- StartMode
- StartName
- PathName

## Initial Detection Query

The first filter was:

```powershell
$Unquoted=Get-CimInstance Win32_Service |
Where-Object {
    $_.PathName -and
    $_.PathName -match "\s" -and
    $_.PathName -notmatch '"'
}

$Unquoted.Count
```

Result:

```text
251
```

## Analysis of the 251 Results

The large result set initially appeared suspicious.

Further investigation showed that the filter was too broad because it treated any space in `PathName` as part of the executable path.

Many standard services used:

```text
C:\Windows\system32\svchost.exe -k <service-group> -p
```

The space came from the command-line arguments.

The executable itself was:

```text
C:\Windows\system32\svchost.exe
```

Therefore, these entries were false positives for the specific unquoted-path condition being investigated.

## WpnService

The following query was used:

```powershell
Get-CimInstance Win32_Service |
Where-Object {
    $_.Name -eq "WpnService"
} |
Select-Object Name, StartName, State, StartMode
```

Result:

```text
Name      : WpnService
StartName : LocalSystem
State     : Running
StartMode : Auto
```

The service was therefore running automatically as `LocalSystem`.

No malicious conclusion was drawn from these attributes.

## PrintWorkflowUserSvc_107314

The service query returned:

```text
Name:
PrintWorkflowUserSvc_107314

PathName:
C:\Windows\system32\svchost.exe -k PrintWorkflow
```

The executable component was:

```text
C:\Windows\system32\svchost.exe
```

The argument was:

```text
-k PrintWorkflow
```

This demonstrated the central false-positive problem.

## Path Validation Error

The following operation was attempted:

```powershell
Get-AuthenticodeSignature "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

It failed because PowerShell treated the entire command line as a filename.

The error indicated that the specified file did not exist.

## Test-Path Error

The following also failed:

```powershell
Test-Path "C:\Windows\system32\svchost.exe -k PrintWorkflow"
```

Result:

```text
False
```

This was expected because no file exists whose literal filename includes:

```text
-k PrintWorkflow
```

## Correct Interpretation

The service command line must be parsed before file validation.

Incorrect approach:

```text
Full PathName
    |
    v
Treat Entire String As File Path
```

Correct approach:

```text
Full PathName
    |
    v
Executable + Arguments
    |
    +---- Executable
    |
    +---- Arguments
```

## Service Start and Account Context

`WpnService` had:

```text
StartMode : Auto
StartName : LocalSystem
State     : Running
```

These characteristics make the service worth understanding during a security investigation, but they are not proof of an unquoted-path vulnerability.

## Service Event ID 7045

The System log contained Event ID 7045 records.

Observed:

```text
27-08-2026 06:37:57
```

and several historical events from earlier dates.

The event source was:

```text
System
```

The event description was:

```text
A service was installed in the system....
```

Because the supplied event output did not expose complete service details, no particular event was attributed to `WpnService`.

## PowerShell Event ID 4104

Relevant service-investigation 4104 records were observed at:

```text
28-08-2026 08:02:18
22-08-2026 07:00:33
```

The searches involved:

```text
Win32_Service
Get-CimInstance
CurrentControlSet\Services
ImagePath
```

These entries were interpreted primarily as laboratory investigation activity.

## Sysmon Event ID 1

A search for `WpnService` did not provide a relevant process-creation result.

Therefore, no direct Sysmon process evidence was established for the service.

## Sysmon Event ID 3

Sysmon Event ID 3 was available and produced numerous network events.

No specific network activity was attributed to the investigated service.

## Security Event ID 4688

The Security log was searched for:

```text
WpnService
```

No relevant result was returned.

## Detection Logic Finding

The initial rule:

```text
Path contains spaces
AND
Path does not start with quote
```

is insufficient for reliable unquoted service path detection.

It must distinguish:

```text
Executable path
```

from:

```text
Executable arguments
```

## Evidence Correlation

The investigation chain was:

```text
Service
   |
   v
PathName
   |
   v
Parse Executable and Arguments
   |
   v
Check Executable Path
   |
   v
Check Quotation
   |
   v
Verify File
   |
   v
Registry ImagePath
   |
   v
Service Context
   |
   v
Event 7045
   |
   v
Process / Network Telemetry
```

