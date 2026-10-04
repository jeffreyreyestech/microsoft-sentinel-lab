# Office Application Spawning PowerShell

## Purpose
Detect Microsoft Office applications that launch PowerShell.

Office applications spawning scripting engines can be associated with malicious documents, macros, phishing payloads, or post-exploitation activity.

## Data Source
Microsoft Defender for Endpoint - `DeviceProcessEvents`

## Detection Logic
This detection identifies PowerShell processes where the initiating process is one of the following Office applications:

- `winword.exe`
- `excel.exe`
- `powerpnt.exe`
- `outlook.exe`

The child process is:

- `powershell.exe`
- `pwsh.exe`

## MITRE ATT&CK
- T1059.001 - PowerShell
- T1204.002 - Malicious File

## Potential False Positives
- Legitimate Office macros
- Internal automation
- Administrative scripts
- Approved plugins or add-ins
- Software deployment workflows

## Tuning Ideas
- Exclude known trusted users
- Exclude approved Office add-ins
- Exclude known administrative devices
- Review recurring legitimate command lines
- Baseline Office-to-PowerShell behavior

## Investigation Steps
1. Review the full PowerShell command line.
2. Review the initiating Office process.
3. Identify the document or attachment involved.
4. Investigate the user who opened the file.
5. Review email activity if Outlook was involved.
6. Check for child processes launched by PowerShell.
7. Review related network connections.
8. Search for the same behavior across other endpoints.

## Validation
A benign validation can be performed in an authorized lab by causing an Office application or controlled test process to launch PowerShell.

Expected validation process:

1. Generate the test event.
2. Confirm the process execution appears in `DeviceProcessEvents`.
3. Run the detection query.
4. Confirm the event is returned.
5. Review the parent-child relationship.
6. Document any legitimate behavior that requires tuning.

> Validation should only be performed in systems you own or are explicitly authorized to test.

## Related Query
See [`office-spawning-powershell.kql`](./office-spawning-powershell.kql)
