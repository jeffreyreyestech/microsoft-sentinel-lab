# Suspicious PowerShell Encoded Command

## Purpose
Detect PowerShell executions that use encoded command-line arguments.

## Data Source
Microsoft Defender for Endpoint - `DeviceProcessEvents`

## Detection Logic
This detection looks for PowerShell processes using encoded command-line parameters such as:

- `-enc`
- `-encodedcommand`

These arguments can be used legitimately, but they are also commonly used to obfuscate PowerShell commands.

## MITRE ATT&CK
- T1059.001 - PowerShell

## Potential False Positives
- Legitimate administrative scripts
- Endpoint management tools
- Software deployment systems
- Automation frameworks
- Approved IT tooling

## Tuning Ideas
- Exclude known administrative hosts
- Exclude trusted service accounts
- Exclude approved automation tools
- Baseline normal PowerShell usage

## Investigation Steps
1. Review the full PowerShell command line.
2. Decode the encoded payload.
3. Review the parent and initiating processes.
4. Investigate the account that executed the command.
5. Check for related network connections.
6. Search for similar activity on other endpoints.

## Response Considerations
If the activity is confirmed malicious:

- Isolate the affected device
- Investigate the user account
- Review related processes and persistence
- Search the environment for the same indicators
- Collect relevant forensic evidence

## Related Query
See [`powershell-encoded-command.kql`](./powershell-encoded-command.kql)
