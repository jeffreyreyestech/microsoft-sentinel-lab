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

## Validation

A benign validation test can be performed in an authorized lab environment by executing PowerShell with an encoded command.

Expected validation process:

1. Execute a benign encoded PowerShell command on a test endpoint.
2. Confirm the execution appears in Microsoft Defender for Endpoint `DeviceProcessEvents`.
3. Run the detection query.
4. Confirm the event is returned.
5. Review the resulting fields including:
   - DeviceName
   - AccountName
   - ProcessCommandLine
   - InitiatingProcessFileName
6. Document any legitimate activity that may require tuning.

> Validation should only be performed in systems you own or are explicitly authorized to test.
