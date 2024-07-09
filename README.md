# Merwin

## Description
A set of PowerShell scripts and configs I created for the purpose of hardening Windows 10 machines. Note that these scripts change thousands of settings in compliance with NIST, DISA STIGS, CIS Benchmarks, MITRE ATT&CK Framework, and more, so be wary of running in a critical environment.

## Individual Documentation

### Registry.csv
A CSV file of security options includes their registry key, default value, recommended value, and severity.

### Services.csv
A CSV file of services and their recommended states.

### Windows V0ID.ps1
Gives the user the option to:

1. Check the system for common persistence mechanisms outlined in the MITRE ATT&CK Framework.
2. Compare the system's registry with registry.csv and display needed changes.
3. Compare the system's services with services.csv and display needed changes.
4. Check the users on the system for common security issues (it is better to use the specific user auditing script).
5. Implement the recommended changes to the registry from registry.csv.
6. Implement the recommended changes to the services from services.csv.
7. View all findings with their recommended changes.
8. Clear all of the findings.
9. Exit

### hardening10.ps1
This script changes more registry keys and removes many unnecessary features pre-installed on Windows, along with implementing some other security best practices.

### defender.ps1
This script implements many of the recommended options relating to Windows Defender through registry and powershell commands.

### filetool.ps1
This script detects executable files that have not been signed or are signed by anyone besides Microsoft. This can be useful in determining malware or other unneeded files on the system.

### admins.txt
This is where the authorized administrator accounts of the machine should be entered.

### users.txt
This is where the authorized user accounts of the machine should be entered.

### groups.txt
This is where the authorized groups of the machine should be entered.

### userauditing.ps1
This script utilizes admins.txt, users.txt, and groups.txt to run some checks and harden user-specific settings. The script also checks for more advanced persistence techniques, such as RID hijacking and hiding users from the login UI.

### firewall.wfw
A firewall config that implements recommended settings.

### secpol_win10_v2.inf
A secpol config tailored to Windows 10 machines that implements hardened local policy settings.

### secpol_mserver.inf
A secpol config tailored to Windows server machines that implements hardened local policy settings.

### hardened_ap.csv
An advanced audit policy config that sets all audit policies to Success and Failure. Will produce a lot of noise.
