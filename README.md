
# SOC Incident Investigation — Malicious RDP Access & Privilege Escalation

<p align="center">
  <img src="INSERT_OVERVIEW_GRAPHIC_URL_HERE" width="850" alt="LetsDefend SOC335 Incident Investigation Overview">
</p>

<p align="center">
  <strong>LetsDefend SOC335 | CVE-2024-49138 Exploitation Detected</strong>
</p>

## Executive Summary

This project documents my investigation of **SOC335 — CVE-2024-49138 Exploitation Detected**, a simulated security incident in the LetsDefend SOC environment.

The investigation began with a medium-severity privilege-escalation alert involving a suspicious executable, `svohost.exe`, on a Windows 10 endpoint named **Victor**.

Using endpoint detection and response (EDR), Windows authentication logs, firewall telemetry, and threat intelligence, I investigated suspicious remote access, malicious file execution, privilege escalation, and potential lateral movement.

My investigation identified:

- Multiple failed RDP authentication attempts followed by a successful login to the Victor account.
- A PowerShell command that downloaded, extracted, and executed a malicious file.
- A suspicious executable that launched PowerShell under the `NT AUTHORITY\SYSTEM` security context.
- A malicious SHA-256 hash identified by 50 of 71 security vendors on VirusTotal.
- No confirmed lateral movement to additional endpoints in the available logs.

I isolated the affected endpoint using LetsDefend's containment functionality.

The alert was ultimately classified as a **True Positive**. The playbook feedback also identified two mistakes in my initial assessment, which are documented in the Lessons Learned section.

> **Investigation Scope:** This was a simulated SOC investigation performed in LetsDefend. Findings are based on the telemetry available in the platform. The specific exploitation mechanism for CVE-2024-49138 was not independently verified.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| LetsDefend | SOC investigation and incident response simulation |
| Endpoint Security / EDR | Process analysis, command history, and host containment |
| Log Management | Windows authentication and firewall log investigation |
| LetsDefend Threat Intelligence | Malicious file reputation and alert correlation |
| VirusTotal | SHA-256 reputation analysis |
| MITRE ATT&CK | Understanding and classifying observed attacker behavior |

---

## 1. Initial Alert and Investigation Objective

### Objective

Determine whether the SOC335 alert represented malicious activity, identify the affected endpoint and associated indicators, investigate potential privilege escalation, and determine whether additional systems were affected.

### Alert Details

| Field | Value |
|---|---|
| Alert | SOC335 — CVE-2024-49138 Exploitation Detected |
| Event ID | 313 |
| Severity | Medium |
| Alert Type | Privilege Escalation |
| Hostname | Victor |
| Host IP | 172.16.17.207 |
| Operating System | Windows 10, 64-bit |
| Suspicious Process | `svohost.exe` |
| Process ID | 7640 |
| Process Path | `C:\temp\service_installer\svohost.exe` |
| Parent Process | `powershell.exe` |
| Initial Device Action | Allowed |

### Evidence — Initial Alert

<p align="center">
  <img src="https://i.imgur.com/UCTW8tp.png" width="850" alt="LetsDefend SOC335 Initial Alert">
</p>

<p align="center"><em>Figure 1 — Initial SOC335 alert showing the affected endpoint, suspicious executable, file hash, and privilege-escalation classification.</em></p>

### Initial Assessment

The alert identified an executable named `svohost.exe`, which closely resembles the legitimate Windows process `svchost.exe`.

However, the filename alone was insufficient to determine whether the executable was malicious.

I continued the investigation by reviewing the executable's location, parent process, execution context, command history, and file reputation.

---

## 2. Endpoint Investigation and Process Analysis

### Objective

Determine how the suspicious executable was launched and whether it was associated with elevated execution.

### Investigation

I opened LetsDefend Endpoint Security, selected the affected host, and reviewed its process activity.

Using the alert's process ID (**7640**), I located events associated with `svohost.exe`.

The executable was launched from:

`C:\temp\service_installer\svohost.exe`

Its parent process was PowerShell.

Further investigation revealed PowerShell activity running under `NT AUTHORITY\SYSTEM`, with `svohost.exe` identified as the parent executable.

One of the SYSTEM-level PowerShell processes was identified as **PID 6528**.

### Observed Process Relationship

```text
powershell.exe
      |
      v
svohost.exe
PID: 7640
      |
      v
powershell.exe
PID: 6528
User: NT AUTHORITY\SYSTEM
      |
      v
whoami.exe
```

This process relationship was significant because it linked the suspicious executable to a PowerShell process running with SYSTEM-level privileges.

The EDR also showed `whoami` activity. Terminal history included `whoami /priv`, a command used to enumerate privileges associated with the current security token.

These observations were consistent with privilege enumeration and potential successful local privilege escalation.

### Evidence — EDR Process Investigation

<p align="center">
  <img src="https://i.imgur.com/58InzP1.png" width="850" alt="Initial suspicious executable process">
</p>

<p align="center"><em>EDR evidence showing svohost.exe execution and process context.</em></p>

<p align="center">
  <img src="https://i.imgur.com/EgG2ugX.png" width="850" alt="SYSTEM-level process activity">
</p>

<p align="center"><em>EDR evidence showing the SYSTEM security context.</em></p>

<p align="center">
  <img src="https://i.imgur.com/k6JiBfX.png" width="850" alt="SYSTEM PowerShell process">
</p>

<p align="center"><em>PowerShell PID 6528 running as NT AUTHORITY\SYSTEM with svohost.exe as its parent.</em></p>

### Assessment

The available process telemetry strongly supported privilege escalation.

However, the exact vulnerability exploitation mechanism was not independently established through the available EDR evidence.

---

## 3. PowerShell Download and Malware Execution

### Objective

Determine how the malicious executable was introduced and executed.

### Investigation

While reviewing the endpoint's terminal history, I identified a PowerShell command that performed several actions:

1. Defined an external ZIP download URL.
2. Downloaded a password-protected archive.
3. Extracted the archive using 7-Zip.
4. Removed the downloaded ZIP file.
5. Executed `svohost.exe` from the extracted directory.

### Observed Download URL

```text
https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip
```

### Observed File Paths

```text
C:\temp\service-installer.zip
C:\temp\service_installer\svohost.exe
```

The archive extraction used the password `infected`.

This password was associated with extracting the ZIP archive and was not evidence of a stolen user credential.

### Evidence — Terminal History

<p align="center">
  <img src="https://i.imgur.com/W1RfJPO.png" width="850" alt="PowerShell Download and Execution">
</p>

<p align="center"><em>Figure 2 — Endpoint terminal history showing the PowerShell download, archive extraction, executable launch, and privilege-enumeration commands.</em></p>

### Assessment

The command sequence demonstrated how the executable was downloaded and launched.

The use of PowerShell, a password-protected archive, a temporary directory, and subsequent executable execution warranted further investigation.

During my initial analysis, I identified the download URL as a suspicious artifact but did not recognize that LetsDefend classified it as the malicious C2 destination.

The playbook feedback later confirmed that the URL had been accessed and the malware downloaded.

This became an important lesson in correlating observed commands with threat indicators.

---


## 4. Authentication and Firewall Log Analysis

### Objective

Investigate potential initial access through Remote Desktop Protocol (RDP).

### Investigation

I reviewed Windows authentication events in LetsDefend Log Management.

The logs showed multiple failed authentication attempts against the `admin` and `guest` accounts from external IP address `185.107.56.141`, followed by a successful login to the `Victor` account.

### Relevant Windows Events

| Event ID | Description | Observation |
|---|---|---|
| 4625 | Failed Logon | Failed attempts against admin and guest |
| 4624 | Successful Logon | Successful Victor authentication |
| Logon Type 10 | RemoteInteractive | Consistent with RDP access |

### Evidence — Windows Authentication Events

<p align="center">
  <img src="https://i.imgur.com/x9OhOjM.png" width="850" alt="Windows Authentication Logs">
</p>

<p align="center"><em>Figure — Failed admin and guest authentication attempts followed by a successful Victor RDP login.</em></p>

### Firewall Investigation

I also reviewed firewall logs and identified connections from the same external IP to Victor on TCP port 3389, the standard RDP port.

**Observed connection:**

`185.107.56.141 → 172.16.17.207:3389`

### Evidence — RDP Firewall Connections

<p align="center">
  <img src="https://i.imgur.com/KIdVBGs.png" width="850" alt="RDP Firewall Connections">
</p>

<p align="center"><em>Figure — Firewall logs showing connections from the suspicious external IP to Victor over TCP port 3389.</em></p>

### Assessment

The combination of failed authentication attempts, a successful RDP login, and corresponding firewall activity suggested suspicious remote access.

Although this activity was consistent with potential unauthorized access, the available evidence did not independently establish how the Victor account credentials were obtained.

---

## 5. Threat Intelligence and Malware Analysis

### Objective

Determine whether the suspicious executable was known to be malicious.

### SHA-256 Indicator

```text
b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9
```

I investigated the hash using VirusTotal and LetsDefend Threat Intelligence.

VirusTotal reported:

**50 / 71 security vendors flagged the file as malicious.**

LetsDefend's threat intelligence and playbook also associated the executable with CVE-2024-49138.

### Evidence — VirusTotal

<p align="center">
  <img src="https://i.imgur.com/D3Oemho.png" width="850" alt="VirusTotal Malware Detection Results">
</p>

<p align="center"><em>Figure 3 — VirusTotal reputation analysis identifying the suspicious executable as malicious.</em></p>

### Assessment

The malicious reputation, suspicious execution path, and observed process behavior strongly supported classifying `svohost.exe` as malware.

However, the CVE label and antivirus detections alone did not prove that the specific vulnerability was exploited.

---

## 6. Lateral Movement and Incident Scope

### Objective

Determine whether the suspicious activity extended beyond the affected endpoint.

### Investigation

I searched the available Log Management and EDR telemetry for activity involving:

- External source IP `185.107.56.141`
- Affected endpoint IP `172.16.17.207`
- Internal IP `172.31.4.60`, which appeared in endpoint network history

The external source IP was observed communicating with Victor, but I did not identify evidence that it accessed additional internal endpoints.

I also searched for activity originating from Victor and found no confirmed lateral movement to other hosts in the available logs.

No additional relevant events were identified for `172.31.4.60` through the searches performed.

### Assessment

**No lateral movement was observed in the available telemetry.**

This finding was limited to the available log sources and search results. It did not prove that lateral movement was impossible or that every potential communication had been captured.

Persistence and data exfiltration were also not confirmed.

---

## 7. Incident Response and Containment

### Objective

Contain the potentially compromised endpoint to reduce the risk of continued malicious network activity.

### Action Taken

After identifying suspicious remote access, malicious executable activity, and evidence of SYSTEM-level execution, I used LetsDefend Endpoint Security to isolate Victor.

### Evidence — Endpoint Containment

<p align="center">
  <img src="https://i.imgur.com/hZ0nB1b.png" width="850" alt="LetsDefend Endpoint Containment">
</p>

<p align="center"><em>Figure 4 — Victor endpoint showing Host Contained in LetsDefend Endpoint Security.</em></p>

### Containment vs. Quarantine

During the playbook, I initially selected **Quarantined** when asked whether the malware had been quarantined or cleaned.

This was incorrect.

The endpoint had been isolated, but the malicious file itself had not been confirmed as quarantined or removed.

The initial alert also recorded the device action as `Allowed`.

This reinforced an important incident response distinction:

| Action | Meaning |
|---|---|
| Endpoint Isolation | Restricts endpoint network connectivity |
| File Quarantine | Prevents or restricts access to a malicious file |
| Eradication | Removes malicious artifacts and associated persistence |

### Response Outcome

The endpoint was contained.

Malware quarantine, eradication, system reimaging, and recovery were not performed or confirmed during this investigation.

---

## 8. Indicators of Compromise (IOCs)

| Indicator | Type | Context |
|---|---|---|
| `185.107.56.141` | IPv4 | Suspicious RDP source |
| `172.16.17.207` | IPv4 | Affected endpoint |
| `svohost.exe` | Filename | Malicious executable |
| `C:\temp\service_installer\svohost.exe` | File Path | Executable location |
| `b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9` | SHA-256 | Malicious file hash |
| `https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip` | URL | Malware download destination; classified as C2 by LetsDefend |

> The AWS-hosted URL is included as an indicator specific to this simulated case. Use of Amazon S3 does not inherently indicate malicious activity.

---

## 9. MITRE ATT&CK Analysis

The alert referenced several MITRE ATT&CK techniques.

The following table distinguishes the alert's mappings from activity independently observed during the investigation.

| Technique | Description | Investigation Assessment |
|---|---|---|
| T1059.001 | PowerShell | Observed in command and process telemetry |
| T1068 | Exploitation for Privilege Escalation | Consistent with SYSTEM execution; exact exploit not independently verified |
| T1548 | Abuse Elevation Control Mechanism | Alert mapping; specific mechanism not confirmed |
| T1055 | Process Injection | Alert mapping; no direct injection evidence established |
| T1110 | Brute Force | Multiple failed logins observed; broader brute-force activity not fully established |
| T1078 | Valid Accounts | Successful Victor RDP authentication; potentially applicable |

These mappings are based on the alert metadata and observed behavior, rather than assuming every listed technique was proven.

---

## 10. CVE-2024-49138 — Exploitation Analysis

The alert associated the suspicious executable with CVE-2024-49138.

My investigation identified:

- Execution of a malicious executable from a temporary directory.
- A PowerShell process launched under the SYSTEM security context.
- Privilege-enumeration activity.
- Antivirus and threat intelligence associations with the CVE.

These observations supported the alert's privilege-escalation classification.

However, the available evidence did not independently establish the precise vulnerability exploitation mechanism.

### Additional Research Opportunities

- Review the technical details and exploitation prerequisites of CVE-2024-49138.
- Verify whether the affected Windows 10 build and patch level were vulnerable.
- Compare known exploitation indicators with the observed process activity.
- Determine whether additional endpoint telemetry would be required to confirm exploitation.

**Current Assessment:** Malicious execution and SYSTEM-level activity strongly supported; exact CVE exploitation mechanism not independently verified.

---

## 11. Investigation Outcome

### Final Classification: True Positive

The investigation identified malicious file execution, suspicious RDP authentication, and SYSTEM-level PowerShell activity on the affected endpoint.

The host was isolated to contain potential malicious network activity.

No confirmed lateral movement, persistence, or data exfiltration was identified in the available logs.

### Evidence — LetsDefend Playbook Results

<p align="center">
  <img src="https://i.imgur.com/nz4jfnT.png" width="850" alt="LetsDefend SOC335 Playbook Results">
</p>

<p align="center"><em>Figure 5 — LetsDefend playbook results confirming the True Positive classification and providing feedback on investigation decisions.</em></p>

### Playbook Performance

**Score: 5 points — 50% success rate**

| Playbook Question | My Answer | Correct Answer |
|---|---|---|
| Was the malicious C2 accessed? | Not Accessed | Accessed |
| Was the file malicious? | Malicious | Malicious |
| Was the malware quarantined? | Quarantined | Not Quarantined |
| Alert classification | True Positive | True Positive |

The results provided an opportunity to evaluate and improve my investigative reasoning.

---

## 12. Lessons Learned

### 1. Correlating Malware Delivery With C2 Indicators

During my initial investigation, I identified the PowerShell command downloading `service-installer.zip` from an AWS S3 URL.

However, I did not initially associate that URL with the C2 indicator referenced by the LetsDefend playbook.

I selected Not Accessed because I had not identified separate command-and-control communications.

The playbook feedback established that the malware download URL was the destination it expected analysts to identify.

**Lesson:** Correlate observed download commands, network indicators, and threat intelligence with the exact question being investigated. Avoid overlooking artifacts already present in endpoint telemetry.

### 2. Distinguishing Containment From Malware Quarantine

I isolated the affected host but initially reported the malware as quarantined.

The playbook correctly identified that host containment and file quarantine are different actions.

**Lesson:** Document the precise response action performed rather than assuming one containment action confirms another.

### 3. Avoiding Unsupported Conclusions

The investigation strongly supported malicious execution and privilege escalation, but I could not independently confirm the exact CVE exploitation mechanism.

Similarly, no lateral movement was identified, but that did not prove it was impossible.

**Lesson:** Separate observed evidence, reasonable assessments, and unverified possibilities.

### 4. Correlating Multiple Security Data Sources

Reviewing EDR, Windows authentication events, firewall logs, and threat intelligence helped build a more complete understanding of the incident.

**Lesson:** An alert is the starting point of an investigation, not the final conclusion.

---

## 13. Recommended Follow-Up Actions

If this were a real enterprise incident, I would recommend the following actions for the incident response team:

1. Preserve relevant endpoint, authentication, and network evidence.
2. Review the affected user's credentials and remote-access authorization.
3. Investigate persistence mechanisms, including scheduled tasks, services, and startup entries.
4. Validate the endpoint's Windows build and patch status against CVE-2024-49138.
5. Conduct broader threat hunting for the malicious file hash and related indicators.
6. Complete malware eradication and endpoint recovery according to approved incident response procedures.
7. Continue monitoring for suspicious authentication and endpoint activity.

These are recommended actions, not actions claimed as completed during the simulation.

---

## Conclusion

This LetsDefend SOC335 investigation provided hands-on experience analyzing a suspected Windows privilege-escalation incident.

I investigated suspicious RDP access, PowerShell-based malware delivery, malicious executable activity, and SYSTEM-level execution. I also reviewed threat intelligence, assessed potential lateral movement, and isolated the affected endpoint.

Although the alert was correctly classified as a True Positive, the playbook feedback exposed gaps in my understanding of C2 indicator correlation and the distinction between endpoint isolation and malware quarantine.

Documenting those mistakes alongside the confirmed findings helped turn the exercise into a practical learning experience.

**The main takeaway:** Effective SOC analysis requires more than identifying malicious activity. It requires correlating evidence, validating assumptions, documenting limitations, and accurately describing the response actions performed.

---

*Environment: LetsDefend SOC Simulation | Case: SOC335 | Investigation Type: Endpoint Compromise / Privilege Escalation*
