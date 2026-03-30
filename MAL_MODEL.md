# MAL Model — EN2720 Attack Scenarios

A minimal MAL-style (Meta Attack Language) model built from real attacker commands across 10 EN2720 CTF scenarios. Every action, effect, and mapping rule in this document is grounded directly in the commands logged in `data/`.

---

## Overview

| | Count |
|---|---|
| Attack scenarios | 10 |
| Total commands | 55 |
| Unique actions | 41 |
| Unique effects | 49 |
| Attack phases covered | 6 |

**Phases:** reconnaissance · exploitation · post-exploitation · persistence · lateral-movement · exfiltration

---

## Core Concepts

**Action** — A deliberate step the attacker consciously chooses. One action can map to multiple concrete commands (e.g. three different `sqlmap` invocations all map to `exploitSQLInjection`).

**Effect** — A state that becomes true after an action succeeds. Effects are the causal links between actions: an action's postconditions become another action's preconditions.

**Mapping rule:**
```
command → action → [produces effects]
                 ← [requires effects]
```

---

## Actions

Sorted by phase. `--` means no precondition (entry point into the attack graph).

| Action | Phase | Requires (preconditions) | Produces (postconditions) |
|---|---|---|---|
| `accessWebApplication` | reconnaissance | -- | `webApplicationAccessed` |
| `enumerateADGroups` | reconnaissance | `shellAccessGained` | `adGroupsEnumerated` |
| `inspectWebPageSource` | reconnaissance | `authenticatedWebAccess`, `hiddenLinksDiscovered` | `hiddenLinksDiscovered`, `sensitiveDataObtained` |
| `scanForService` | reconnaissance | -- | `ftpHostIdentified` |
| `scanNetwork` | reconnaissance | -- | `liveHostsDiscovered`, `openPortsKnown` |
| `testSQLInjection` | reconnaissance | `webApplicationAccessed` | `sqlInjectionConfirmed` |
| `bruteForceFTP` | exploitation | `ftpHostIdentified` | `ftpCredentialsObtained` |
| `bruteForceHTTPAuth` | exploitation | `openPortsKnown` | `tomcatCredentialsObtained` |
| `configureExploitModule` | exploitation | `exploitFrameworkReady` | `exploitConfigured` |
| `createWebAccount` | exploitation | `webApplicationAccessed` | `authenticatedWebAccess` |
| `enumerateDatabaseTables` | exploitation | `databaseNamesKnown` | `databaseTablesKnown` |
| `enumerateDatabases` | exploitation | `sqlInjectionConfirmed` | `databaseNamesKnown` |
| `exploitSQLInjection` | exploitation | -- | `shellAccessGained`, `webShellAccessGained` |
| `exploitTomcatManager` | exploitation | `exploitConfigured`, `tomcatCredentialsObtained` | `remoteSessionOpened` |
| `loginFTP` | exploitation | `ftpCredentialsObtained` | `ftpAccessGained`, `sensitiveDataObtained` |
| `prepareExploitFramework` | exploitation | `tomcatCredentialsObtained` | `exploitFrameworkReady` |
| `browseWebApplication` | post-exploitation | `tomcatCredentialsObtained` | `sensitiveDataObtained` |
| `captureNetworkTraffic` | post-exploitation | `networkInterfaceKnown`, `shellAccessGained` | `trafficCaptured` |
| `dropToShell` | post-exploitation | `remoteSessionOpened` | `shellAccessGained` |
| `enumerateActiveDirectory` | post-exploitation | `adEnumerationReady`, `adForestStructureKnown` | `adForestStructureKnown`, `domainControllersKnown` |
| `enumerateCronJobs` | post-exploitation | `webShellAccessGained` | `writableCronJobFound`, `cronScheduleKnown` |
| `enumerateWebFiles` | post-exploitation | `shellAccessGained`, `webRootContentsKnown` | `webRootContentsKnown`, `webFilesEnumerated`, `sensitiveDataObtained` |
| `escalatePrivilegesViaCron` | post-exploitation | `passwdModificationConfirmed`, `userPasswordSet` | `rootAccessGained`, `sensitiveDataObtained` |
| `escalateToDomainAdmin` | post-exploitation | `rdpSessionEstablished`, `groupMembershipModified` | `domainAdminPrivilegesGained` |
| `gatherNetworkInfo` | post-exploitation | `shellAccessGained` | `networkInterfaceKnown` |
| `gatherSystemInfo` | post-exploitation | `shellAccessGained`, `webShellAccessGained` | `webDirectoryContentsKnown`, `currentDirectoryKnown`, `availableModulesKnown`, `currentUserIdentified`, `privilegeLevelKnown` |
| `modifyADPermissions` | post-exploitation | `adGroupOwnershipGained` | `adGroupFullControlGranted` |
| `modifyGroupMembership` | post-exploitation | `adGroupFullControlGranted`, `credentialsObtained` | `groupMembershipModified` |
| `prepareADEnumeration` | post-exploitation | `availableModulesKnown` | `adEnumerationReady` |
| `readSensitiveFile` | post-exploitation | `shellAccessGained` | `credentialsObtained` |
| `searchFilesystem` | post-exploitation | `shellAccessGained` | `sensitiveFileLocated` |
| `takeADObjectOwnership` | post-exploitation | `adGroupsEnumerated`, `shellAccessGained` | `adGroupOwnershipGained` |
| `verifyPrivilegeChange` | post-exploitation | `cronScriptComplete` | `passwdModificationConfirmed` |
| `setUserPassword` | persistence | `webShellAccessGained` | `userPasswordSet` |
| `writeMaliciousCronScript` | persistence | `writableCronJobFound`, `maliciousCronScriptStarted`, `cronPayloadInjected` | `maliciousCronScriptStarted`, `cronPayloadInjected`, `cronScriptComplete` |
| `loginRDP` | lateral-movement | `groupMembershipModified`, `credentialsObtained` | `rdpSessionEstablished` |
| `analyzePacketCapture` | exfiltration | `trafficCaptured` | `sensitiveDataObtained` |
| `dumpDatabase` | exfiltration | `databaseTablesKnown` | `databaseContentsDumped`, `sensitiveDataObtained` |
| `dumpDatabaseCredentials` | exfiltration | `databaseNamesKnown` | `dbCredentialsObtained` |
| `exfiltrateFile` | exfiltration | `sensitiveFileLocated` | `fileExfiltrated` |
| `queryADObjectAttributes` | exfiltration | `adEnumerationReady`, `adForestStructureKnown`, `domainControllersKnown` | `sensitiveDataObtained` |

### Notes on action design

- **Entry points** (no preconditions): `accessWebApplication`, `exploitSQLInjection`, `scanNetwork`, `scanForService`. These represent actions where prior access was either assumed or not logged.
- **Multi-step actions**: `writeMaliciousCronScript`, `enumerateActiveDirectory`, `enumerateWebFiles`, `inspectWebPageSource` each cover 2–3 sequential commands that build on intermediate effects within the same logical step.
- **`gatherSystemInfo`** aggregates five recon commands (`ls`, `pwd`, `whoami`, `id`, `Get-Module`) — all produce informational state that does not gate further actions in this model but is retained as evidence of attacker enumeration behaviour.

---

## Effects

| Effect | Produced By | Enables |
|---|---|---|
| `adEnumerationReady` | `prepareADEnumeration` | `enumerateActiveDirectory`, `queryADObjectAttributes` |
| `adForestStructureKnown` | `enumerateActiveDirectory` | `enumerateActiveDirectory`, `queryADObjectAttributes` |
| `adGroupFullControlGranted` | `modifyADPermissions` | `modifyGroupMembership` |
| `adGroupOwnershipGained` | `takeADObjectOwnership` | `modifyADPermissions` |
| `adGroupsEnumerated` | `enumerateADGroups` | `takeADObjectOwnership` |
| `authenticatedWebAccess` | `createWebAccount` | `inspectWebPageSource` |
| `availableModulesKnown` | `gatherSystemInfo` | `prepareADEnumeration` |
| `credentialsObtained` | `readSensitiveFile` | `modifyGroupMembership`, `loginRDP` |
| `cronPayloadInjected` | `writeMaliciousCronScript` | `writeMaliciousCronScript` |
| `cronScheduleKnown` | `enumerateCronJobs` | — (terminal) |
| `cronScriptComplete` | `writeMaliciousCronScript` | `verifyPrivilegeChange` |
| `currentDirectoryKnown` | `gatherSystemInfo` | — (terminal) |
| `currentUserIdentified` | `gatherSystemInfo` | — (terminal) |
| `databaseContentsDumped` | `dumpDatabase` | — (terminal) |
| `databaseNamesKnown` | `enumerateDatabases` | `enumerateDatabaseTables`, `dumpDatabaseCredentials` |
| `databaseTablesKnown` | `enumerateDatabaseTables` | `dumpDatabase` |
| `dbCredentialsObtained` | `dumpDatabaseCredentials` | — (terminal) |
| `domainAdminPrivilegesGained` | `escalateToDomainAdmin` | — (terminal, objective) |
| `domainControllersKnown` | `enumerateActiveDirectory` | `queryADObjectAttributes` |
| `exploitConfigured` | `configureExploitModule` | `exploitTomcatManager` |
| `exploitFrameworkReady` | `prepareExploitFramework` | `configureExploitModule` |
| `fileExfiltrated` | `exfiltrateFile` | — (terminal, objective) |
| `ftpAccessGained` | `loginFTP` | — (terminal) |
| `ftpCredentialsObtained` | `bruteForceFTP` | `loginFTP` |
| `ftpHostIdentified` | `scanForService` | `bruteForceFTP` |
| `groupMembershipModified` | `modifyGroupMembership` | `loginRDP`, `escalateToDomainAdmin` |
| `hiddenLinksDiscovered` | `inspectWebPageSource` | `inspectWebPageSource` |
| `liveHostsDiscovered` | `scanNetwork` | — (terminal) |
| `maliciousCronScriptStarted` | `writeMaliciousCronScript` | `writeMaliciousCronScript` |
| `networkInterfaceKnown` | `gatherNetworkInfo` | `captureNetworkTraffic` |
| `openPortsKnown` | `scanNetwork` | `bruteForceHTTPAuth` |
| `passwdModificationConfirmed` | `verifyPrivilegeChange` | `escalatePrivilegesViaCron` |
| `privilegeLevelKnown` | `gatherSystemInfo` | — (terminal) |
| `rdpSessionEstablished` | `loginRDP` | `escalateToDomainAdmin` |
| `remoteSessionOpened` | `exploitTomcatManager` | `dropToShell` |
| `rootAccessGained` | `escalatePrivilegesViaCron` | — (terminal, objective) |
| `sensitiveDataObtained` | `analyzePacketCapture`, `enumerateWebFiles`, `inspectWebPageSource`, `queryADObjectAttributes`, `browseWebApplication`, `escalatePrivilegesViaCron`, `loginFTP`, `dumpDatabase` | — (terminal, objective) |
| `sensitiveFileLocated` | `searchFilesystem` | `exfiltrateFile` |
| `shellAccessGained` | `exploitSQLInjection`, `dropToShell` | `gatherNetworkInfo`, `captureNetworkTraffic`, `gatherSystemInfo`, `enumerateWebFiles`, `searchFilesystem`, `readSensitiveFile`, `enumerateADGroups`, `takeADObjectOwnership` |
| `sqlInjectionConfirmed` | `testSQLInjection` | `enumerateDatabases` |
| `tomcatCredentialsObtained` | `bruteForceHTTPAuth` | `browseWebApplication`, `prepareExploitFramework`, `exploitTomcatManager` |
| `trafficCaptured` | `captureNetworkTraffic` | `analyzePacketCapture` |
| `userPasswordSet` | `setUserPassword` | `escalatePrivilegesViaCron` |
| `webApplicationAccessed` | `accessWebApplication` | `createWebAccount`, `testSQLInjection` |
| `webDirectoryContentsKnown` | `gatherSystemInfo` | — (terminal) |
| `webFilesEnumerated` | `enumerateWebFiles` | — (terminal) |
| `webRootContentsKnown` | `enumerateWebFiles` | `enumerateWebFiles` |
| `webShellAccessGained` | `exploitSQLInjection` | `gatherSystemInfo`, `enumerateCronJobs`, `setUserPassword` |
| `writableCronJobFound` | `enumerateCronJobs` | `writeMaliciousCronScript` |

### Terminal effects

Effects marked `(terminal)` are end states with no downstream action in this model. Objectives (`sensitiveDataObtained`, `rootAccessGained`, `domainAdminPrivilegesGained`, `fileExfiltrated`) are intentional terminals. Informational terminals (`currentUserIdentified`, `privilegeLevelKnown`, etc.) represent gathered state that would gate further actions in a more complete model.

---

## Attack Chains (per scenario)

Each chain shows the sequence of actions, in order, as logged in the source data.

### 1 — Network Traffic Capture
```
gatherNetworkInfo
  -> networkInterfaceKnown
captureNetworkTraffic
  -> trafficCaptured
analyzePacketCapture
  -> sensitiveDataObtained
```

### 2 — Web Server File Enumeration
```
exploitSQLInjection
  -> shellAccessGained, webShellAccessGained
gatherSystemInfo
  -> webDirectoryContentsKnown, currentDirectoryKnown
enumerateWebFiles
  -> webRootContentsKnown, webFilesEnumerated, sensitiveDataObtained
```

### 3 — Web Application Source Inspection
```
accessWebApplication
  -> webApplicationAccessed
createWebAccount
  -> authenticatedWebAccess
inspectWebPageSource
  -> hiddenLinksDiscovered -> sensitiveDataObtained
```

### 4 — Active Directory Metadata Query
```
gatherSystemInfo
  -> availableModulesKnown
prepareADEnumeration
  -> adEnumerationReady
enumerateActiveDirectory
  -> adForestStructureKnown, domainControllersKnown
queryADObjectAttributes
  -> sensitiveDataObtained
```

### 5 — Tomcat Manager Brute-Force
```
scanNetwork
  -> liveHostsDiscovered, openPortsKnown
bruteForceHTTPAuth
  -> tomcatCredentialsObtained
browseWebApplication
  -> sensitiveDataObtained
```

### 6 — Cron Job Privilege Escalation
```
exploitSQLInjection
  -> webShellAccessGained
gatherSystemInfo
  -> privilegeLevelKnown, currentUserIdentified
enumerateCronJobs
  -> writableCronJobFound, cronScheduleKnown
writeMaliciousCronScript
  -> maliciousCronScriptStarted, cronPayloadInjected, cronScriptComplete
setUserPassword
  -> userPasswordSet
verifyPrivilegeChange
  -> passwdModificationConfirmed
escalatePrivilegesViaCron
  -> rootAccessGained, sensitiveDataObtained
```

### 7 — FTP Credential Brute-Force
```
scanForService
  -> ftpHostIdentified
bruteForceFTP
  -> ftpCredentialsObtained
loginFTP
  -> ftpAccessGained, sensitiveDataObtained
```

### 8 — Tomcat Exploit and File Exfiltration
```
prepareExploitFramework        [requires tomcatCredentialsObtained from scenario 5]
  -> exploitFrameworkReady
configureExploitModule
  -> exploitConfigured
exploitTomcatManager
  -> remoteSessionOpened
dropToShell
  -> shellAccessGained
searchFilesystem
  -> sensitiveFileLocated
exfiltrateFile
  -> fileExfiltrated
```

### 9 — AD ACL Abuse and Domain Admin Escalation
```
readSensitiveFile              [requires shellAccessGained from scenario 8]
  -> credentialsObtained
enumerateADGroups
  -> adGroupsEnumerated
takeADObjectOwnership
  -> adGroupOwnershipGained
modifyADPermissions
  -> adGroupFullControlGranted
modifyGroupMembership
  -> groupMembershipModified
loginRDP
  -> rdpSessionEstablished
escalateToDomainAdmin
  -> domainAdminPrivilegesGained
```

### 10 — SQL Injection Database Dump
```
testSQLInjection               [requires webApplicationAccessed]
  -> sqlInjectionConfirmed
enumerateDatabases
  -> databaseNamesKnown
enumerateDatabaseTables
  -> databaseTablesKnown
dumpDatabase
  -> databaseContentsDumped, sensitiveDataObtained
dumpDatabaseCredentials
  -> dbCredentialsObtained
```

---

## Cross-scenario dependencies

Some scenarios depend on effects produced in other scenarios. These are real dependencies observed in the data, not modelled as explicit edges in the graph (each flag's chain is analysed independently):

| Dependent scenario | Requires | Produced in |
|---|---|---|
| Tomcat Exploit (8) | `tomcatCredentialsObtained` | Tomcat Brute-Force (5) |
| AD ACL Abuse (9) | `shellAccessGained` | Tomcat Exploit (8) |
| SQL Injection Dump (10) | `webApplicationAccessed` | Web App Inspection (3) |
| Network Traffic Capture (1) | `shellAccessGained` | assumed from prior sqlmap access |

---

## Command-to-action mapping (selected examples)

| Command | Action |
|---|---|
| `nmap 10.0.3.0/24` | `scanNetwork` |
| `nmap -p 21 10.0.3.0/24` | `scanForService` |
| `hydra -L usernames.txt -P passwords.txt ... http-get /manager/html` | `bruteForceHTTPAuth` |
| `hydra -L usernames.txt -p passwords.txt ftp://...` | `bruteForceFTP` |
| `sqlmap ... --os-shell` | `exploitSQLInjection` |
| `sqlmap ... --dbs` | `enumerateDatabases` |
| `sqlmap ... --tables` | `enumerateDatabaseTables` |
| `sqlmap ... --dump` | `dumpDatabase` |
| `tcpdump -i ens4 -w /tmp/traffic.pcap` | `captureNetworkTraffic` |
| `strings /tmp/traffic.pcap \| grep ...` | `analyzePacketCapture` |
| `ip addr` | `gatherNetworkInfo` |
| `whoami` / `id` / `ls` / `pwd` | `gatherSystemInfo` |
| `ls -la /etc/cron.*` / `cat /etc/crontab` | `enumerateCronJobs` |
| `echo ... > /etc/cron.hourly/...` | `writeMaliciousCronScript` |
| `echo "user:pass" \| chpasswd` | `setUserPassword` |
| `cat /etc/passwd` | `verifyPrivilegeChange` |
| `echo 'pass' \| su user -c 'ls /root/'` | `escalatePrivilegesViaCron` |
| `msfconsole` | `prepareExploitFramework` |
| `use exploit/multi/http/tomcat_mgr_upload` | `configureExploitModule` |
| `set RHOSTS ... exploit` | `exploitTomcatManager` |
| `shell` (in meterpreter) | `dropToShell` |
| `dir /s /b C:\\ \| findstr /i "..."` | `searchFilesystem` |
| `download "C:\\..." /home/kali/...` | `exfiltrateFile` |
| `type "...tomcat-users.xml"` | `readSensitiveFile` |
| `Get-ADForest` / `Get-ADDomainController` | `enumerateActiveDirectory` |
| `Get-ADObject -Filter * -Properties *` | `queryADObjectAttributes` |
| `Import-Module ActiveDirectory` | `prepareADEnumeration` |
| `$group.psbase.ObjectSecurity.SetOwner(...)` | `takeADObjectOwnership` |
| `$acl.AddAccessRule(...)` | `modifyADPermissions` |
| `$helpdesk.Add("LDAP://CN=...")` | `modifyGroupMembership` |
| `xfreerdp3 /u:... /v:...` | `loginRDP` |
| `$daGroup.Add("LDAP://CN=Domain Admins...")` | `escalateToDomainAdmin` |
| `' (single quote in search field)` | `testSQLInjection` |
| `find /var/www -type f` | `enumerateWebFiles` |
| `ftp 10.0.3.197` | `loginFTP` |
| `Get-Module -ListAvailable` | `gatherSystemInfo` |

---

## Data sources

All data in `data/*.json`. Each file contains the ordered command sequence for one attack scenario with fields: `command`, `reasoning`, `output`, `agent`.

| File | Scenario |
|---|---|
| `data/flag14ce18.json` | Network Traffic Capture |
| `data/flag3b2000.json` | Web Server File Enumeration |
| `data/flag521bce.json` | Web Application Source Inspection |
| `data/flag59ecca.json` | Active Directory Metadata Query |
| `data/flag90b353.json` | Tomcat Manager Brute-Force |
| `data/flag9f1f16.json` | Cron Job Privilege Escalation |
| `data/flagadcb1f.json` | FTP Credential Brute-Force |
| `data/flagcd699a.json` | Tomcat Exploit and File Exfiltration |
| `data/flagcfcec8.json` | AD ACL Abuse and Domain Admin Escalation |
| `data/flagde3b1c.json` | SQL Injection Database Dump |
