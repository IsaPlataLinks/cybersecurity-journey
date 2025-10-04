# RED TEAM 
Repositório criado para documentar minha jornada de aprendizado em Red Team e Offensive Security com foco em formação completa e competitiva para o mercado.
---
## FASE 1: FUNDAMENTOS ESSENCIAIS
### Redes
- [ ] Modelo OSI (7 camadas)
- [ ] Modelo TCP/IP (4 camadas)
- [ ] Protocolos principais
  - [ ] HTTP/HTTPS
  - [ ] DNS
  - [ ] SMB/CIFS
  - [ ] FTP/SFTP
  - [ ] SSH
  - [ ] SMTP/POP3/IMAP
  - [ ] LDAP/LDAPS
  - [ ] Kerberos
- [ ] Conceitos de IP
  - [ ] IPv4 vs IPv6
  - [ ] Public vs Private IP
  - [ ] localhost/loopback (127.0.0.1)
  - [ ] subnet mask, default gateway
  - [ ] CIDR notation
- [ ] **Subnetting profundo**
  - [ ] Cálculo de redes e hosts
  - [ ] VLSM (Variable Length Subnet Mask)
  - [ ] Supernetting
  - [ ] Exercícios práticos de subnetting
- [ ] NAT, VLAN, roteamento básico
- [ ] **Topologias de rede**
  - [ ] Star, Ring, Bus, Mesh
  - [ ] Vantagens e desvantagens de cada
- [ ] **NAS e SAN**
  - [ ] Network Attached Storage
  - [ ] Storage Area Network
  - [ ] Diferenças e casos de uso
##
### Linux
- [ ] Navegação básica
- [ ] ls, cd, pwd, find, locate, which, whereis
- [ ] man pages e --help
- [ ] Manipulação de arquivos
- [ ] cat, grep, awk, sed, cut, sort, uniq
- [ ] head, tail, less, more
- [ ] Permissões
- [ ] chmod, chown, chgrp
- [ ] SUID, SGID, Sticky Bit
- [ ] sudo e su
- [ ] Processos
- [ ] ps, top, htop, kill, killall
- [ ] systemctl, service
- [ ] jobs, fg, bg, nohup
- [ ] Bash scripting
- [ ] Bash scripting
- [ ] Variáveis e loops
- [ ] Condicionais
- [ ] Funções
- [ ] Redirecionamento e pipes
##
### Windows
- [ ] Comandos CMD básicos
  - [ ] dir, cd, copy, move, del
  - [ ] ipconfig, netstat, tasklist
- [ ] PowerShell básico
  - [ ] Get-Command, Get-Help
  - [ ] Cmdlets essenciais
  - [ ] Pipeline do PowerShell
- [ ] Active Directory conceitos
  - [ ] Usuários, Grupos, OUs
  - [ ] Group Policy Objects (GPO)
  - [ ] Domain Controllers
  - [ ] Trust relationships
##
### Programação e Automação
- [ ] Python
  - [ ] Sintaxe básica
  - [ ] Estruturas de dados (listas, dicts, sets)
  - [ ] Manipulação de arquivos
  - [ ] Requests HTTP (biblioteca requests)
  - [ ] Sockets básicos
- [ ] Bash scripting (aprofundar)
  - [ ] Automação de tarefas
  - [ ] One-liners úteis
  - [ ] Text processing
##
### IT Fundamentals
- [ ] **Hardware básico**
  - [ ] CPU, RAM, Storage, Motherboard
  - [ ] Periféricos e interfaces
  - [ ] Troubleshooting físico
- [ ] **Virtualização**
  - [ ] Hypervisor Type 1 vs Type 2
  - [ ] VMware Workstation/ESXi
  - [ ] VirtualBox
  - [ ] Proxmox
  - [ ] Snapshots e cloning
  - [ ] Network modes (NAT, Bridged, Host-only)
##
### Ferramentas Iniciais
- [ ] **Nmap** - Port scanning e service detection
  - [ ] Scan types (-sS, -sT, -sU)
  - [ ] Scripts NSE básicos
- [ ] **Netcat** - Banner grabbing e reverse shells
- [ ] **Wireshark** - Análise de tráfego
  - [ ] Filtros básicos
  - [ ] Follow TCP stream
- [ ] **Burp Suite** - Web application testing
  - [ ] Proxy configuration
  - [ ] Repeater e Intruder
- [ ] **OWASP ZAP** - Automated web scanning
- [ ] **Metasploit Framework** - Exploitation básica
  - [ ] msfconsole básico
  - [ ] Exploits e payloads
- [ ] **Gobuster/FFuF** - Directory brute-forcing
##
### Prática
- [ ] TryHackMe: Complete Beginner Path
- [ ] TryHackMe: Jr Penetration Tester Path
- [ ] HackTheBox: Pelo menos 10 máquinas Easy
- [ ] OverTheWire: Bandit (todos os níveis)
- [ ] OverTheWire: Natas (primeiros 10 níveis)
---
## FASE 2: RECONHECIMENTO & ENUMERAÇÃO
### OSINT (Open Source Intelligence)
- [ ] **Google Dorking**
  - [ ] site:, inurl:, intitle:, filetype:
  - [ ] Operadores avançados
  - [ ] Google Hacking Database (GHDB)
- [ ] **Shodan** - Busca de dispositivos expostos
- [ ] **Censys** - Certificados e infraestrutura
- [ ] **theHarvester** - Email e subdomain harvesting
- [ ] **Recon-ng** - Framework de reconhecimento
- [ ] **Maltego** - Visualização de relacionamentos
- [ ] **WHOIS/DNS** - Informações de domínio
  - [ ] whois lookups
  - [ ] DNS records (A, AAAA, MX, TXT, NS)
##
### Passive Reconnaissance
- [ ] **Subdomain Enumeration**
  - [ ] Amass
  - [ ] Subfinder
  - [ ] Assetfinder
  - [ ] crt.sh (Certificate Transparency)
- [ ] **GitHub Reconnaissance**
  - [ ] Busca por credenciais (GitDorking)
  - [ ] Truffehog, GitLeaks
- [ ] **Wayback Machine** - Histórico de websites
- [ ] **Certificate Transparency Logs**
- [ ] **Passive DNS** - SecurityTrails, VirusTotal
##
### Active Enumeration
- [ ] **Port Scanning Avançado**
  - [ ] Nmap scripts NSE
  - [ ] Evasão de firewall (-f, --mtu, -D)
  - [ ] Masscan (scanning em larga escala)
  - [ ] Rustscan (scanning rápido)
- [ ] **Service Enumeration**
  - [ ] SMB: enum4linux, smbclient, smbmap, crackmapexec
  - [ ] LDAP: ldapsearch, windapsearch
  - [ ] DNS: dig, dnsenum, dnsrecon, fierce
  - [ ] SNMP: snmpwalk, onesixtyone, snmp-check
  - [ ] NFS: showmount, nfs-ls
- [ ] **Web Directory Brute-forcing**
  - [ ] Gobuster (múltiplos modos)
  - [ ] Feroxbuster
  - [ ] FFuF (fuzzing avançado)
  - [ ] Dirbuster, dirb
##
### Network Troubleshooting Tools (NOVO)
- [ ] **ping** - Teste de conectividade
- [ ] **traceroute/tracert** - Rastreamento de rota
- [ ] **nslookup/dig** - DNS queries
- [ ] **netstat** - Conexões de rede
- [ ] **arp** - ARP table
- [ ] **route** - Tabela de roteamento
- [ ] **tcpdump** - Packet capture CLI
- [ ] **iptables** (Linux) - Firewall rules
##
### Prática
- [ ] TryHackMe: Red Team Fundamentals
- [ ] HackTheBox: Máquinas Easy/Medium focadas em enum
- [ ] Criar scripts próprios de enumeração em Python/Bash
- [ ] Resolver desafios de OSINT (CTFs específicos)
---
## FASE 2.5: WIRELESS & PHYSICAL SECURITY (NOVO)
### Wireless Hacking
- [ ] **Fundamentos WiFi**
  - [ ] 802.11 standards (a/b/g/n/ac/ax)
  - [ ] Canais e frequências (2.4GHz vs 5GHz)
  - [ ] WEP, WPA, WPA2, WPA3
  - [ ] EAP, PEAP, WPS
- [ ] **Wireless Attacks**
  - [ ] WPA/WPA2 cracking
    - [ ] Handshake capture (aircrack-ng)
    - [ ] Dictionary attacks
    - [ ] PMKID attack
  - [ ] Evil Twin attacks
    - [ ] Rogue Access Point
    - [ ] Captive portal attacks
    - [ ] hostapd-wpe
  - [ ] WPS exploitation (Reaver, Bully)
  - [ ] Deauthentication attacks
  - [ ] KARMA/MANA attacks
  - [ ] Rogue AP detection evasion
- [ ] **Bluetooth attacks**
  - [ ] Bluejacking
  - [ ] Bluesnarfing
  - [ ] BlueBorne
- [ ] **NFC/RFID attacks** (básico)
  - [ ] Cloning attacks
  - [ ] Sniffing
##
### Physical Security
- [ ] **Lock Picking**
  - [ ] Pin tumbler locks
  - [ ] Ferramentas (tension wrench, picks)
  - [ ] Prática em padlocks
- [ ] **Badge Cloning**
  - [ ] RFID cloning (Proxmark3)
  - [ ] NFC cloning
  - [ ] HID cards
- [ ] **USB Drop Attacks**
  - [ ] USB Rubber Ducky
  - [ ] Bash Bunny
  - [ ] BadUSB
  - [ ] Payload development
- [ ] **Social Engineering Físico**
  - [ ] Tailgating techniques
  - [ ] Pretexting presencial
  - [ ] Dumpster diving
  - [ ] Shoulder surfing
- [ ] **Camera Evasion**
  - [ ] Identificação de câmeras
  - [ ] Pontos cegos
  - [ ] Técnicas de evasão
- [ ] **Physical Intrusion Planning**
  - [ ] Site reconnaissance
  - [ ] Entry/exit points
  - [ ] Security guards e patrols
##
### Ferramentas Wireless
- [ ] aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
- [ ] wifite (automated)
- [ ] kismet (wireless detection)
- [ ] WiFi Pineapple (hardware - opcional)
- [ ] bettercap (MITM framework)
- [ ] hostapd-wpe (rogue AP)
- [ ] Proxmark3 (RFID/NFC)
##
### Prática
- [ ] Montar lab WiFi caseiro (router de teste)
- [ ] Praticar WPA2 cracking com handshake próprio
- [ ] Criar Evil Twin para teste controlado
- [ ] Lock picking kit e prática
- [ ] Programar USB Rubber Ducky básico
- [ ] TryHackMe: WiFi Hacking 101
---
## FASE 3: EXPLORAÇÃO INICIAL
### Web Application Attacks
- [ ] **SQL Injection**
  - [ ] Union-based SQLi
  - [ ] Boolean-based blind SQLi
  - [ ] Time-based blind SQLi
  - [ ] Error-based SQLi
  - [ ] Out-of-band SQLi
  - [ ] sqlmap (automated)
  - [ ] Manual exploitation
- [ ] **Cross-Site Scripting (XSS)**
  - [ ] Reflected XSS
  - [ ] Stored XSS
  - [ ] DOM-based XSS
  - [ ] XSS bypasses (WAF evasion)
  - [ ] BeEF framework
- [ ] **CSRF** - Cross-Site Request Forgery
- [ ] **SSRF** - Server-Side Request Forgery
  - [ ] Internal network enumeration
  - [ ] Cloud metadata abuse (AWS, Azure)
- [ ] **XXE** - XML External Entity
- [ ] **File Upload Vulnerabilities**
  - [ ] Bypass de filtros (extension, MIME type)
  - [ ] Web shells (PHP, ASPX)
  - [ ] Magic bytes manipulation
- [ ] **Directory Traversal / LFI/RFI**
  - [ ] Path traversal
  - [ ] Local File Inclusion
  - [ ] Remote File Inclusion
  - [ ] Log poisoning
- [ ] **Authentication Bypass**
  - [ ] Logic flaws
  - [ ] Session management issues
  - [ ] JWT attacks
- [ ] **Business Logic Flaws**
  - [ ] Race conditions
  - [ ] Price manipulation
  - [ ] Parameter tampering
- [ ] **IDOR** - Insecure Direct Object Reference
- [ ] **Deserialization attacks**
- [ ] **SSTI** - Server-Side Template Injection
- [ ] **OWASP Top 10** (completo)
##
### Network Exploitation
- [ ] **SMB Exploitation**
  - [ ] EternalBlue (MS17-010)
  - [ ] SMBGhost (CVE-2020-0796)
  - [ ] SMB relay attacks
  - [ ] Null sessions
- [ ] **RDP Attacks**
  - [ ] BlueKeep (CVE-2019-0708)
  - [ ] Password spraying
  - [ ] RDP session hijacking
- [ ] **SSH Exploitation**
  - [ ] Brute-force attacks
  - [ ] Key-based attacks
  - [ ] Weak algorithms
- [ ] **FTP/TFTP Exploitation**
  - [ ] Anonymous login
  - [ ] Bounce attacks
- [ ] **SNMP Exploitation**
  - [ ] Community string guessing
  - [ ] Information disclosure
- [ ] **DNS Attacks**
  - [ ] DNS zone transfer
  - [ ] DNS poisoning
  - [ ] DNS tunneling
- [ ] **MITM Attacks** (básico)
  - [ ] ARP spoofing
  - [ ] LLMNR/NBT-NS poisoning (Responder)
### Password Attacks
- [ ] **Brute Force**
  - [ ] Hydra (múltiplos serviços)
  - [ ] Medusa
  - [ ] Patator
  - [ ] Ncrack
- [ ] **Password Spraying**
  - [ ] Single password, multiple users
  - [ ] CrackMapExec
- [ ] **Hash Cracking**
  - [ ] John the Ripper (CPU)
  - [ ] Hashcat (GPU)
  - [ ] Rainbow tables (conceito)
  - [ ] Hash identification (hash-identifier, hashid)
- [ ] **Default Credentials**
  - [ ] DefaultCreds-cheat-sheet
  - [ ] RouterPasswords
  - [ ] CIRT.net

### Prática
- [ ] PortSwigger Web Security Academy (TODOS os labs)
- [ ] HackTheBox: 15 máquinas Medium focadas em web
- [ ] VulnHub: OWASP BWA, DVWA, bWAPP
- [ ] TryHackMe: Web Fundamentals Path
- [ ] Resolver 10+ web CTF challenges
- [ ] Criar cheat sheet próprio de payloads
---
## FASE 4: POST-EXPLOITATION
### Privilege Escalation - Linux
- [ ] **SUID/SGID Binaries**
  - [ ] find / -perm -4000 2>/dev/null
  - [ ] GTFOBins exploitation
- [ ] **Kernel Exploits**
  - [ ] Dirty COW
  - [ ] DirtyCred
  - [ ] linux-exploit-suggester
- [ ] **Cron Jobs**
  - [ ] Writable cron scripts
  - [ ] PATH hijacking em cron
- [ ] **Capabilities**
  - [ ] getcap -r / 2>/dev/null
  - [ ] Capability abuse
- [ ] **Path Hijacking**
  - [ ] $PATH manipulation
  - [ ] Relative paths em scripts
- [ ] **Sudo Misconfigurations**
  - [ ] sudo -l abuse
  - [ ] LD_PRELOAD
  - [ ] LD_LIBRARY_PATH
  - [ ] NOPASSWD entries
- [ ] **Writable /etc/passwd e /etc/shadow**
- [ ] **NFS no_root_squash**
- [ ] **Docker Escape**
  - [ ] Privileged containers
  - [ ] Docker socket exposure
- [ ] **Shared libraries** (.so hijacking)
- [ ] **Kernel modules** (menos comum)
### Privilege Escalation - Windows
- [ ] **Token Impersonation**
  - [ ] Potato attacks (Hot, Rotten, Juicy, Sweet)
  - [ ] PrintSpoofer
  - [ ] SeImpersonatePrivilege abuse
- [ ] **UAC Bypass**
  - [ ] FodHelper
  - [ ] EventViewer
  - [ ] DiskCleanup
- [ ] **Unquoted Service Paths**
- [ ] **DLL Hijacking**
  - [ ] DLL search order
  - [ ] Missing DLLs
- [ ] **Registry Exploits**
  - [ ] AlwaysInstallElevated
  - [ ] Autorun executables
  - [ ] Service registry modifications
- [ ] **Kernel Exploits**
  - [ ] MS16-032, MS17-017
  - [ ] Windows Exploit Suggester
- [ ] **SeImpersonate/SeAssignPrimaryToken**
- [ ] **Scheduled Tasks Abuse**
- [ ] **Credentials in Files**
  - [ ] Unattended XML files
  - [ ] PowerShell history
  - [ ] IIS web.config
  - [ ] Registry (Autologon)
- [ ] **Services Exploitation**
  - [ ] Insecure service permissions
  - [ ] Service binary path hijacking
### Ferramentas de Enumeração
- [ ] **Linux**
  - [ ] LinPEAS (automated)
  - [ ] LinEnum
  - [ ] Linux Smart Enumeration (lse.sh)
  - [ ] pspy (process monitoring)
- [ ] **Windows**
  - [ ] WinPEAS (automated)
  - [ ] PowerUp (PowerShell)
  - [ ] Seatbelt (C#)
  - [ ] SharpUp (C#)
  - [ ] PrivescCheck (PowerShell)
- [ ] **PEASS-ng suite** (ambos)
### Persistence
#### Linux
- [ ] Cron jobs maliciosos
- [ ] Systemd timers
- [ ] SSH keys (~/.ssh/authorized_keys)
- [ ] Backdoor em binários (LD_PRELOAD)
- [ ] .bashrc / .profile modification
- [ ] /etc/passwd backdoor user
- [ ] Rootkits (conceito básico)
#### Windows
- [ ] Registry run keys (HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run)
- [ ] Scheduled tasks
- [ ] WMI events
- [ ] Service creation
- [ ] Startup folder
- [ ] Backdoor accounts
- [ ] Golden Ticket (AD environment)
- [ ] Skeleton Key (AD environment)
### Lateral Movement
- [ ] **Pass-the-Hash (PtH)**
  - [ ] CrackMapExec/NetExec
  - [ ] Evil-WinRM
  - [ ] Impacket (psexec.py, wmiexec.py, smbexec.py)
- [ ] **Pass-the-Ticket (PtT)**
  - [ ] Rubeus
  - [ ] Mimikatz
- [ ] **WMI/WinRM** - Remote execution
- [ ] **PSExec/PsRemoting**
  - [ ] Sysinternals PSExec
  - [ ] Impacket psexec.py
- [ ] **RDP Hijacking**
  - [ ] tscon
  - [ ] Session hijacking
- [ ] **DCOM Exploitation**
  - [ ] MMC20.Application
  - [ ] ShellBrowserWindow
- [ ] **SSH Tunneling** (port forwarding)
- [ ] **Pivoting**
  - [ ] chisel
  - [ ] ligolo-ng
  - [ ] sshuttle
  - [ ] Metasploit routes
### Hardening Awareness
Para cada técnica de privilege escalation/lateral movement, estudar:
- [ ] Controles defensivos que previnem
- [ ] Como seriam detectados (logs, SIEM)
- [ ] Mitigações e hardening
- [ ] Indicadores de comprometimento (IoCs)
### Prática
- [ ] HackTheBox: 20+ máquinas Medium/Hard
- [ ] TryHackMe: Post-Exploitation Path
- [ ] Resolver máquinas que exigem pivoting
- [ ] Criar cheat sheets de privesc (Linux e Windows)
- [ ] Documentar técnicas com screenshots
---
## FASE 5: ACTIVE DIRECTORY DOMINATION
### AD Fundamentals (Aprofundamento)
- [ ] **Estrutura do AD**
  - [ ] Domains, Trees, Forests
  - [ ] Organizational Units (OUs)
  - [ ] Trusts (Parent-Child, Cross-Forest, External)
- [ ] **Objetos do AD**
  - [ ] Users, Groups, Computers
  - [ ] Service Accounts
  - [ ] Group Policy Objects (GPO)
- [ ] **Autenticação**
  - [ ] Kerberos (TGT, TGS, PAC)
  - [ ] NTLM (NTLMv1, NTLMv2)
- [ ] **Protocolos**
  - [ ] LDAP/LDAPS
  - [ ] SMB/CIFS
  - [ ] DNS (AD-integrated)
  - [ ] Kerberos (88/TCP)
### Enumeration
- [ ] **BloodHound/SharpHound**
  - [ ] Data collection
  - [ ] Path analysis
  - [ ] Custom queries
  - [ ] Attack paths
- [ ] **PowerView** (PowerShell)
  - [ ] Domain enumeration
  - [ ] User/Group enumeration
  - [ ] ACL enumeration
  - [ ] Trust mapping
- [ ] **ADRecon**
  - [ ] CSV/HTML reports
  - [ ] Comprehensive enumeration
- [ ] **LDAP Queries**
  - [ ] ldapsearch (Linux)
  - [ ] ADExplorer (Windows)
  - [ ] Manual LDAP queries
- [ ] **Domain Trust Mapping**
  - [ ] Get-DomainTrust
  - [ ] nltest
### Initial Foothold
- [ ] **LLMNR/NBT-NS Poisoning**
  - [ ] Responder (capture hashes)
  - [ ] Mitm6 (IPv6 attacks)
  - [ ] Inveigh (PowerShell variant)
- [ ] **SMB Relay Attacks**
  - [ ] ntlmrelayx.py (Impacket)
  - [ ] MultiRelay
  - [ ] SMB signing disabled exploitation
- [ ] **IPv6 Attacks**
  - [ ] mitm6 (DNS takeover)
  - [ ] IPv6 + WPAD attacks
- [ ] **Password Spraying em escala**
  - [ ] CrackMapExec/NetExec
  - [ ] DomainPasswordSpray
  - [ ] Spray toolkit
  - [ ] Lockout threshold awareness
### Privilege Escalation & Credential Access
- [ ] **Kerberoasting**
  - [ ] Rubeus
  - [ ] GetUserSPNs.py (Impacket)
  - [ ] Cracking com Hashcat (mode 13100)
  - [ ] Targeted Kerberoasting
- [ ] **AS-REP Roasting**
  - [ ] Usuários sem pre-authentication
  - [ ] GetNPUsers.py (Impacket)
  - [ ] Rubeus asreproast
- [ ] **DCSync**
  - [ ] Mimikatz
  - [ ] secretsdump.py (Impacket)
  - [ ] Replication permissions abuse
- [ ] **NTDS.dit Extraction**
  - [ ] Volume Shadow Copy
  - [ ] DCSync (privileged)
  - [ ] Offline extraction
- [ ] **LSASS Dumping**
  - [ ] Mimikatz
  - [ ] ProcDump (Sysinternals)
  - [ ] Comsvcs.dll (rundll32)
  - [ ] Task Manager dump
  - [ ] Nanodump, Dumpert
- [ ] **Group Policy Abuse**
  - [ ] SharpGPOAbuse
  - [ ] Immediate scheduled tasks
  - [ ] Group Policy Preferences (GPP)
  - [ ] SYSVOL password retrieval
### Delegation Attacks
- [ ] **Unconstrained Delegation**
  - [ ] Printer bug
  - [ ] TGT extraction
  - [ ] Rubeus monitor
- [ ] **Constrained Delegation**
  - [ ] S4U2Self, S4U2Proxy
  - [ ] Rubeus s4u
- [ ] **Resource-Based Constrained Delegation (RBCD)**
  - [ ] msDS-AllowedToActOnBehalfOfOtherIdentity
  - [ ] Computer account creation
  - [ ] Rubeus RBCD
### Certificate Services Attacks
- [ ] **AD CS (Active Directory Certificate Services)**
  - [ ] Certify (enumeration)
  - [ ] Certipy (exploitation)
  - [ ] ESC1: Misconfigured Certificate Templates
  - [ ] ESC2: Misconfigured Certificate Templates
  - [ ] ESC3: Misconfigured Enrollment Agent Templates
  - [ ] ESC4: Vulnerable Certificate Template Access Control
  - [ ] ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
  - [ ] ESC7: Vulnerable Certificate Authority Access Control
  - [ ] ESC8: NTLM Relay to AD CS HTTP Endpoints
### Persistence & Domain Dominance
- [ ] **Golden Ticket**
  - [ ] Forjar TGT
  - [ ] Mimikatz
  - [ ] Ticketer.py (Impacket)
- [ ] **Silver Ticket**
  - [ ] Forjar TGS
  - [ ] Service-specific tickets
- [ ] **Skeleton Key**
  - [ ] Mimikatz misc::skeleton
  - [ ] Universal password
- [ ] **DSRM Password**
  - [ ] Directory Services Restore Mode
  - [ ] Persistence no DC
- [ ] **Malicious GPO**
  - [ ] SharpGPOAbuse
  - [ ] Immediate scheduled tasks
- [ ] **SID History Injection**
  - [ ] Mimikatz
  - [ ] Enterprise Admin persistence
- [ ] **AdminSDHolder**
  - [ ] ACL modifications
  - [ ] Persistence via protected groups
### Trust Exploitation
- [ ] **Cross-Forest Attacks**
  - [ ] SID filtering bypass
  - [ ] Trust keys
- [ ] **SID History Attacks**
  - [ ] Domain migration abuse
- [ ] **Foreign Security Principals**
### Ferramentas AD
- [ ] **Impacket suite** (todos os scripts)
  - [ ] psexec.py, wmiexec.py, smbexec.py
  - [ ] secretsdump.py
  - [ ] GetUserSPNs.py, GetNPUsers.py
  - [ ] ticketer.py, getTGT.py
- [ ] **CrackMapExec / NetExec**
- [ ] **Rubeus** (Kerberos abuse)
- [ ] **Mimikatz / Pypykatz**
- [ ] **BloodHound** (enumeration e visualização)
- [ ] **Certify / Certipy** (AD CS)
- [ ] **PowerView** (PowerShell)
- [ ] **SharpHound** (data collection)
### Defensive Controls (NOVO)
Para cada ataque de AD, estudar:
- [ ] Como é detectado (Event IDs do Windows)
- [ ] Configurações de hardening que previnem
- [ ] Logs relevantes (4768, 4769, 4776, 5136, etc.)
- [ ] Ferramentas de defesa (Microsoft Defender for Identity, Splunk)
### Prática
- [ ] TryHackMe: Attacking and Defending Active Directory
- [ ] HackTheBox Pro Labs:
  - [ ] RastaLabs (AD focus)
  - [ ] Offshore (Red Team)
- [ ] PentesterAcademy: Attacking and Defending AD
- [ ] **Criar lab AD próprio**
  - [ ] 1 Domain Controller (Windows Server)
  - [ ] 2-3 Workstations (Windows 10/11)
  - [ ] Vulnerabilidades intencionais
  - [ ] GOAD (Game of Active Directory)
  - [ ] DetectionLab
- [ ] Resolver 5+ máquinas HTB focadas em AD
---
## FASE 6: EVASÃO E STEALTH (CONTINUAÇÃO)
  - [ ] Sleep timers
  - [ ] Environment checks
  - [ ] User interaction requirements
### Defense Evasion Techniques
- [ ] **AMSI Bypass**
  - [ ] AntiMalware Scan Interface
  - [ ] Memory patching
  - [ ] Obfuscation
  - [ ] AMSITrigger
- [ ] **ETW Bypass**
  - [ ] Event Tracing for Windows
  - [ ] Provider removal
  - [ ] Patching techniques
- [ ] **Sysmon Evasion**
  - [ ] Rule analysis
  - [ ] Event ID manipulation
  - [ ] Driver unloading (arriscado)
- [ ] **Log Tampering**
  - [ ] Event log clearing
  - [ ] Selective log deletion
  - [ ] Log modification
  - [ ] wevtutil
- [ ] **Timestomping**
  - [ ] Modificação de timestamps (MACE)
  - [ ] SetMACE tools
- [ ] **Process Hiding**
  - [ ] Rootkit techniques (conceito)
  - [ ] DKOM (Direct Kernel Object Manipulation)
- [ ] **Unhooking**
  - [ ] API unhooking
  - [ ] EDR hooks bypass
  - [ ] Direct syscalls
### Custom Tooling
- [ ] **Exploit Development (Básico)**
  - [ ] Buffer overflow exploitation
  - [ ] Shellcode writing (Assembly)
  - [ ] Exploit adaptation
- [ ] **Custom C2 Frameworks**
  - [ ] HTTP/HTTPS C2
  - [ ] DNS C2
  - [ ] Protocol implementation
- [ ] **Payload Generators**
  - [ ] Shellcode em C/Assembly
  - [ ] Stagers customizados
  - [ ] Dropper development
- [ ] **Evasion em Go**
  - [ ] Malware development (educacional)
  - [ ] Cross-platform compilation
  - [ ] Low-level Windows API
- [ ] **Evasion em C#**
  - [ ] .NET assemblies
  - [ ] Reflection
  - [ ] In-memory execution
### Anti-Forensics (NOVO)
- [ ] **Artifact Removal**
  - [ ] Prefetch files
  - [ ] Shimcache
  - [ ] AmCache
  - [ ] USN Journal
- [ ] **Memory Forensics Awareness**
  - [ ] Volatility framework (conceitos)
  - [ ] Memory dumps
  - [ ] Anti-memory forensics
- [ ] **Disk Forensics Awareness**
  - [ ] File carving
  - [ ] Deleted file recovery
  - [ ] Anti-carving techniques
- [ ] **Network Forensics Evasion**
  - [ ] Encrypted C2 traffic
  - [ ] Protocol mimicry
  - [ ] Traffic normalization
### Prática
- [ ] **Sektor7 Institute**
  - [ ] Malware Development Essentials
  - [ ] Red Team Operator: Malware Development Intermediate
- [ ] **PEN-300/OSEP Prep**
  - [ ] Evasion Techniques and Breaching Defenses
- [ ] Criar payloads que bypassam:
  - [ ] Windows Defender
  - [ ] Microsoft Defender for Endpoint (simulado)
  - [ ] Common AVs (VirusTotal score < 5/70)
- [ ] Desenvolver mini C2 funcional
- [ ] Contribuir em projetos open-source de evasão
---
## FASE 7: CLOUD & CONTAINERS
### Cloud Fundamentals
- [ ] **Cloud Service Models**
  - [ ] IaaS (Infrastructure as a Service)
  - [ ] PaaS (Platform as a Service)
  - [ ] SaaS (Software as a Service)
- [ ] **Cloud Deployment Models**
  - [ ] Public Cloud
  - [ ] Private Cloud
  - [ ] Hybrid Cloud
- [ ] **Shared Responsibility Model**
- [ ] **Infrastructure as Code (IaC)**
  - [ ] Terraform
  - [ ] CloudFormation (AWS)
  - [ ] ARM Templates (Azure)
- [ ] **Serverless Computing**
  - [ ] AWS Lambda
  - [ ] Azure Functions
  - [ ] Google Cloud Functions
- [ ] **CDN (Content Delivery Network)**
### AWS (Amazon Web Services)
- [ ] **Fundamentos AWS**
  - [ ] IAM (Users, Roles, Policies)
  - [ ] EC2 (Elastic Compute Cloud)
  - [ ] S3 (Simple Storage Service)
  - [ ] VPC (Virtual Private Cloud)
  - [ ] Lambda (Serverless)
- [ ] **S3 Misconfigurations**
  - [ ] Buckets públicos
  - [ ] Policy vulnerabilities
  - [ ] ACL misconfigurations
  - [ ] Enumeration (aws s3 ls, s3scanner)
- [ ] **IAM Privilege Escalation**
  - [ ] Pacu framework
  - [ ] 20+ escalation paths
  - [ ] Policy analysis
  - [ ] Role assumption
- [ ] **Lambda Exploitation**
  - [ ] Function enumeration
  - [ ] Code injection
  - [ ] Environment variables
- [ ] **EC2 Metadata Abuse**
  - [ ] IMDSv1 (169.254.169.254)
  - [ ] IMDSv2 (token-based)
  - [ ] Credential extraction
- [ ] **CloudTrail Log Analysis**
  - [ ] Log tampering
  - [ ] Suspicious activities
- [ ] **Secrets Manager / Parameter Store**
  - [ ] Secrets extraction
  - [ ] Access policies
### Azure
- [ ] **Fundamentos Azure**
  - [ ] Azure AD (Entra ID)
  - [ ] Resource Groups
  - [ ] Virtual Machines
  - [ ] Storage Accounts
  - [ ] Azure Functions
- [ ] **Azure AD Enumeration**
  - [ ] AzureHound (BloodHound for Azure)
  - [ ] ROADtools
  - [ ] AADInternals
  - [ ] PowerZure
- [ ] **Service Principal Abuse**
  - [ ] Application permissions
  - [ ] Certificate-based authentication
  - [ ] Client secrets
- [ ] **Managed Identity Exploitation**
  - [ ] System-assigned
  - [ ] User-assigned
  - [ ] IMDS access (169.254.169.254)
- [ ] **Azure Key Vault Extraction**
  - [ ] Secrets, keys, certificates
  - [ ] Access policies
- [ ] **Azure Runbooks**
  - [ ] Automation accounts
  - [ ] Code execution
### GCP (Google Cloud Platform)
- [ ] **Fundamentos GCP**
  - [ ] IAM
  - [ ] Compute Engine
  - [ ] Cloud Storage
  - [ ] Cloud Functions
- [ ] **GCS Bucket Enumeration**
  - [ ] Public buckets
  - [ ] Misconfigured permissions
- [ ] **Service Account Exploitation**
  - [ ] Key extraction
  - [ ] Privilege escalation
- [ ] **Metadata Server Abuse**
  - [ ] 169.254.169.254
  - [ ] Service account tokens
### Kubernetes/Docker
- [ ] **Docker Fundamentals**
  - [ ] Images, containers, volumes
  - [ ] Dockerfile
  - [ ] Docker networking
- [ ] **Kubernetes Fundamentals**
  - [ ] Pods, services, deployments
  - [ ] Namespaces
  - [ ] RBAC (Role-Based Access Control)
  - [ ] Secrets, ConfigMaps
- [ ] **Container Escape**
  - [ ] Privileged containers
  - [ ] Docker socket exposure (/var/run/docker.sock)
  - [ ] CAP_SYS_ADMIN abuse
  - [ ] Kernel exploits (DirtyCow em containers)
- [ ] **Exposed APIs**
  - [ ] Kubelet API (10250/TCP)
  - [ ] Kubernetes Dashboard
  - [ ] Docker API (2375/TCP)
  - [ ] etcd (2379/TCP)
- [ ] **Misconfigured RBAC**
  - [ ] Overly permissive roles
  - [ ] Service account token abuse
  - [ ] kubectl access
- [ ] **Supply Chain Attacks**
  - [ ] Poisoned images
  - [ ] Malicious base images
  - [ ] Docker Hub backdoors
- [ ] **Kubernetes Attacks**
  - [ ] Pod creation for persistence
  - [ ] Secrets extraction
  - [ ] Lateral movement entre pods
### Ferramentas Cloud
- [ ] **AWS**
  - [ ] Pacu (exploitation framework)
  - [ ] ScoutSuite (security auditing)
  - [ ] Prowler (CIS benchmark)
  - [ ] aws-cli
  - [ ] CloudMapper
- [ ] **Azure**
  - [ ] AzureHound
  - [ ] ROADtools (Azure AD reconnaissance)
  - [ ] Stormspotter (graph visualization)
  - [ ] PowerZure
  - [ ] az-cli
- [ ] **GCP**
  - [ ] gcloud CLI
  - [ ] GCPBucketBrute
  - [ ] ScoutSuite (multi-cloud)
- [ ] **Kubernetes/Docker**
  - [ ] kube-hunter (vulnerability scanner)
  - [ ] kubeaudit (audit tool)
  - [ ] kubectl (CLI)
  - [ ] kubeletctl
  - [ ] amicontained (container introspection)
### Prática
- [ ] HackTheBox: Máquinas cloud-focused
- [ ] Criar labs em free tier:
  - [ ] AWS Free Tier (12 meses)
  - [ ] Azure Free Account
  - [ ] GCP Free Trial
- [ ] TryHackMe: Cloud Penetration Testing
- [ ] Resolver 5+ CTFs focados em cloud
- [ ] **CloudGoat** (AWS vulnerable by design)
- [ ] **AzureGoat** (Azure vulnerable labs)
- [ ] **GCP-Goat** (GCP vulnerable scenarios)
---
## FASE 8: MOBILE & IoT SECURITY
### Mobile Security Fundamentals
- [ ] **Android Architecture**
  - [ ] Application sandbox
  - [ ] Permissions model
  - [ ] APK structure
  - [ ] Intents e Activities
- [ ] **iOS Architecture**
  - [ ] App Sandbox
  - [ ] Code signing
  - [ ] Keychain
  - [ ] IPA structure
### Android Pentesting
- [ ] **Static Analysis**
  - [ ] APK decompilation (apktool)
  - [ ] Dex to jar (dex2jar)
  - [ ] Reverse engineering (jadx, JEB)
  - [ ] Manifest analysis
  - [ ] Hardcoded secrets
- [ ] **Dynamic Analysis**
  - [ ] Frida framework
  - [ ] Objection
  - [ ] SSL pinning bypass
  - [ ] Root detection bypass
- [ ] **MobSF** (Mobile Security Framework)
  - [ ] Automated analysis
  - [ ] OWASP Mobile Top 10 testing
- [ ] **Drozer** (Android exploitation)
- [ ] **ADB (Android Debug Bridge)**
### iOS Pentesting
- [ ] **Jailbreaking**
  - [ ] checkra1n, unc0ver
  - [ ] SSH access
  - [ ] Filesystem access
- [ ] **Static Analysis**
  - [ ] IPA extraction
  - [ ] Class-dump
  - [ ] Hopper/Ghidra (binary analysis)
- [ ] **Dynamic Analysis**
  - [ ] Frida (iOS)
  - [ ] Objection
  - [ ] SSL pinning bypass
  - [ ] Jailbreak detection bypass
- [ ] **Keychain Dumping**
### OWASP Mobile Top 10
- [ ] M1: Improper Platform Usage
- [ ] M2: Insecure Data Storage
- [ ] M3: Insecure Communication
- [ ] M4: Insecure Authentication
- [ ] M5: Insufficient Cryptography
- [ ] M6: Insecure Authorization
- [ ] M7: Client Code Quality
- [ ] M8: Code Tampering
- [ ] M9: Reverse Engineering
- [ ] M10: Extraneous Functionality
### IoT Security
- [ ] **IoT Protocols**
  - [ ] MQTT (Message Queuing Telemetry Transport)
  - [ ] CoAP (Constrained Application Protocol)
  - [ ] Zigbee
  - [ ] Z-Wave
  - [ ] BLE (Bluetooth Low Energy)
- [ ] **Firmware Analysis**
  - [ ] Firmware extraction
  - [ ] binwalk (firmware analysis)
  - [ ] firmwalker (script scanning)
  - [ ] strings, hexdump
  - [ ] Entropy analysis
- [ ] **Hardware Interfaces**
  - [ ] UART (Universal Asynchronous Receiver-Transmitter)
  - [ ] JTAG (Joint Test Action Group)
  - [ ] SPI (Serial Peripheral Interface)
  - [ ] I2C (Inter-Integrated Circuit)
- [ ] **Hardware Hacking**
  - [ ] Bus Pirate
  - [ ] Logic analyzer
  - [ ] Multimeter usage
  - [ ] Soldering basics
- [ ] **ICS/SCADA (Industrial Control Systems)**
  - [ ] Modbus protocol
  - [ ] DNP3
  - [ ] Shodan for ICS
  - [ ] PLCs (Programmable Logic Controllers)
### Ferramentas Mobile & IoT
- [ ] **Mobile**
  - [ ] Frida, Objection
  - [ ] MobSF
  - [ ] apktool, jadx, dex2jar
  - [ ] Drozer
  - [ ] SSL Kill Switch (iOS)
- [ ] **IoT**
  - [ ] binwalk, firmwalker
  - [ ] MQTT Explorer
  - [ ] Bus Pirate
  - [ ] Attify Badge
  - [ ] Flipper Zero
### Prática
- [ ] **DIVA** (Damn Insecure and Vulnerable App - Android)
- [ ] **InsecureBankv2** (Android)
- [ ] **DVHMA** (Damn Vulnerable Hybrid Mobile App)
- [ ] **IoTGoat** (vulnerable IoT firmware)
- [ ] TryHackMe: Mobile Security
- [ ] HackTheBox: Mobile challenges
- [ ] Participar de mobile bug bounty programs
---
## FASE 9: RED TEAM OPERATIONS
### C2 Frameworks (Command & Control)
- [ ] **Cobalt Strike** (Industry standard)
  - [ ] Beacons
  - [ ] Malleable C2 profiles
  - [ ] Aggressor scripts
  - [ ] Infrastructure setup
  - [ ] Pivoting e redirectors
- [ ] **Mythic** (Open-source)
  - [ ] Agents (Apollo, Apfell)
  - [ ] Payload generation
  - [ ] Tasking
- [ ] **Sliver** (Modern C2 by BishopFox)
  - [ ] Implants
  - [ ] Multiplayer mode
  - [ ] MTLS, HTTP(S), DNS
- [ ] **Havoc** (Open-source alternative)
  - [ ] Demons (agents)
  - [ ] C2 infrastructure
- [ ] **Covenant** (.NET C2)
  - [ ] Grunts
  - [ ] Tasks
- [ ] **Empire/Starkiller** (PowerShell C2)
  - [ ] Stagers e agents
  - [ ] Modules
### Infrastructure Setup
- [ ] **Redirectors**
  - [ ] Apache mod_rewrite
  - [ ] nginx proxy
  - [ ] Traffic filtering
  - [ ] Categorização de domínios
- [ ] **Domain Fronting**
  - [ ] CDN abuse (CloudFront, CloudFlare)
  - [ ] Host header manipulation
- [ ] **DNS Tunneling**
  - [ ] dnscat2
  - [ ] iodine
  - [ ] DNS C2 channels
- [ ] **HTTPS C2**
  - [ ] Certificate management
  - [ ] Let's Encrypt
  - [ ] SSL/TLS best practices
- [ ] **Cloud-based C2**
  - [ ] AWS/Azure/GCP hosting
  - [ ] Serverless C2
  - [ ] Lambda/Functions for C2
### Social Engineering
- [ ] **Phishing Campaigns**
  - [ ] Gophish framework
  - [ ] Email spoofing (SPF/DKIM/DMARC bypass)
  - [ ] Credential harvesting pages
  - [ ] Payload delivery
  - [ ] Attachment macros
  - [ ] HTA/ISO/LNK file abuse
- [ ] **Vishing** (Voice Phishing)
  - [ ] Pretexting scripts
  - [ ] VOIP setup
  - [ ] Social engineering psychology
- [ ] **Physical Intrusion**
  - [ ] Tailgating
  - [ ] Badge cloning (já coberto)
  - [ ] Lock picking (já coberto)
  - [ ] Site reconnaissance
- [ ] **USB Drops**
  - [ ] Rubber Ducky payloads
  - [ ] Bash Bunny scripts
  - [ ] O.MG Cable
- [ ] **Clone Websites**
  - [ ] SET (Social Engineer Toolkit)
  - [ ] evilginx2 (phishing framework)
  - [ ] Modlishka
- [ ] **Watering Hole Attacks** (conceito)
### Advanced Techniques
- [ ] **Protocol Smuggling**
  - [ ] HTTP request smuggling
  - [ ] CL.TE, TE.CL vulnerabilities
- [ ] **ICMP Tunneling**
  - [ ] ptunnel
  - [ ] ICMP C2 channels
- [ ] **Fileless Malware**
  - [ ] In-memory execution
  - [ ] PowerShell Empire
  - [ ] Living off the land
- [ ] **Supply Chain Compromise** (estudo teórico)
  - [ ] Dependency confusion
  - [ ] Typosquatting
  - [ ] Software supply chain
- [ ] **Watering Hole Attacks** (implementação)
- [ ] **Zero-Click Exploits** (estudo teórico)
- [ ] **APT Simulation**
  - [ ] MITRE ATT&CK TTPs
  - [ ] Multi-stage attacks
  - [ ] Long-term persistence
### Operational Security (OPSEC)
- [ ] **Infrastructure Hardening**
  - [ ] Firewall rules
  - [ ] SSH key-based auth
  - [ ] Fail2ban
  - [ ] Log monitoring
- [ ] **Anonymity**
  - [ ] VPN chains
  - [ ] Tor network
  - [ ] Proxychains
  - [ ] Burner infrastructure
- [ ] **Anti-forensics** (já coberto)
- [ ] **Traffic Blending**
  - [ ] Normal user behavior simulation
  - [ ] C2 traffic mimicry
  - [ ] Beaconing jitter
- [ ] **Attribution Avoidance**
  - [ ] OpSec fails (study of real incidents)
  - [ ] Metadata removal
  - [ ] Timezone awareness
  - [ ] Language indicators
- [ ] **Compartmentalization**
  - [ ] Separate infrastructure per client
  - [ ] Burn after use mentality
### Threat Intelligence Integration (NOVO)
- [ ] **MITRE ATT&CK Framework**
  - [ ] TTPs mapping
  - [ ] Adversary emulation
  - [ ] ATT&CK Navigator
- [ ] **Cyber Kill Chain** (Lockheed Martin)
  - [ ] Reconnaissance
  - [ ] Weaponization
  - [ ] Delivery
  - [ ] Exploitation
  - [ ] Installation
  - [ ] Command & Control
  - [ ] Actions on Objectives
- [ ] **Diamond Model**
  - [ ] Adversary, Capability, Infrastructure, Victim
  - [ ] Threat intelligence analysis
### Reporting & Communication
- [ ] **Executive Summaries**
  - [ ] Para C-level (CEO, CISO)
  - [ ] Business impact
  - [ ] Risk quantification
  - [ ] High-level findings
- [ ] **Technical Reports**
  - [ ] Para equipe técnica (IT, SOC)
  - [ ] Detailed attack paths
  - [ ] IoCs (Indicators of Compromise)
  - [ ] Evidence (screenshots, logs)
- [ ] **Remediation Recommendations**
  - [ ] Priorização por risco (CVSS)
  - [ ] Quick wins vs long-term fixes
  - [ ] Compensating controls
- [ ] **Risk Assessment**
  - [ ] CVSS scoring (Common Vulnerability Scoring System)
  - [ ] Likelihood vs Impact matrix
  - [ ] Risk appetite alignment
- [ ] **Lessons Learned**
  - [ ] Post-operation debrief
  - [ ] What worked/didn't work
  - [ ] Detection analysis
- [ ] **Metrics & KPIs**
  - [ ] Dwell time (tempo sem detecção)
  - [ ] Detection rate
  - [ ] Initial access time
  - [ ] Privilege escalation time
  - [ ] Objectives achieved
### Frameworks & Compliance Awareness
- [ ] **ISO 27001/27002**
  - [ ] Information security controls
  - [ ] Compliance requirements
- [ ] **NIST Cybersecurity Framework**
  - [ ] Identify, Protect, Detect, Respond, Recover
- [ ] **CIS Controls**
  - [ ] 18 Critical Security Controls
- [ ] **OSSTMM**
  - [ ] Open Source Security Testing Methodology Manual
- [ ] **PCI DSS** (Payment Card Industry)
- [ ] **HIPAA** (Healthcare)
- [ ] **GDPR/LGPD** (Privacy regulations)
### Legal & Ethical Considerations
- [ ] **Rules of Engagement (RoE)**
  - [ ] Scope definition
  - [ ] Authorized targets
  - [ ] Out-of-scope systems
  - [ ] Timing restrictions
  - [ ] Emergency contacts
- [ ] **Scoping Documents**
  - [ ] Statement of Work (SOW)
  - [ ] Master Service Agreement (MSA)
  - [ ] Non-Disclosure Agreement (NDA)
- [ ] **Legal Boundaries**
  - [ ] Computer Fraud and Abuse Act (CFAA - EUA)
  - [ ] Lei Carolina Dieckmann (Brasil)
  - [ ] LGPD implications
  - [ ] International laws
- [ ] **Responsible Disclosure**
  - [ ] Coordinated vulnerability disclosure
  - [ ] Bug bounty ethics
  - [ ] Vendor communication
- [ ] **Chain of Custody** (Forensics)
  - [ ] Evidence handling
  - [ ] Documentation
  - [ ] Legal admissibility
### Prática
- [ ] **HackTheBox Pro Labs**
  - [ ] APTLabs (Advanced Persistent Threat simulation)
  - [ ] Dante (Network pentest)
  - [ ] Zephyr (Red Team)
- [ ] **SANS NetWars** (Tournament style)
- [ ] **Simular operação completa de Red Team**
  - [ ] Reconnaissance
  - [ ] Initial access (phishing)
  - [ ] Establish C2
  - [ ] Lateral movement
  - [ ] Privilege escalation
  - [ ] Data exfiltration
  - [ ] Persistence
  - [ ] Full report
- [ ] **Criar playbook de Red Team Operations**
  - [ ] Standard procedures
  - [ ] Checklist de OPSEC
  - [ ] Communication protocols
  - [ ] Escalation procedures
---
## CERTIFICAÇÕES
### Entry Level
- [ ] **eJPT** (eLearnSecurity Junior Penetration Tester)
  - Custo: ~$200
  - Foco: Fundamentos de pentest
  - Tempo estimado: 1-2 meses de prep
### Fundamental 
- [ ] **PNPT** (Practical Network Penetration Tester - TCM Security)
  - Custo: ~$400
  - Foco: Pentest prático com relatório completo
  - Buffer overflow, AD basics, report writing
  - Tempo estimado: 2-3 meses de prep
- [ ] **OSCP** (Offensive Security Certified Professional)
  - Custo: ~$1600 (90 dias lab + exam)
  - Foco: Try Harder - hands-on exploitation
  - **PRIORITÁRIA PARA RED TEAM**
  - 24h exam (3 máquinas + 1 AD set)
  - Relatório em 24h após exam
  - Tempo estimado: 3-6 meses de prep
### Active Directory Focus 
- [ ] **CRTP** (Certified Red Team Professional - Pentester Academy)
  - Custo: ~$250
  - Foco: Active Directory attacks (básico a intermediário)
  - Kerberoasting, DCSync, Golden Ticket
  - Tempo estimado: 1-2 meses de prep
- [ ] **CRTE** (Certified Red Team Expert)
  - Custo: ~$500
  - Foco: AD avançado, forest trusts, SQL Server links
  - Tempo estimado: 2-3 meses de prep
### Advanced 
- [ ] **CRTO** (Certified Red Team Operator - Zero-Point Security)
  - Custo: ~$600 (com exam)
  - Foco: Red Team operations, C2 (Cobalt Strike), evasion
  - Adversary simulation completa
  - Tempo estimado: 2-3 meses de prep
- [ ] **OSEP** (Offensive Security Experienced Penetration Tester)
  - Custo: ~$1800
  - Foco: Evasion, AV bypass, advanced exploitation
  - Code review, advanced pivoting
  - Tempo estimado: 3-4 meses de prep
### Expert Level
- [ ] **OSWE** (Offensive Security Web Expert)
  - Custo: ~$1800
  - Foco: Advanced web exploitation, code review
  - Whitebox testing
  - Tempo estimado: 3-4 meses de prep
- [ ] **OSED** (Offensive Security Exploit Developer)
  - Custo: ~$1800
  - Foco: Exploit development, assembly, reverse engineering
  - Buffer overflows, ROP, DEP/ASLR bypass
  - Tempo estimado: 4-6 meses de prep
- [ ] **GXPN** (GIAC Exploit Researcher and Advanced Penetration Tester)
  - Custo: ~$2500 (só exam)
  - Foco: Zero-day research, advanced exploitation
  - Tempo estimado: Requer experiência significativa
### Opcionais (Especializações)
- [ ] **BSCP** (Burp Suite Certified Practitioner - PortSwigger)
  - Foco: Web application security
- [ ] **eCPPTv2** (eLearnSecurity Certified Professional Penetration Tester)
- [ ] **GWAPT** (GIAC Web Application Penetration Tester)
- [ ] **CEH** (Certified Ethical Hacker - EC-Council)
  - Nota: Mais teórico, menos hands-on
---
## PLATAFORMAS DE PRÁTICA
### Iniciante 
- [ ] **TryHackMe** - Guided learning paths
  - [ ] Complete Beginner
  - [ ] Jr Penetration Tester
  - [ ] Offensive Pentesting
  - [ ] Red Team Fundamentals
  - Custo: ~$10-15/mês (Premium)
- [ ] **PentesterLab** - Web-focused
  - [ ] Essential badge
  - [ ] Unix badge
  - Custo: ~$20/mês
- [ ] **PicoCTF** - CTF for beginners (gratuito)
- [ ] **OverTheWire** - Linux skills
  - [ ] Bandit (básico)
  - [ ] Natas (web)
  - [ ] Leviathan
  - Gratuito
### Intermediário 
- [ ] **HackTheBox** - Realistic machines
  - [ ] Starting Point (gratuito)
  - [ ] 20+ máquinas Easy
  - [ ] 20+ máquinas Medium
  - [ ] Tracks temáticos
  - Custo: ~$20/mês (VIP) ou gratuito (limited)
- [ ] **VulnHub** - Downloadable VMs (gratuito)
  - [ ] OSCP-like machines
- [ ] **Root-Me** - Challenges diversos
  - Gratuito
- [ ] **PentesterLab Pro** - Advanced tracks
  - Code review, advanced web
### Avançado 
- [ ] **HackTheBox Pro Labs**
  - [ ] RastaLabs (AD focus) - $90
  - [ ] Offshore (Red Team) - $90
  - [ ] APTLabs (Advanced) - $130
  - [ ] Dante (Network) - $40
  - [ ] Zephyr (Red Team) - $90
- [ ] **PentesterAcademy Attack Defense Labs**
  - [ ] Red Team Labs
  - Custo: ~$250/ano
- [ ] **SANS NetWars** - Tournament style
  - Custo: Varia (geralmente em conferências)
- [ ] **Proving Grounds** (OffSec)
  - OSCP-like machines
  - Custo: ~$20/mês
### Competições
- [ ] **CTFtime** - Competitive CTFs
  - Buscar CTFs por skill level
  - Gratuito (maioria)
- [ ] **National Cyber League** (EUA)
- [ ] **DEFCON CTF** (quando chegar no nível)
---
## LINGUAGENS DE PROGRAMAÇÃO
### Essenciais (Prioridade ALTA)
#### Python
- [ ] **Fundamentos**
  - [ ] Sintaxe, estruturas de dados
  - [ ] OOP (Object-Oriented Programming)
- [ ] **Automação**
  - [ ] Scripts de enum, exploit
  - [ ] Web scraping (BeautifulSoup, Scrapy)
- [ ] **Network Programming**
  - [ ] Sockets (TCP/UDP)
  - [ ] Requests HTTP
  - [ ] Scapy (packet manipulation)
- [ ] **Exploit Development**
  - [ ] pwntools
  - [ ] struct module
  - [ ] Shellcode generation
#### Bash
- [ ] **Fundamentos**
  - [ ] Variables, loops, conditionals
  - [ ] Functions
- [ ] **Automação**
  - [ ] Enum scripts
  - [ ] One-liners poderosos
- [ ] **Privilege Escalation Scripts**
  - [ ] Customização de LinPEAS-like tools
- [ ] **Text Processing**
  - [ ] awk, sed, grep mastery
#### PowerShell
- [ ] **Fundamentos**
  - [ ] Cmdlets, pipeline
  - [ ] Objects (tudo é objeto)
- [ ] **Windows Exploitation**
  - [ ] PowerView (AD enum)
  - [ ] Invoke-Expression abuse
- [ ] **AD Enumeration**
  - [ ] Get-ADUser, Get-ADGroup
  - [ ] Custom queries
- [ ] **Empire/Covenant Payloads**
  - [ ] Stagers
  - [ ] Obfuscation
#### C/C++
- [ ] **Exploit Development**
  - [ ] Buffer overflows
  - [ ] Format string vulnerabilities
  - [ ] Heap exploitation
- [ ] **Shellcode Writing**
  - [ ] Assembly basics (x86/x64)
  - [ ] Syscalls
  - [ ] Position-independent code
- [ ] **Memory Management**
  - [ ] Pointers, malloc/free
  - [ ] Stack vs Heap
- [ ] **Low-level Programming**
  - [ ] Direct memory access
  - [ ] Inline assembly
#### C#
- [ ] **Windows Payloads**
  - [ ] .NET assemblies
  - [ ] P/Invoke (Platform Invocation)
- [ ] **AV/EDR Bypass**
  - [ ] Reflection
  - [ ] In-memory execution
  - [ ] Assembly loading
- [ ] **.NET Exploitation**
  - [ ] Deserialization
  - [ ] ViewState exploitation
- [ ] **Tools Development**
  - [ ] Rubeus, Seatbelt (estudo de código)
#### Go
- [ ] **Malware Development** (educacional)
  - [ ] Cross-platform compilation
  - [ ] Small binary size
  - [ ] Concurrency
- [ ] **Network Tools**
  - [ ] Port scanners
  - [ ] Custom proxies
- [ ] **Windows API em Go**
  - [ ] syscall package
  - [ ] golang.org/x/sys/windows
### Complementares
#### JavaScript
- [ ] **XSS Payloads**
  - [ ] DOM manipulation
  - [ ] Cookie stealing
  - [ ] Keyloggers
- [ ] **Web Exploitation**
  - [ ] Prototype pollution
  - [ ] Node.js security
- [ ] **Browser Exploitation**
  - [ ] BeEF (Browser Exploitation Framework)
#### Ruby
- [ ] **Metasploit Development**
  - [ ] Custom modules
  - [ ] Exploit adaptation
#### Assembly (x86/x64)
- [ ] **Reverse Engineering**
  - [ ] Reading assembly code
  - [ ] GDB, WinDbg
- [ ] **Exploit Development**
  - [ ] ROP (Return-Oriented Programming)
  - [ ] Shellcode optimization
- [ ] **Debugging**
  - [ ] Breakpoints, stepping
---
## RECURSOS DE ESTUDO
### Livros Fundamentais
#### Red Team & Pentesting
- [ ] **The Hacker Playbook 2 & 3** - Peter Kim
- [ ] **RTFM: Red Team Field Manual** - Ben Clark
- [ ] **Red Team Development and Operations** - Joe Vest & James Tubberville
- [ ] **Penetration Testing** - Georgia Weidman
- [ ] **The Web Application Hacker's Handbook** - Dafydd Stuttard & Marcus Pinto
- [ ] **Operator Handbook** - Red Team + OSINT
#### Active Directory
- [ ] **Active Directory Security** (blog) - Sean Metcalf (adsecurity.org)
- [ ] **Attacking Network Protocols** - James Forshaw
#### Exploit Development
- [ ] **The Shellcoder's Handbook** - Jack Koziol et al.
- [ ] **Hacking: The Art of Exploitation** - Jon Erickson
- [ ] **Gray Hat Hacking** - Allen Harper et al.
#### Wireless & Hardware
- [ ] **The Hardware Hacker** - Bunnie Huang
- [ ] **Practical IoT Hacking** - Fotios Chantzis et al.
#### Mobile
- [ ] **Android Hacker's Handbook** - Joshua J. Drake et al.
- [ ] **iOS Hacker's Handbook** - Charlie Miller et al.
#### Social Engineering
- [ ] **The Art of Deception** - Kevin Mitnick
- [ ] **Social Engineering: The Science of Human Hacking** - Christopher Hadnagy
---
## FERRAMENTAS ESSENCIAIS POR CATEGORIA
### Reconhecimento
- [ ] nmap, masscan, rustscan
- [ ] theHarvester, recon-ng
- [ ] Amass, Subfinder, Assetfinder
- [ ] Shodan, Censys
- [ ] Maltego
- [ ] SpiderFoot
- [ ] FOCA (metadata analysis)
### Web Application
- [ ] Burp Suite Professional (essencial investir)
- [ ] OWASP ZAP
- [ ] sqlmap
- [ ] Nikto, WPScan
- [ ] Gobuster, FFuF, Feroxbuster
- [ ] Wfuzz
- [ ] Commix (command injection)
- [ ] XSStrike
### Exploitation
- [ ] Metasploit Framework
- [ ] Impacket suite
- [ ] CrackMapExec / NetExec
- [ ] Searchsploit (Exploit-DB local)
- [ ] msfvenom (payload generation)
### Post-Exploitation
- [ ] Mimikatz / Pypykatz
- [ ] BloodHound
- [ ] Rubeus
- [ ] LinPEAS / WinPEAS
- [ ] PowerView, SharpHound
- [ ] LaZagne (credentials)
- [ ] SharpUp, Seatbelt
- [ ] pspy (Linux process monitor)
### Password Attacks
- [ ] Hashcat (GPU-based)
- [ ] John the Ripper
- [ ] Hydra, Medusa
- [ ] CeWL (wordlist generator)
- [ ] Patator
- [ ] Responder (LLMNR/NBT-NS)
### C2 Frameworks
- [ ] Cobalt Strike (comercial - ~$3500/ano)
- [ ] Mythic (open-source)
- [ ] Sliver (open-source)
- [ ] Havoc (open-source)
- [ ] Covenant (open-source)
- [ ] Empire/Starkiller (open-source)
### Network
- [ ] Wireshark
- [ ] tcpdump
- [ ] Responder
- [ ] Bettercap (MITM)
- [ ] Ettercap
- [ ] arpspoof
### Wireless
- [ ] aircrack-ng suite
- [ ] wifite
- [ ] kismet
- [ ] hostapd-wpe
- [ ] WiFi Pineapup (hardware)
### Social Engineering
- [ ] Gophish
- [ ] SET (Social Engineer Toolkit)
- [ ] evilginx2
- [ ] King Phisher
### Evasion
- [ ] Veil Framework
- [ ] Invoke-Obfuscation
- [ ] Shellter (AV evasion)
- [ ] Unicorn (Metasploit evasion)
### Cloud
- [ ] Pacu (AWS)
- [ ] ScoutSuite (multi-cloud)
- [ ] Prowler (AWS CIS)
- [ ] AzureHound (Azure AD)
- [ ] ROADtools (Azure)
### Mobile
- [ ] Frida
- [ ] Objection
- [ ] MobSF
- [ ] apktool, jadx
- [ ] Drozer (Android)
### Forensics/Analysis
- [ ] Volatility (memory forensics)
- [ ] Autopsy
- [ ] Binwalk (firmware)
- [ ] strings, hexdump, xxd
- [ ] Ghidra, IDA Free (reverse engineering)
---
## TIMELINE REALISTA

**Total**: 24 meses (2 anos) de estudo intensivo

| Fase | Período | Duração | Foco Principal |
|------|---------|---------|----------------|
| Fase 1 | Mês 1-3 | 3 meses | Fundamentos (Linux, redes, ferramentas, IT basics) |
| Fase 2 | Mês 3-5 | 2 meses | Reconhecimento e OSINT |
| Fase 2.5 | Mês 5-6 | 1 mês | Wireless & Physical Security |
| Fase 3 | Mês 6-9 | 3 meses | Exploração (web, network, passwords) |
| Fase 4 | Mês 9-12 | 3 meses | Post-exploitation e privilege escalation |
| Fase 5 | Mês 12-16 | 4 meses | Active Directory (mais tempo/complexo) |
| Fase 6 | Mês 16-19 | 3 meses | Evasão e custom tooling |
| Fase 7 | Mês 19-21 | 2 meses | Cloud & containers |
| Fase 8 | Mês 21-23 | 2 meses | Mobile & IoT |
| Fase 9 | Mês 23-24 | 1 mês | Red Team operations completas |
---
## MÉTRICAS DE PROGRESSO
### Metas Mensais
- [ ] Máquinas resolvidas: Mínimo 4-6 por mês (Easy/Medium)
- [ ] Writeups escritos: 2-4 por mês
- [ ] Ferramentas novas: 2-3 por mês (domínio prático)
- [ ] Conceitos revisados: Semanalmente
- [ ] Tempo de estudo: 60-80h/mês
### Metas Trimestrais
- [ ] Certificação ou curso completo: 1 por trimestre (se viável)
- [ ] Projeto prático: Lab próprio, ferramenta custom, CTF team
- [ ] Revisão geral: Cheat sheets atualizados
- [ ] Networking: Participar de comunidade/evento
### Metas Anuais
- [ ] **Ano 1**: OSCP + CRTP + 50+ máquinas HTB + lab AD funcional
- [ ] **Ano 2**: CRTO/OSEP + Pro Lab completo + Operação Red Team simulada + portfolio robusto
---
## DOCUMENTAÇÃO E NOTAS
### Estrutura de Writeups
```markdown
# [Nome da Máquina/Challenge]
## Information Gathering
- **IP**: 10.10.10.X
- **Difficulty**: Easy/Medium/Hard
- **OS**: Linux/Windows
- **Points**: X
## Enumeration
### Nmap Scan
```bash
[comandos e resultados]
```
### Service Enumeration
[enumeração detalhada de cada serviço]
## Exploitation
### Initial Foothold
[como conseguiu acesso inicial - exploit usado, vulnerability, etc]
### User Flag
[caminho até user.txt]
## Privilege Escalation
[técnica usada - SUID, sudo, kernel, etc]
### Root Flag
[caminho até root.txt]
## Lessons Learned
- Técnicas aprendidas
- Ferramentas novas
- Conceitos importantes
- Erros cometidos
## References
- [links úteis]
- [CVE numbers se aplicável]
```
### Cheat Sheets Pessoais
Criar e manter atualizados:
- [ ] **Comandos Linux** (enumeration, privesc)
- [ ] **Comandos Windows** (enumeration, privesc)
- [ ] **Reverse shells** (todas as linguagens)
- [ ] **SQL Injection payloads** (union, blind, time-based)
- [ ] **XSS payloads** (bypass filters)
- [ ] **Active Directory attacks** (kerberoasting, DCSync, etc)
- [ ] **Port scanning** (nmap flags e scripts)
- [ ] **File transfers** (Linux to Windows, Windows to Linux)
- [ ] **Password cracking** (hashcat modes)
### Template Semanal de Progresso
```markdown
## Semana [número] - [data início] a [data fim]
### Objetivos da Semana
- [ ] Objetivo 1
- [ ] Objetivo 2
- [ ] Objetivo 3
### Máquinas/Desafios Resolvidos
- [ ] [Nome] - [Dificuldade] - [Técnicas: X, Y, Z]
- [ ] [Nome] - [Dificuldade] - [Técnicas: A, B, C]

### Conceitos Estudados
- **Conceito 1**: [resumo breve]
- **Conceito 2**: [resumo breve]

### Ferramentas Aprendidas
- **Ferramenta**: [uso prático, sintaxe básica]

### Dificuldades Encontradas
- **Problema**: [como resolvi ou preciso revisar]

### Próxima Semana
- [ ] Continuar [tema]
- [ ] Iniciar [novo tema]

### Tempo Total: Xh
### Notas Adicionais
[observações, links úteis, ideias para projetos]
```

### Planilha de Máquinas

| # | Máquina | Plataforma | Dificuldade | Data | Técnicas Principais | Writeup |
|---|---------|------------|-------------|------|---------------------|---------|
| 1 | Lame | HTB | Easy | 01/01 | SMB, distcc | ✅ |
| 2 | Legacy | HTB | Easy | 03/01 | MS08-067 | ✅ |
| ... | ... | ... | ... | ... | ... | ... |

---

## LABORATÓRIO PRÓPRIO

### Setup Básico (VirtualBox/VMware)

**Máquinas Essenciais**:
- [ ] **Kali Linux** (attacker machine) - 4GB RAM, 60GB disk
- [ ] **Parrot OS** (alternative attacker) - opcional
- [ ] **Metasploitable 2/3** (vulnerable targets)
- [ ] **DVWA** (Damn Vulnerable Web Application)
- [ ] **VulnHub VMs** (múltiplos cenários)
- [ ] **Windows 10/11** (target for Windows attacks)

### Active Directory Lab (CRÍTICO)

**Estrutura Mínima**:
- [ ] **1x Windows Server 2019/2022** (Domain Controller)
  - 4GB RAM mínimo, 60GB disk
  - Configurar AD DS, DNS
- [ ] **2x Windows 10/11** (workstations)
  - 2GB RAM cada, 40GB disk cada
  - Domain-joined
- [ ] **1x Kali Linux** (attacker)
  - Same network

**Configurações**:
- [ ] Criar domain (ex: lab.local)
- [ ] Usuários realistas (10-15 users)
- [ ] Grupos (IT, HR, Finance, Admins)
- [ ] OUs (Organizational Units)
- [ ] GPOs básicas
- [ ] Service accounts com SPNs (para Kerberoasting)
- [ ] Usuários sem pre-auth (para AS-REP Roasting)
- [ ] Trust relationships (se 2 domains)

**Vulnerabilidades Intencionais**:
- [ ] Weak passwords
- [ ] AlwaysInstallElevated enabled
- [ ] Unquoted service paths
- [ ] Writable shares
- [ ] LLMNR/NBT-NS enabled
- [ ] SMB signing disabled

**Recursos para AD Lab**:
- [ ] **GOAD** (Game of Active Directory) - github.com/Orange-Cyberdefense/GOAD
- [ ] **DetectionLab** - github.com/clong/DetectionLab
- [ ] **BadBlood** - github.com/davidprowe/BadBlood (populate AD)

### Hardware Recomendado

**Mínimo**:
- **CPU**: 4 cores
- **RAM**: 16GB (8GB para host, 8GB para VMs)
- **Storage**: 250GB SSD

**Ideal**:
- **CPU**: 6-8 cores
- **RAM**: 32GB (permite múltiplas VMs simultâneas)
- **Storage**: 500GB+ SSD (NVMe melhor performance)
- **GPU**: Opcional, mas útil para hashcat

**Network**:
- Interface dupla para isolamento (host-only + NAT)
- Switch virtual para labs complexos

---

## CONQUISTAS E MILESTONES

### Mês 3
- [ ] 10 máquinas Easy HTB resolvidas
- [ ] TryHackMe: Complete Beginner Path concluído
- [ ] Primeiro writeup publicado no GitHub
- [ ] Lab Linux básico montado (Kali + Metasploitable)
- [ ] 5 scripts de automação funcionais

### Mês 6
- [ ] 20 máquinas Easy + 5 Medium HTB
- [ ] TryHackMe: Jr Penetration Tester concluído
- [ ] **eJPT conquistado**
- [ ] 10 writeups publicados
- [ ] Lab Windows basic montado

### Mês 9
- [ ] 30 máquinas Easy + 15 Medium HTB
- [ ] PortSwigger Academy: 50% concluído
- [ ] Primeiro exploit próprio desenvolvido
- [ ] 15 writeups publicados
- [ ] Participação em 3 CTFs

### Mês 12 (1 Ano)
- [ ] **OSCP CONQUISTADO** 🎯
- [ ] 40 máquinas Easy + 25 Medium + 5 Hard HTB
- [ ] **CRTP conquistado**
- [ ] 20+ writeups publicados
- [ ] Lab Active Directory montado e funcional
- [ ] Script de automação robusto desenvolvido

### Mês 15
- [ ] HTB Pro Lab iniciado (RastaLabs ou Offshore)
- [ ] 50 máquinas Easy + 35 Medium + 10 Hard
- [ ] Active Directory: domínio completo de técnicas
- [ ] Primeiro payload customizado com evasão de AV

### Mês 18
- [ ] HTB Pro Lab concluído
- [ ] **CRTE conquistado**
- [ ] 60+ máquinas Medium/Hard
- [ ] Ferramenta própria publicada no GitHub
- [ ] 30+ writeups

### Mês 21
- [ ] **OSEP ou CRTO em andamento**
- [ ] 70+ máquinas variadas
- [ ] Mini C2 framework desenvolvido (educacional)
- [ ] Colaboração em ferramenta open-source
- [ ] Blog técnico com 10+ artigos

### Mês 24 (2 Anos)
- [ ] **OSEP ou CRTO CONQUISTADO** 🎯
- [ ] 100+ máquinas HTB resolvidas
- [ ] Operação Red Team completa simulada
- [ ] Portfolio robusto com 40+ writeups
- [ ] Ferramenta própria com 50+ stars no GitHub
- [ ] **Pronto para mercado de trabalho como Red Teamer**

---

## PREPARAÇÃO PARA O MERCADO

### Portfolio Development

#### GitHub Bem Organizado
- [ ] **README profissional**
  - Sobre mim, skills, certificações
  - Links para projetos destacados
- [ ] **Writeups em markdown**
  - Organizados por plataforma/dificuldade
  - Screenshots e explicações claras
- [ ] **Ferramentas desenvolvidas**
  - Código limpo e documentado
  - README com usage examples
- [ ] **Contribuições open-source**
  - PRs em projetos conhecidos
  - Issues reportadas

#### Blog Técnico
- [ ] **Medium, Dev.to ou próprio**
- [ ] **Artigos técnicos**
  - Walkthroughs detalhados
  - Técnicas específicas deep dive
- [ ] **Tutoriais**
  - Setup de labs
  - Ferramenta X vs Y
- [ ] **Análises de vulnerabilidades**
  - CVE breakdowns
  - Case studies

#### LinkedIn Otimizado
- [ ] **Headline clara** (ex: "Aspiring Red Team Operator | OSCP | Active Directory Specialist")
- [ ] **About section** detalhada mas concisa
- [ ] **Certificações** listadas
- [ ] **Projetos** destacados
- [ ] **Recomendações** de mentores/colegas
- [ ] **Posts regulares** sobre aprendizados

### Networking

- [ ] **Conferências**
  - BSides (local/online)
  - DEFCON (quando viável)
  - Black Hat (quando viável)
  - H2HC (Brasil)
- [ ] **Comunidades online**
  - Discord (HTB, THM, InfoSec servers)
  - Reddit (r/netsec, r/AskNetsec, r/oscp)
  - Twitter/X (InfoSec community)
- [ ] **Conectar com profissionais**
  - LinkedIn networking
  - Mentoria (buscar e oferecer)
- [ ] **CTFs em equipe**
  - Formar/juntar-se a team
  - Competições regulares

### Soft Skills

#### Communication
- [ ] **Report writing**
  - Praticar com cada máquina
  - Feedback de peers
- [ ] **Apresentações técnicas**
  - Local meetups
  - Lightning talks
- [ ] **Documentação clara**
  - READMEs, comments
  - Technical writing

#### Teamwork
- [ ] **Colaboração em CTFs**
  - Divisão de tarefas
  - Comunicação efetiva
- [ ] **Code reviews**
  - Dar e receber feedback
- [ ] **Knowledge sharing**
  - Ensinar o que aprende
  - Mentoria reversa

#### Problem Solving
- [ ] **Pensamento crítico**
  - Enumeration methodology
  - Try Harder mentality
- [ ] **Metodologia estruturada**
  - Documentar process
  - Repeatable approach
- [ ] **Persistência**
  - Não desistir em máquinas Hard
  - Aprender com failures

---

## AVISOS IMPORTANTES

### Ética e Legalidade

**NUNCA:**
- Atacar sistemas sem autorização explícita por escrito
- Usar conhecimentos para fins maliciosos ou ilegais
- Compartilhar exploits 0-day sem responsible disclosure
- Violar leis de privacidade (LGPD/GDPR)
- Exceder escopo de autorizações
- Acessar dados sensíveis desnecessariamente

**SEMPRE:**
- Seguir responsible disclosure
- Trabalhar apenas em ambientes autorizados
- Respeitar ToS das plataformas (HTB, THM, etc)
- Manter ética profissional
- Obter permissão por escrito (RoE)
- Documentar todas as ações

### Saúde Mental e Burnout

- [ ] **Fazer pausas regulares**
  - Técnica Pomodoro (25min work, 5min break)
  - Pausas de tela a cada hora
- [ ] **Não comparar seu progresso com outros**
  - Cada pessoa tem seu ritmo
  - Foco no seu progresso pessoal
- [ ] **Celebrar pequenas vitórias**
  - Cada máquina resolvida é progresso
  - Cada conceito entendido importa
- [ ] **Pedir ajuda quando travado**
  - Forums, Discord, comunidades
  - Não há vergonha em pedir hints
- [ ] **Manter equilíbrio vida/estudo**
  - Exercício físico
  - Tempo com amigos/família
  - Hobbies não relacionados
- [ ] **Sleep > grinding**
  - Sono adequado melhora aprendizado
  - Brain needs rest to consolidate

**Sinais de Burnout**:
- Exaustão constante
- Perda de motivação
- Irritabilidade
- Dificuldade de concentração
- Evitar estudos

**Se identificar sinais**: PARE, descanse, reavalie metas.

### Síndrome do Impostor

Red Team é um campo VASTO. Ninguém sabe tudo. Profissionais experientes ainda aprendem diariamente.

**É normal se sentir**:
- Perdido em conceitos novos
- Insuficiente comparado a outros
- Intimidado por máquinas Hard/Insane
- Frustrado ao travar

**Lembre-se**:
- Todos começaram do zero
- IppSec também travava em máquinas Easy
- OSCP reprova 50-60% na primeira tentativa
- Progresso > Perfeição

---

## ROTINA DE ESTUDOS SUGERIDA

### Segunda a Sexta (2-3h/dia)

**Noite (19h-22h):**
- **19:00-19:15** - Revisão do aprendido ontem (flashcards, notas)
- **19:15-20:15** - Teoria (vídeos, leitura, cursos)
- **20:15-21:45** - Prática (máquinas, labs, challenges)
- **21:45-22:00** - Documentação (notas, writeup parcial, atualizar repo)

### Sábado (4-6h)

**Manhã/Tarde:**
- **09:00-09:30** - Planejamento da semana
- **09:30-12:30** - Máquina HTB/THM (foco total, sem distrações)
- **12:30-14:00** - Almoço e descanso
- **14:00-17:00** - Continuação ou nova máquina/desafio
- **17:00-17:30** - Revisão do dia

### Domingo (4-6h)

**Tarde:**
- **14:00-16:00** - Writeup da máquina da semana
- **16:00-17:30** - Estudo de ferramenta nova ou conceito profundo
- **17:30-18:30** - Revisão semanal e planejamento da próxima

### Flexibilidade

Este é um modelo. Adapte conforme sua rotina (trabalho, faculdade, família).

**Princípios chave**:
- Consistência > Quantidade
- Qualidade > Velocidade
- Prática > Teoria (70/30)
- Documentação é parte do aprendizado

---

# RED TEAM ROADMAP COMPLETO - DO INICIANTE AO AVANÇADO (CONTINUAÇÃO)

## RECURSOS COMPLEMENTARES (CONTINUAÇÃO)

### Comunidades e Fóruns

- [ ] **Discord Servers**
  - HackTheBox Official
  - TryHackMe Official
  - InfoSec Prep (OSCP focused)
  - NetSecFocus
  - The Cyber Mentor

- [ ] **Reddit**
  - r/netsec (notícias e discussões)
  - r/AskNetsec (perguntas)
  - r/oscp (OSCP specific)
  - r/HowToHack (iniciantes)
  - r/redteamsec

- [ ] **Forums**
  - HackTheBox Forums
  - Offensive Security Forums
  - Exploit-DB Forums

### GitHub Repos Essenciais

- [ ] **Awesome Lists**
  - Awesome Hacking
  - Awesome Pentest
  - Awesome Red Teaming
  - Awesome Windows Exploitation

- [ ] **Cheat Sheets**
  - PayloadsAllTheThings
  - HackTricks
  - RTFM
  - PentestMonkey Cheat Sheets

- [ ] **Tools Collections**
  - Red Team Infrastructure Wiki
  - C2 Matrix
  - GTFOBins
  - LOLBAS Project

---

## CURSOS RECOMENDADOS (ALÉM DAS CERTIFICAÇÕES)

### Gratuitos

- [ ] **Cybrary**
  - Introduction to IT & Cybersecurity
  - CompTIA courses (parcialmente gratuito)

- [ ] **YouTube Playlists**
  - The Cyber Mentor - Practical Ethical Hacking
  - John Hammond - Malware Analysis
  - IppSec - HTB Walkthroughs (TODOS)

- [ ] **PortSwigger Web Security Academy**
  - Todos os labs (ESSENCIAL)
  - Grátis e de altíssima qualidade

### Pagos (Por Ordem de Prioridade)

1. **TCM Security Academy** (~$30/mês)
   - Practical Ethical Hacking
   - Windows/Linux Privilege Escalation
   - OSINT Fundamentals

2. **PentesterAcademy** (~$49/mês ou $250/ano)
   - Attacking and Defending Active Directory
   - Red Team Labs
   - Vários cursos especializados

3. **Sektor7 Institute**
   - Malware Development Essentials (~$200)
   - RTO: Malware Development Intermediate (~$400)

4. **Zero-Point Security** (CRTO)
   - Red Team Ops (~$600 com exam)
  
---

### Caminhos de Especialização

#### Web Application Security
- [ ] OSWE (Offensive Security Web Expert)
- [ ] BSCP (Burp Suite Certified Practitioner)
- [ ] Bug bounty programs (HackerOne, Bugcrowd)
- [ ] OWASP leadership/contribution

#### Mobile Security
- [ ] OWASP Mobile Top 10 mastery
- [ ] iOS/Android pentesting expertise
- [ ] Mobile app bug bounty

#### Cloud Security
- [ ] AWS/Azure/GCP pentesting specialization
- [ ] Cloud security certifications (AWS Security Specialty)
- [ ] Kubernetes security expertise

#### ICS/SCADA
- [ ] GICSP (GIAC Critical Infrastructure Protection)
- [ ] Industrial protocols expertise
- [ ] OT security specialization

#### Wireless Security
- [ ] Advanced WiFi attacks
- [ ] IoT security
- [ ] Bluetooth/NFC/RFID

---

## SUBSCRIPTIONS ÚTEIS (OPCIONAL)

### Essenciais

- [ ] **HackTheBox VIP** (~$20/mês)
  - Máquinas retired
  - Pro Labs (adicional)
  
- [ ] **TryHackMe Premium** (~$10/mês)
  - Paths completos
  - Offensive Pentesting path

### Recomendados

- [ ] **PentesterLab Pro** (~$20/mês)
  - Web exploitation focus
  
- [ ] **INE/eLearnSecurity** (~$40/mês)
  - Múltiplos cursos
  - Labs diversos

### Premium (Quando Empregado)

- [ ] **Burp Suite Professional** (~$400/ano)
  - Ferramenta essencial para web
  
- [ ] **Cobalt Strike** (~$3500/ano)
  - C2 profissional (empresa geralmente paga)

---

## CONTRIBUIÇÃO OPEN SOURCE

### Projetos para Contribuir

- [ ] **Impacket** (Python) - Network protocols
- [ ] **BloodHound** (JavaScript/C#) - AD visualization
- [ ] **Metasploit Framework** (Ruby) - Exploitation
- [ ] **Nuclei Templates** (YAML) - Vulnerability scanning
- [ ] **SecLists** (Wordlists) - Password lists
- [ ] **HackTricks** (Documentation) - Knowledge base

### Criar Projetos Próprios

- [ ] **Ferramenta de enumeração** (Python/Go)
- [ ] **Script de automação** (Bash/PowerShell)
- [ ] **Payload generator** (qualquer linguagem)
- [ ] **CTF challenges** (para comunidade)
- [ ] **Writeup template** (Markdown)
- [ ] **Vulnerable application** (para treino de outros)

---

## MANTRAS DO RED TEAMER

**"Try Harder"** - Persistência é chave (OSCP motto)

**"Enumeration is key"** - 80% do pentest é enumeração

**"Document everything"** - Você vai esquecer detalhes

**"Assume breach"** - Sempre pense como attacker

**"There's always a way"** - Criatividade vence

**"RTFM"** - Read The Manual (sempre)

**"Practice makes perfect"** - Repetição constrói expertise

**"Stay ethical"** - Hacking sem ética não é hacking

**"Never stop learning"** - Campo muda constantemente

---

## CHECKLIST FINAL - "ESTOU PRONTO PARA RED TEAM?"

Antes de se considerar pronto para posições Red Team profissionais:

### Técnico
- [ ] Resolver 50+ máquinas HTB (variadas dificuldades)
- [ ] Ter OSCP ou equivalente
- [ ] Ter certificação de AD (CRTP/CRTE)
- [ ] Dominar pelo menos 2 linguagens (Python + PowerShell/Bash)
- [ ] Conhecer 3+ C2 frameworks
- [ ] Ter completado pelo menos 1 Pro Lab
- [ ] Desenvolver 1+ ferramenta própria funcional
- [ ] Entender MITRE ATT&CK profundamente

### Documentação
- [ ] Escrever 20+ writeups técnicos detalhados
- [ ] Portfolio GitHub organizado e profissional
- [ ] Demonstrar metodologia estruturada

### Prático
- [ ] Ter experiência com evasão de AV/EDR
- [ ] Simular operação Red Team completa ponta a ponta
- [ ] Lab AD próprio funcional
- [ ] Participar de CTFs competitivos (top 30% em pelo menos 3)

### Soft Skills
- [ ] Conseguir explicar conceitos técnicos para não-técnicos
- [ ] Escrever relatórios executivos e técnicos
- [ ] Conhecer frameworks de compliance (ISO, NIST)
- [ ] Entender aspectos legais e éticos

### Networking
- [ ] LinkedIn profissional ativo
- [ ] Conexões na comunidade InfoSec
- [ ] Contribuições open-source
- [ ] Presença em comunidades (Discord, Reddit)

**Se marcou 15+**, você está no caminho certo para posições Junior/Mid-level Red Team.

---

## MOTIVAÇÃO FINAL

### Lembre-se Sempre

Todo expert foi iniciante um dia. IppSec também travava em máquinas Easy. OSCP é difícil, mas possível com dedicação. A comunidade existe para ajudar. Progresso importa mais que perfeição.

### Quando Sentir Vontade de Desistir

- Releia seus writeups antigos - veja o quanto evoluiu
- Fale com a comunidade - você não está sozinho
- Faça uma pausa - rest é parte do processo
- Celebre pequenas vitórias - cada máquina conta
- Lembre por que começou - sua motivação inicial

---

## AGRADECIMENTOS E RECURSOS USADOS

Este roadmap foi construído com base em:
- Experiências compartilhadas pela comunidade InfoSec
- Syllabi de certificações (OSCP, CRTP, CRTO, OSEP)
- Roadmaps públicos (roadmap.sh)
- Feedback de profissionais atuantes
- Trilhas de plataformas (HTB, THM)

**Créditos especiais**:
- Offensive Security (metodologia "Try Harder")
- HackTheBox & TryHackMe (plataformas de prática)
- IppSec (educação gratuita de qualidade)
- Comunidade InfoSec brasileira e internacional

---

## DISCLAIMER LEGAL

Este roadmap é para fins **exclusivamente educacionais**. 

Todo o conhecimento aqui deve ser aplicado apenas em:
- Ambientes próprios
- Plataformas autorizadas (HTB, THM, etc)
- Engajamentos profissionais com autorização por escrito

**O autor não se responsabiliza pelo uso indevido deste conteúdo.**

Sempre obtenha autorização explícita antes de testar qualquer sistema. O uso não autorizado é crime em praticamente todas as jurisdições.

---

**FIM DO ROADMAP COMPLETO**

**Total de Páginas em Markdown**: ~100+ páginas  
**Checklist Items**: 800+ itens  
**Tempo Estimado**: 24 meses dedicados  
**Nível Final**: Red Team Operator pronto para mercado

---

**Este é um guia, não uma prisão.** 

**"The quieter you become, the more you can hear."** - Hacker Koan
