# kalilinux-red
A custom kali linux docker image with some importent pre-installed CLI tools.

Welcome to my custom Kali Linux image! This image is specifically designed for security researchers looking to conduct offensive security testing. Here are some important details and benefits that you need to know before using this image:

**Pre-Installed Tools** This image includes several pre-installed CLI tools for offensive security testing, such as vulnerability scanners, penetration testing tools, network analysis tools, and more. These tools have been carefully selected and configured to provide a comprehensive toolkit for security researchers.

**Efficient Testing** With this image, you can get started with offensive security testing right away. The pre-installed tools and configurations make it easy to quickly launch a testing environment and get straight to work, without having to spend time setting up and configuring each tool individually.

**Consistency and Reliability** By using this custom Kali Linux image, you can ensure that you're using the same set of tools and configurations every time you conduct a test. This consistency is important for producing reliable and repeatable results, and helps to ensure that you don't miss any potential vulnerabilities or security flaws.

**Isolation** Offensive security testing can be risky, as it involves probing and exploiting vulnerabilities in systems and networks. By running this custom Kali Linux image in a container, you can isolate your testing environment from the rest of your system, reducing the risk of unintended damage.

**Collaboration** This custom Kali Linux image is easily portable, meaning that you can share it with others and collaborate on security research projects. This can help you to learn from others and improve your skills as a security researcher.

**Getting Started** To get started with this custom Kali Linux image, you'll need to have Docker installed on your system. Once you have Docker set up, you can simply pull the image from Docker Hub and run it in a container. From there, you can start using the pre-installed tools and configurations to conduct offensive security testing.

```
docker pull ilyasousbaa/kalilinux-red
```

#### starting the container

```
docker run --tty --interactive --name kalilinux --hostname kalilinux ilyasousbaa/kalilinux-red
```

## Apt tools

`sqlmap`:  Automatic SQL injection tool

`amass`:  In-depth DNS Enumeration and Network Mapping

`axel`:  Light command line download accelerator

`cewl`:  Custom word list generator

`commix`:  Automated All-in-One OS Command Injection and Exploitation Tool

`crackmapexec`:  Swiss army knife for pentesting networks

`creddump7`:  Python tool to extract credentials and secrets from Windows registry hives

`crunch`:  Tool for creating wordlist

`dirb`:  URL bruteforcing tool

`dns2tcp`:  TCP-over-DNS tunnel server and client

`dnschef`:  DNS proxy for penetration testers

`dnsrecon`:  Powerful DNS enumeration script

`dos2unix`:  Convert text file line endings between CRLF and LF

`enum4linux`:  Enumerates info from Windows and Samba systems

`ethtool`:  Display or change Ethernet device settings

`exe2hexbat`:  Convert EXE to bat

`libimage-exiftool-perl`:  Library and program to read and write meta information in multimedia files

`exploitdb`:  Searchable Exploit Database archive

`ffuf`:  Fast web fuzzer written in Go (program)

`fierce`:  Domain DNS scanner

`gpp-decrypt`:  Group Policy Preferences decrypter

`hash-identifier`:  Tool to identify hash types

`hashcat-utils`:  Set of small utilities for advanced password cracking

`hydra`:  very fast network logon cracker

`impacket-scripts`:  Links to useful impacket scripts examples

`inetsim`:  Software suite for simulating common internet services

`iptables`:  Administration tools for packet filtering and NAT

`john`:  Active password cracking tool

`lbd`:  Load balancer detector

`macchanger`:  Utility for manipulating the MAC address of network interfaces

`magicrescue`:  Recover files by looking for magic bytes

`maskprocessor`:  High-performance word generator with a per-position configurable charset

`masscan`:  TCP port scanner

`medusa`:  Fast, parallel, modular, login brute-forcer for network services

`metasploit-framework`:  Framework for exploit development and vulnerability research

`nmap`:  Vulnerabilites scaner

`miredo`:  Teredo IPv6 tunneling through NATs

`mitmproxy`:  SSL-capable man-in-the-middle HTTP proxy

`msfpc`:  MSFvenom Payload Creator (MSFPC)

`nano`:  Small, friendly text editor inspired by Pico

`nasm`:  General-purpose x86 assembler

`nbtscan`:  Scan networks searching for NetBIOS information

`ncrack`:  High-speed network authentication cracking tool

`ncurses`: Hexedit:  Edit files/disks in hex, ASCII and EBCDIC

`netmask`:  Helps determine network masks

`netsed`:  Network packet-altering stream editor

`netsniff-ng`:  Linux network packet sniffer toolkit

`nikto`:  Web server security scanner

`nuclei`:  Fast and customizable vulnerability scanner based on simple YAML based DSL

`onesixtyone`:  Fast and simple SNMP scanner

`openvpn`:  virtual private network daemon

`ophcrack-cli`:  Microsoft Windows password cracker using rainbow tables (cmdline)

`passing-the-hash`:  Patched tools to use password hashes as authentication input

`pipal`:  Statistical analysis on password dumps

`powersploit`:  PowerShell Post-Exploitation Framework

`proxychains`:  proxy chains - redirect connections through proxy servers

`proxytunnel`:  Help SSH and other protocols through HTTP(S) proxies

`ptunnel`:  Tunnel TCP connections over ICMP packets

`pwnat`:  NAT to NAT client-server communication

`python3-impacket`:  Python3 module to easily build and dissect network protocols

`recon-ng`:  Web Reconnaissance framework written in Python

`responder`:  LLMNR/NBT-NS/mDNS Poisoner

`rinetd`:  Internet TCP/UDP redirection server

`rsmangler`:  Wordlist mangling tool

`samdump2`:  Dump Windows 2k/NT/XP password hashes

`sbd`:  Secure backdoor for linux and windows

`scalpel`:  Fast filesystem-independent file recovery

`smbmap`:  Handy SMB enumeration tool

`snmpcheck`:  SNMP service enumeration tool

`socat`:  Multipurpose relay for bidirectional data transfer

`spiderfoot`:  OSINT collection and reconnaissance tool

`spike`:  Network protocol fuzzer

`ssldump`:  SSLv3/TLS network protocol analyzer

`sslscan`:  Fast SSL scanner

`sslsplit`:  Transparent and scalable SSL/TLS interception

`sslstrip`:  SSL/TLS man-in-the-middle attack tool

`sslyze`:  Fast and full-featured SSL scanner

`stunnel4`:  Universal SSL tunnel for network daemons

`swaks`:  SMTP command-line test tool

`tcpdump`:  Command-line network traffic analyzer

`tcpick`:  TCP stream sniffer and connection tracker

`tcpreplay`:  Tool to replay saved tcpdump files at arbitrary speeds

`thc-ipv6`:  The Hacker Choice's IPv6 Attack Toolkit

`thc-pptp-bruter`:  THC PPTP Brute Force

`theharvester`:  Tool for gathering e-mail accounts and subdomain names from public sources

`udptunnel`:  Tunnel UDP packets over a TCP connection

`upx-ucl`:  Efficient live-compressor for executables

`wafw00f`:  Identify and fingerprint Web Application Firewall products

`webshells`:  Collection of webshells

`weevely`:  Stealth tiny web shell

`wfuzz`:  Web application bruteforcer

`wget`:  Retrieves files from the web

`whatweb`:  Next generation web scanner

`whois`:  Intelligent WHOIS client

`routersploit`:  Exploitation Framework for Embedded Devices

`powershell`:  PowerShell is an automation and configuration management platform.

`npm`:  package manager for Node.js

`jq`:  Lightweight and flexible command-line JSON processor

`dirsearch`:  Web path scanner

`gitleaks`:  Scan git repos (or files) for secrets using regex and entropy

`naabu`:  Is a port scanning tool written in Go

`subfinder`:  Is a subdomain discovery tool

`shodan`: A shodan cli for shodan internet connected device crawling

`mlocate`: Transitional dummy package

## Tools from source

`rustscan`: A fast port scanning and enumeration

`linkedin2username`:  OSINT Tool, Generate username lists from companies on LinkedIn

`sigit`:  Simple Information Gathering Toolkit

`Sublist3r`:  Is a python tool designed to enumerate subdomains of websites using OSINT

`Invoke-Obfuscation`:  PowerShell obfuscator for windows defense evasion

> Note: require `git`

## Npm tools

`wappalyzer`: Wappalyzer cli for web technologies identifier

>Note: Require `chromium-driver`

## Go tools

`httpx`: Fast and multi-purpose HTTP probing

`katana`: A next-generation crawling and spidering framework.

`tlsx`: Fast and configurable TLS grabber focused on TLS based data collection and analysis.

`uncovr`:  Quickly discover exposed hosts on the internet using multiple search engines.

> Note: Require `go`
