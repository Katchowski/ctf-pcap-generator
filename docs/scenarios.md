# Scenario Reference Guide

This guide describes every scenario the CTF PCAP Generator can produce. A **scenario** is a type of network attack or activity captured in a PCAP file -- a packet capture that students open and analyze in Wireshark, a free network protocol analyzer. Each scenario embeds a hidden flag (a secret string like `CTF{example_flag}`) that students must find by examining the traffic.

The generator includes 10 attack scenarios and 2 tutorial scenarios. Attack scenarios simulate real-world network threats. Tutorial scenarios produce simple, predictable traffic useful for getting students comfortable with Wireshark before tackling attacks.

For setup instructions, see the [Deployment Guide](./deployment.md). For environment variable details (including packet count limits), see the [Configuration Reference](./configuration.md).

---

## Table of Contents

- [How Difficulty Works](#how-difficulty-works)
- [Attack Scenarios](#attack-scenarios)
  - [Network Attacks](#network-attacks)
  - [Web Traffic](#web-traffic)
  - [Covert Channels](#covert-channels)
  - [Malware / C2](#malware--c2)
  - [Post-Exploitation](#post-exploitation)
- [Tutorial Scenarios](#tutorial-scenarios)

---

## How Difficulty Works

Every scenario supports three difficulty levels: **Easy**, **Medium**, and **Hard**. An important thing to understand is that difficulty does **not** change the attack traffic itself -- the attack packets are identical at every difficulty level. A SQL injection looks the same whether you generate it on Easy or Hard.

What difficulty controls is how hard the **flag** is to find. Specifically, difficulty adjusts five things:

1. **Noise ratio and types** -- How much unrelated background traffic surrounds the attack. More noise means students have to sift through more irrelevant packets.
2. **Flag encoding chain** -- How the flag is encoded before being embedded. Easy uses plaintext; Hard uses randomly chained encodings that students must decode step by step.
3. **Flag split count** -- Whether the flag is embedded as one whole string or split across multiple packets. More pieces means more reassembly work.
4. **Total packet count** -- The overall size of the capture. Larger captures make it harder to locate relevant packets.
5. **Timing jitter** -- Variation in packet timing. Wider jitter makes time-based filtering less reliable.

Here is the master difficulty comparison table with exact values used by the generator:

| Aspect | Easy | Medium | Hard |
|--------|------|--------|------|
| **Noise ratio** | 20% (ARP only) | 60% (ARP, DNS) | 85% (ARP, DNS, HTTP, ICMP) |
| **Flag encoding** | Plaintext | Base64 | Chained (see note below) |
| **Flag split** | 1 piece (whole flag) | 2 pieces | 3-4 pieces |
| **Packet count** | 20-50 | 200-500 | 1,000-5,000 |
| **Timing jitter** | 10-50 ms | 5-200 ms | 1-500 ms |

> **Hard encoding chains:** Hard difficulty uses randomly selected encoding chains. Each time you generate a Hard PCAP, one of these chains is chosen at random: Base64 + Hex, ROT13 + Base64, Hex + Base64, Hex + ROT13 + Base64, Base64 + ROT13, and ROT13 + Hex. Students must identify and reverse the chain to recover the flag.

These settings apply identically to all scenarios. The sections below describe each scenario's attack traffic, not its difficulty behavior.

---

## Attack Scenarios

### Network Attacks

---

#### SYN Port Scan

| Property | Value |
|----------|-------|
| **Scenario file** | `syn_scan.yaml` |
| **Protocol** | TCP |
| **Category** | Network Attack |
| **Default difficulty** | Easy |

**What the attacker does:** Sends SYN packets -- the initial packet in a TCP connection handshake -- to a range of common service ports on a target machine. This is called a "half-open" scan because the attacker never completes the handshake. For each port, the target either responds with SYN-ACK (meaning the port is open and a service is listening) or RST (meaning the port is closed). Students will see a burst of SYN packets to ports like 22 (SSH), 80 (HTTP), and 443 (HTTPS), with only a few getting SYN-ACK replies.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
This filter isolates only the initial SYN probes sent by the scanner, filtering out all response packets and background noise.

---

#### Brute Force Login

| Property | Value |
|----------|-------|
| **Scenario file** | `brute_force.yaml` |
| **Protocol** | TCP (HTTP) |
| **Category** | Network Attack |
| **Default difficulty** | Medium |

**What the attacker does:** Sends repeated HTTP POST requests to a login page, trying different username and password combinations. Students will see a series of failed login attempts (the server responds with error codes or "login failed" messages) followed by one successful login at the end. This simulates a real brute force attack where an attacker automates credential guessing against a web application.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
http.request.method == "POST" && http contains "login"
```
This filter shows only HTTP POST requests that contain "login" in the payload, isolating the authentication attempts from other traffic.

---

#### ARP Spoofing / MITM

| Property | Value |
|----------|-------|
| **Scenario file** | `arp_spoofing.yaml` |
| **Protocol** | ARP / TCP |
| **Category** | Network Attack |
| **Default difficulty** | Hard |

**What the attacker does:** Sends gratuitous ARP replies -- unsolicited ARP messages that are a type of network-layer announcement -- to trick other devices on the network into associating the attacker's MAC address (hardware address) with the gateway's IP address. Once the ARP cache is poisoned, traffic from the victim flows through the attacker's machine, enabling a man-in-the-middle (MITM) position. Students will see ARP reply packets followed by intercepted HTTP or DNS traffic that should have gone directly to the gateway.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
arp.opcode == 2
```
This filter shows only ARP reply packets (opcode 2), which includes the gratuitous replies used for cache poisoning.

---

### Web Traffic

---

#### SQL Injection

| Property | Value |
|----------|-------|
| **Scenario file** | `sqli.yaml` |
| **Protocol** | TCP (HTTP) |
| **Category** | Web Traffic |
| **Default difficulty** | Medium |

**What the attacker does:** Sends HTTP GET requests with SQL injection payloads in a query parameter. The attack progresses from simple tautology probes (like `' OR 1=1 --`) to more advanced UNION SELECT statements that extract data from the database. Students will see the malicious SQL embedded in the URL query string and can observe how the server responses change as the attacker discovers the database structure. SQL injection is one of the most common web application vulnerabilities.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
http.request.uri contains "UNION" || http.request.uri contains "%27"
```
This filter catches requests containing UNION SELECT statements or `%27` (the URL-encoded single quote character used in injection attempts).

---

#### XSS Reflected

| Property | Value |
|----------|-------|
| **Scenario file** | `xss_reflected.yaml` |
| **Protocol** | TCP (HTTP) |
| **Category** | Web Traffic |
| **Default difficulty** | Medium |

**What the attacker does:** Sends HTTP requests with cross-site scripting (XSS) payloads in a query parameter. The server reflects the payload back in the HTML response without sanitizing it, allowing injected JavaScript to execute. Students will see progressively sophisticated XSS payloads -- from simple `<script>alert(1)</script>` tags to encoded variations designed to bypass basic filters. The PCAP shows both the malicious request and the server's response containing the unescaped script.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
http.request.uri contains "<script" || http.request.uri contains "%3Cscript"
```
This filter catches requests containing `<script` tags in either literal or URL-encoded (`%3C`) form.

---

#### Directory Traversal

| Property | Value |
|----------|-------|
| **Scenario file** | `dir_traversal.yaml` |
| **Protocol** | TCP (HTTP) |
| **Category** | Web Traffic |
| **Default difficulty** | Medium |

**What the attacker does:** Sends HTTP GET requests with path traversal sequences (`../`) in the URL to escape the intended directory and access files elsewhere on the server's filesystem. Students will see a series of attempts -- some returning 403 Forbidden or 404 Not Found -- followed by successful responses that leak file contents like `/etc/passwd`. This demonstrates how improperly validated file paths can expose sensitive server files.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
http.request.uri contains ".."
```
This filter isolates HTTP requests containing the `..` directory traversal sequence in the URL path.

---

### Covert Channels

---

#### DNS Tunneling

| Property | Value |
|----------|-------|
| **Scenario file** | `dns_tunnel.yaml` |
| **Protocol** | UDP (DNS) |
| **Category** | Covert Channel |
| **Default difficulty** | Hard |

**What the attacker does:** Exfiltrates data by encoding it into DNS subdomain labels. DNS (Domain Name System) is the protocol that translates domain names to IP addresses, and most networks allow DNS traffic through firewalls. The attacker encodes stolen data using Base32 and sends it as queries for subdomains under an attacker-controlled domain (for example, `encoded-data.exfil.attacker.com`). Students will notice unusually long subdomain names and high query volumes to a suspicious domain -- hallmarks of DNS tunneling.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
dns.qry.name contains "exfil" || dns.qry.name.len > 50
```
This filter catches DNS queries where the queried name contains "exfil" or is unusually long (over 50 characters), both indicators of tunneled data.

---

#### ICMP Exfiltration

| Property | Value |
|----------|-------|
| **Scenario file** | `icmp_exfil.yaml` |
| **Protocol** | ICMP / TCP |
| **Category** | Covert Channel |
| **Default difficulty** | Hard |

**What the attacker does:** Hides stolen data inside ICMP echo request payloads -- the same type of packet used by the `ping` command. Normally, ping payloads contain padding data, but here the attacker replaces that padding with encoded chunks of exfiltrated data. A TCP control channel on port 4444 coordinates the exfiltration. Students will see ICMP packets with unusually large or non-standard payloads alongside suspicious TCP connections, indicating covert data transfer over a protocol that is often left unmonitored.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
icmp && data.len > 0
```
This filter shows ICMP packets that carry a data payload, distinguishing the exfiltration traffic from normal empty pings.

---

### Malware / C2

---

#### HTTP Beaconing / C2

| Property | Value |
|----------|-------|
| **Scenario file** | `http_beacon.yaml` |
| **Protocol** | TCP (HTTP) |
| **Category** | Malware / C2 |
| **Default difficulty** | Hard |

**What the attacker does:** Simulates malware that periodically "phones home" to a command-and-control (C2) server disguised as a CDN (Content Delivery Network). The infected machine sends HTTP requests at regular intervals to a domain like `cdn-static.updates.com`, checking in for instructions. The C2 server responds with Base64-encoded commands hidden in what looks like normal CDN traffic. Students will notice the periodic timing pattern and the suspicious domain, and can decode the C2 commands from the response bodies.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
http.host contains "cdn-static" || http.request.uri contains "/api/check"
```
This filter isolates traffic to the disguised C2 domain or the check-in URI path used by the beacon.

---

### Post-Exploitation

---

#### Reverse Shell

| Property | Value |
|----------|-------|
| **Scenario file** | `reverse_shell.yaml` |
| **Protocol** | TCP |
| **Category** | Post-Exploitation |
| **Default difficulty** | Hard |

**What the attacker does:** Establishes an interactive shell session from a compromised machine back to the attacker's listener on port 4444. Once connected, the attacker sends operating system commands (like `whoami`, `ls`, `cat /etc/passwd`) and receives their output over the persistent TCP connection. Students will see a long-lived TCP session on a suspicious port with readable command-and-response text flowing in both directions -- a clear indicator of remote access.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
tcp.port == 4444 && tcp.len > 0
```
This filter shows TCP packets on the reverse shell port that carry payload data, isolating the interactive session from TCP handshake and control packets.

---

## Tutorial Scenarios

These scenarios generate simple, clean traffic useful for introducing students to Wireshark before moving to attack scenarios. They produce minimal packets with straightforward protocols, making them ideal for a first lab exercise.

---

#### Simple TCP Session

| Property | Value |
|----------|-------|
| **Scenario file** | `simple_tcp.yaml` |
| **Protocol** | TCP |
| **Category** | Tutorial |
| **Default difficulty** | Easy |

**What happens:** Generates a basic TCP session -- a three-way handshake (SYN, SYN-ACK, ACK), a data transfer containing an HTTP request, and a connection teardown. Students can follow the complete lifecycle of a TCP connection and practice identifying the handshake, payload, and teardown phases.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
tcp.port == 80
```
This filter shows all TCP traffic on port 80 (HTTP), which is the entire tutorial session.

---

#### Simple DNS Lookup

| Property | Value |
|----------|-------|
| **Scenario file** | `simple_dns.yaml` |
| **Protocol** | UDP (DNS) |
| **Category** | Tutorial |
| **Default difficulty** | Easy |

**What happens:** Generates a handful of DNS query-and-response pairs for different domain names. Students can see how DNS resolution works: the client asks a DNS server "what is the IP address of example.com?" and the server responds with the answer. This is a good starting point for understanding DNS before tackling the DNS Tunneling attack scenario.

**Difficulty differences:** See [How Difficulty Works](#how-difficulty-works) above -- difficulty settings apply identically to all scenarios.

**Wireshark display filters:**
```
dns
```
This filter shows all DNS traffic -- both queries and responses.

---

*For setup instructions, see the [Deployment Guide](./deployment.md). For environment variable details, see the [Configuration Reference](./configuration.md).*
