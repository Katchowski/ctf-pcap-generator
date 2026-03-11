# For Professors: Running a Network Forensics CTF

This guide helps you plan, run, and grade a Capture The Flag (CTF) competition using the CTF PCAP Generator. Whether you are running your first CTF or your tenth, you will find checklists, recommended scenario packs, and grading tips that turn the tool into a complete competition workflow.

---

## What Is a CTF?

A Capture The Flag competition is a cybersecurity exercise where participants solve challenges to find hidden "flags" -- secret strings like `CTF{found_the_attack}`. Teams or individuals earn points for each flag they submit correctly. CTFs are widely used in university courses, security training programs, and industry hiring because they test practical skills in a hands-on, competitive format.

In a network forensics CTF, the challenges are PCAP files -- recordings of network traffic captured from a network interface. Each PCAP contains evidence of an attack or suspicious activity, with a flag hidden somewhere in the traffic. Students analyze these files in Wireshark, a free and widely-used network protocol analyzer, to identify what happened and find the flag.

Here is what a student's workflow looks like during the competition: they download a PCAP file from the scoring platform, open it in Wireshark, examine the packets to identify suspicious traffic patterns, locate the hidden flag string embedded in the network data, and submit it to the scoring platform to earn points. The CTF PCAP Generator creates these challenge files for you -- complete with realistic attack traffic, configurable difficulty, and embedded flags -- so you can focus on teaching rather than crafting packets by hand.

---

## Before the Competition -- Two Weeks Out

Use this checklist to get everything set up with plenty of time for testing and adjustments.

1. **Install Docker Desktop and get the PCAP generator running.** Follow the [Deployment Guide](./deployment.md) -- it walks you from installation through your first generated PCAP in about 10 minutes.

2. **Choose your scenarios.** The generator includes 12 scenarios (10 attack scenarios and 2 tutorials). See the [Scenario Reference](./scenarios.md) for descriptions, protocols, and Wireshark filters for each one, or pick a [Starter Pack](#starter-packs) below for a curated selection.

3. **Decide on difficulty levels for each scenario.** Easy difficulty uses plaintext flags with minimal background noise -- good for introductory classes. Medium adds Base64 encoding and more noise. Hard uses chained encodings and high noise ratios, suitable for students with prior experience. See the [Scenario Reference](./scenarios.md) for the full difficulty comparison table.

4. **Generate test PCAPs and open them in Wireshark yourself.** Verify that the flags are findable and that the challenges match the difficulty level you want. This also gives you first-hand experience with what your students will see.

5. **Set up CTFd if using a scoring platform.** CTFd is an open-source platform that handles student logins, file distribution, flag submission, and live scoring. Follow the [CTFd Integration Guide](./ctfd-integration.md) to get it running alongside the PCAP generator.

6. **Create student accounts in CTFd** (or enable self-registration so students can create their own accounts on competition day).

---

## Before the Competition -- Day Before

Final preparations to make sure everything is ready.

1. **Generate your final PCAPs with production flags.** Use different flags from the ones you used during testing -- you do not want test answers floating around.

2. **Push challenges to CTFd** using the [CTFd Integration Guide](./ctfd-integration.md), or prepare a ZIP file of PCAPs for manual distribution if you are not using a scoring platform.

3. **Test the full student workflow end-to-end.** Log into CTFd as a test student, download a PCAP, find the flag in Wireshark, and submit it. Confirm the scoreboard updates correctly.

4. **Prepare a brief introductory slide or handout** explaining what a CTF is, how to open PCAPs in Wireshark, and how to submit flags. Even a 5-minute overview saves significant time on competition day.

---

## During the Competition

1. **Share the CTFd URL with students** (or distribute the PCAP ZIP file if not using CTFd). Make sure students know where to go and how to log in.

2. **Point students to Wireshark** if they do not already have it installed. It is a free download at [wireshark.org](https://www.wireshark.org/).

3. **Start with an Easy scenario as a warm-up.** Give students 10-15 minutes to work on it, then walk through the solution together as a class. This gets everyone comfortable with the workflow before tackling harder challenges.

4. **Monitor the CTFd scoreboard for progress.** You can see which challenges have been solved and by whom in real time. If no one is making progress on a particular challenge, consider dropping a hint.

5. **Be available for hints.** The auto-generated writeups included with each PCAP contain Wireshark filters and analysis steps that help you guide students without giving away the answer directly.

---

## After the Competition

1. **Review the CTFd scoreboard** to see which challenges were solved, which were not, and how students ranked. This data helps you gauge how well the difficulty levels matched your students' skill levels.

2. **Walk through solutions** using the auto-generated writeups. Each writeup includes the Wireshark display filter to isolate the relevant traffic, step-by-step analysis of the attack, and where the flag was hidden.

3. **Discuss real-world implications.** Each scenario simulates a real attack technique. Use the post-competition debrief to connect the exercise to real-world incidents -- SQL injection, brute force attacks, DNS tunneling, and reverse shells are all things students may encounter in their careers.

4. **Gather student feedback** for future competitions. Ask what they found too easy, too hard, or confusing. This helps you tune the difficulty and scenario selection for next time.

---

## Starter Packs

These are curated sets of scenarios grouped by student experience level. Each pack is designed to fill a specific time slot and provide a progression from simpler to more complex challenges. For full details on any scenario, see the [Scenario Reference](./scenarios.md).

### Intro Pack -- First-Time Students (~1 hour)

Best for students who have never used Wireshark or analyzed network traffic before. Start with the tutorials to build confidence, then introduce one real attack.

| Scenario | Category | Difficulty | Why Include It |
|----------|----------|------------|----------------|
| Simple TCP Session | Tutorial | Easy | Warm-up: teaches basic Wireshark navigation and TCP handshake |
| Simple DNS Lookup | Tutorial | Easy | Introduces the DNS protocol and how to inspect query/response pairs |
| SYN Port Scan | Network Attack | Easy | First real attack: a simple, repetitive pattern that is easy to spot |

### Intermediate Pack -- Some Networking Background (~2 hours)

For students who understand basic networking concepts (TCP/IP, HTTP, DNS) but are new to security analysis. These scenarios require deeper packet inspection and introduce different attack categories.

| Scenario | Category | Difficulty | Why Include It |
|----------|----------|------------|----------------|
| SQL Injection | Web Traffic | Medium | Application-layer attack visible in HTTP request URLs |
| Brute Force Login | Network Attack | Medium | Repetitive pattern recognition with failed/successful login attempts |
| DNS Tunneling | Covert Channel | Medium | Hidden data inside normal-looking DNS traffic -- teaches protocol misuse |

### Advanced Pack -- Experienced Students (~3 hours)

For students with prior security coursework or CTF experience. These scenarios require understanding of lower-level protocols, multi-step analysis, and pattern recognition across large captures.

| Scenario | Category | Difficulty | Why Include It |
|----------|----------|------------|----------------|
| ARP Spoofing / MITM | Network Attack | Hard | Layer 2 attack requiring ARP cache analysis and traffic correlation |
| Reverse Shell | Post-Exploitation | Hard | Identifying attacker command-and-control over a persistent TCP session |
| HTTP Beaconing / C2 | Malware / C2 | Hard | Detecting periodic check-in patterns disguised as normal web traffic |
| ICMP Exfiltration | Covert Channel | Hard | Data hidden inside ping packet payloads -- tests deep protocol knowledge |

> **Mix and match:** You are not limited to these packs. Pick any combination of scenarios from the [Scenario Reference](./scenarios.md) to build a custom competition tailored to your syllabus.

---

## Grading and Assessment Tips

- **Flag submission is binary proof of work.** Either students found the flag or they did not -- there is no partial credit built into the scoring platform. This makes grading straightforward and objective.

- **Recommended point values by difficulty:** Easy challenges are worth 100 points, Medium are worth 200, and Hard are worth 300. You can adjust these values in CTFd when creating or editing challenges.

- **Use the CTFd scoreboard for real-time tracking.** During the competition, you can see exactly who has solved what and when. After the competition, export the results for your records.

- **Consider partial credit for written analysis.** If a student cannot find the flag but can describe the attack they observed in the PCAP (for example, "I saw repeated POST requests to a login page with different passwords"), that demonstrates understanding even without a correct flag submission. Ask students to submit a brief write-up alongside their flag attempts.

- **Auto-generated writeups simplify answer key creation.** Each PCAP the generator produces comes with a writeup that includes the Wireshark filter, analysis steps, and flag location. You can use these directly as your answer key or as the basis for a solution walkthrough after the competition.

---

*For scenario details and Wireshark filters, see the [Scenario Reference](./scenarios.md). For connecting to a scoring platform, see the [CTFd Integration Guide](./ctfd-integration.md). For installation and setup, see the [Deployment Guide](./deployment.md).*
