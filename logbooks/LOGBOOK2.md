# Work done in Weeks #2 e #3

## Identification

- CVE-2022-30190 - Follina
- [Remote Code Execution](https://encyclopedia.kaspersky.com/glossary/remote-code-execution-rce/): Gives attackers the ability to execute malicious code/malware and take over an affected system.
- It can be exploited when the Microsoft Windows Support Diagnostic Tool (MSDT) is called using the URL protocol from an application (Microsoft Word, for instance).
- Affected Systems:
    - Office Pro Plus, 2013, 2016, 2019 and 2021.
    - Windows 7, 8.1, 10, 11
    - Windows Server 2008, 2012, 2016, 2019 and 2022.

## Cataloguing

- CVSS severity score: 3.x - 7.8 (high); 2.0 - 9.3 (high)
- On May 29th 2022 a security researcher, Kevin Beaumont published an article about a malicious Microsoft Word document by "Nao_sec" [two days before](https://x.com/nao_sec/status/1530196847679401984?s=20)
- Microsoft acknowledge this on May 31st as a zero-day exploit
- Security updates were released on June 14th to address the vulnerability

## Exploit

- Attackers create a malicious Microsoft Office document and send it to the victim through phishing tactics.
- The infected file contains a link to an HTML file, which contains JavaScript code that executes malicious code in the command line via the MSDT.
- If the vulnerability is successfully exploited, the attackers can install programs, create accounts and view, modify or destroy data — they basically get access to the victim's system privileges.

## Attacks

- Former Conti cybercrime members conducted a [phishing campaign to deploy Malware](https://thehackernews.com/2022/09/some-members-of-conti-group-targeting.html) on to targeted hosts in media and critical infrastructures in Ukraine.
- Unknown threat actor [targeted Russian entities with a remote access trojan](https://thehackernews.com/2022/08/new-woody-rat-malware-being-used-to.html) for espionage purposes using Follina to distribute the payload.
- Hackers leveraged Follina to [spread an undisclosed backdoor on Windows](https://thehackernews.com/2022/07/hackers-exploiting-follina-bug-to.html)  capable of injecting a remote shell connectionback to the attacker's machine.
- Actor TA413 CN APT installed malicious payloads into [targeted Tibetan entities](https://www.bleepingcomputer.com/news/security/windows-msdt-zero-day-now-exploited-by-chinese-apt-hackers/) by impersonating the 'Women Empowerments Desk'.
