# Phishing Email Analysis Lab

## Objective
[Brief Objective - Remove this afterwards]

The primary objective of this lab exercise was to conduct a comprehensive manual investigation of a real-world phishing email to determine its legitimacy and potential threat level.By shifting away from automated tools, the lab focused on deep-dive forensic techniques to uncover the technical infrastructure used by threat actors.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Header Parsing & Decoding
- Email Authentication Auditing
- Infrastructure Tracing
- Multi-Engine Malware Detection
- Indicator of Compromise (IOC) Pivot
- Safe Handling of Malicious Artifacts 

### Tools Used
[Bullet Points - Remove this afterwards]

- EML Analyzer / Header Parser: To convert raw .eml files into a structured format.
- Virus Total: Used for multi-engine scanning of extracted URLs and file hashes.
- Whois Lookup (EML Analyzer) : Utilized to determine the age of the sending domain and the registrar's details.
- IP Reputation Databases: Applied to verify if the source mail server was blacklisted for spamming or hosting malicious content.
- URL Defanging Tools: Used to safely neutralize malicious links

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Phhishing Email Analysis*

To ensure safety and isolation, the analysis was performed within a hardened Ubuntu Linux virtual machine (running on Oracle VirtualBox). This environment provided a controlled sandbox to deconstruct malicious attachments and scripts without risking the host system.

<img width="1600" height="900" alt="Screenshot (66)" src="https://github.com/user-attachments/assets/75415fd1-6531-485c-8cd7-d04aa933cde9" />

*Ref 2: Phishing Email Analysis*

After extracting the raw email data, the next step was to analyze the Verdicts provided by the EML Analyzer. This phase focuses on understanding the specific "red flags" that automated systems like SpamAssassin use to categorize an email as malicious or spam, even when direct malware is not present.

<img width="1600" height="900" alt="Screenshot (67)" src="https://github.com/user-attachments/assets/6bccf122-687d-438b-9c02-a8038e0efa95" />


*Ref 3: Phishing Email Analysis*


This stage demonstrates the importance of looking beyond a "low" automated score; the combination of malformed headers, failed authentication, and suspicious external links provides strong evidence of a programmatic phishing attempt.


<img width="1419" height="843" alt="Screenshot 2025-12-17 180826" src="https://github.com/user-attachments/assets/ba7aa1a4-2392-4547-9bd4-a6f1343489ed" />



*Ref 4: Phishing Email Analysis*

Examining these hidden headers, the investigation moved beyond the "Friendly From" name to uncover the technical reality of the message's origin. The discrepancy between the claimed identity and the root-level return path on a generic Linux server provides irrefutable evidence of a phishing campaign.


<img width="1197" height="543" alt="Screenshot 2025-12-17 180929" src="https://github.com/user-attachments/assets/9842d73d-5f0d-441b-91e8-4e27d1d82a1b" />


*Ref 5: Phishing Email Analysis*

The combination of structural anomalies, failed cryptographic signatures, and suspicious cloud-based origin provides irrefutable evidence of a malicious phishing attempt. This lab successfully demonstrated the high-fidelity results achievable through manual header deconstruction and artifact correlation.


<img width="1195" height="764" alt="Screenshot 2025-12-17 182035" src="https://github.com/user-attachments/assets/1dbef140-2c5a-4261-bd67-fd1057017afa" />

*Ref 6: Phishing Email Analysis*

By deconstructing the email's HTML body, this phase moved beyond the visual appearance of a legitimate financial communication from Banco do Bradesco. This stage demonstrates the importance of looking beyond a "low" automated score; the combination of malformed headers and suspicious external links provides strong evidence of a programmatic phishing attempt. Identifying these specific URL artifacts was crucial for the subsequent threat intelligence validation using platforms like VirusTotal.

<img width="1207" height="758" alt="Screenshot 2025-12-17 183222" src="https://github.com/user-attachments/assets/d9e61408-f01b-4cbc-a1a5-8caa45a58578" />

*Ref 7: Phishing Email Analysis*

This investigation demonstrates the critical importance of looking beyond "low" automated scores; the combination of failed cryptographic signatures, malformed technical headers, and suspicious cloud-based origin provides irrefutable evidence of a malicious, programmatic phishing campaign.


<img width="1600" height="900" alt="Screenshot (68)" src="https://github.com/user-attachments/assets/a7eb1ca6-da72-4f40-b045-5e5249b32575" />








