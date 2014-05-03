HeartLeak
=========

Yet, another exploitation script for the most buzzed bug of all the time. 
The script has two features:


scan: Generates random hosts (IP addresses), checks if they supports OpenSSL, test them if they vulnerable to CVE-2014-0160 (Heartbeat Buffer over-read bug) and save vulnerable hosts in a TXT file


monitor: This keeps sending malicious heartbeat requests, dumps leaked data "as is" in a file. It also looks for printable data, save them in a TXT file and display them on the screen.
