Campaign Context

These are detection rules developed against a real, active incident (Axios NPM Supply Chain Compromise) using open source information available as of March 31, 2026. Key facts driving the detection logic:

* Attacker: UNC1069 (North Korea-nexus, attributed by Google GTIG / Mandiant), also tracked as Sapphire Sleet by Microsoft
* Compromised packages: axios@1.14.1 and axios@0.30.4
* Malicious dependency: plain-crypto-js@4.2.1
* Dropper: setup.js (SHA256: e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09) executed via postinstall npm hook, self-deletes after execution
* Backdoor: WAVESHAPER.V2 C++ (macOS), PowerShell (Windows), Python (Linux)
* C2: sfrclak[.]com:8000 / 142.11.206.73
* Window: 00:21–03:29 UTC March 31, 2026

Detection Rule Notes:

Highest confidence detections: Rules 2 (wt.exe masquerade) and 5 (C2 network). The ProgramData path for wt.exe has no legitimate use, and sfrclak.com has no legitimate presence. Both are near-zero false positive.

Retrospective hunting priority: Query 6 (lockfile audit) is the most scalable retrospective signal if you have file content telemetry. Any package-lock.json or yarn.lock containing plain-crypto-js on a host that ran npm install during the March 31 window is a confirmed exposure.

Known coverage gaps: The dropper self-deletes (setup.js removes itself and restores package.json). If your endpoint telemetry doesn't capture file creation events before deletion, Rule 1 (process creation) is your primary signal for the dropper execution itself.
