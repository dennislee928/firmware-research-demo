# 🔍 Firmware Unpacking & Signature Detection Demo

This project demonstrates my hands-on exploration of firmware analysis, focusing on:

- 🧩 Firmware unpacking using `binwalk` and `hexdump`
- 🧠 Static string and pattern analysis via `Ghidra`
- 🧪 Rule-based detection using `YARA`
- 📑 Simulated report for component recognition in embedded systems

---

## 📦 Structure

```bash
firmware-analysis-demo/
├── firmware.bin              # Sample firmware image (public router bin)
├── binwalk-analysis/         # Unpacked directory using binwalk
├── hexdump-analysis/         # Raw hex + offset annotations
├── yara-rules/
│   └── telnetd_rule.yar      # Custom rule detecting telnet/ssh daemon
├── ghidra-notes.md           # String/function references + annotated images
├── simulated_report.md       # Signature detection summary
├── can-log-demo.txt          # (Optional) Simulated CAN protocol snippet
├── screenshots/              # CLI and GUI usage
└── README.md


🛠️ Tools Used
Tool	Purpose
binwalk	Firmware extraction
hexdump	Raw data inspection
Ghidra	Binary analysis + string mapping
YARA	Rule-based signature matching

🔬 What I Did
✅ Step 1: Unpack Firmware with binwalk

    Extracted file system and component headers

    Identified compressed payloads and ELF headers
    → See /binwalk-analysis/

✅ Step 2: Inspect with hexdump

    Viewed offsets of known patterns (telnetd, dropbear, /etc/shadow)

    Mapped byte ranges for potential rules
    → See /hexdump-analysis/

✅ Step 3: Analyze with Ghidra

    Loaded .bin into Ghidra

    Used "Defined Strings" and "Function Graph" views

    Located embedded services (e.g., BusyBox, sshd)

    💡 Screenshot of Ghidra analysis included in /screenshots/

✅ Step 4: Write & Run YARA Rule

rule Detect_Telnetd {
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
}


    Successfully detected telnetd in unpacked files

    Possible indicator of insecure legacy service

📑 Simulated Detection Report

See simulated_report.md for:

    Matching components

    Risk assessment

    Mapping to detection signature format

🎯 Outcome
Objective	Achieved
Understand embedded firmware layout	✅
Practice binary analysis tools	✅
Create a custom detection signature	✅
Document the process for review	✅
🧠 Next Steps

    Expand ruleset with YARA regexes & metadata

    Integrate pattern match into automation (Python)

    Explore binwalk -eM for multi-layer images

    Learn radare2 or IDA Pro for deeper analysis

📚 Resources Used

    Binwalk Documentation

    YARA Docs

    Ghidra Reverse Engineering Guide

    Firmware Sample

💬 Contact

Dennis Lee
🔗 GitHub: @dennislee928
🔗 Portfolio: next-js-portfolio
📧 Email available upon request


---


