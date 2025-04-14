rule Detect_Telnetd {
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
} 