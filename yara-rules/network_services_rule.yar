rule Detect_Network_Services {
    strings:
        $telnet = "telnetd"
        $ssh = "dropbear"
        $shadow = "/etc/shadow"
    condition:
        any of them
} 