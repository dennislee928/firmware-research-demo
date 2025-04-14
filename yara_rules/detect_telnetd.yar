rule detect_telnetd {
    meta:
        description = "Detect telnet daemon in firmware"
        author = "Dennis Lee"
        date = "2024-04-14"
    strings:
        $telnetd = "telnetd" nocase
        $telnet_port = "23" ascii
    condition:
        any of them
}
