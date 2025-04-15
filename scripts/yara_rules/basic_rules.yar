rule detect_telnetd {
    meta:
        description = "Detect telnetd executable or related strings"
        severity = "high"
    strings:
        $a = "telnetd"
        $b = "telnet server"
    condition:
        any of them
}

rule detect_busybox {
    meta:
        description = "Detect BusyBox executable"
        severity = "medium"
    strings:
        $a = "BusyBox v"
        $b = "applets:"
    condition:
        all of them
}

rule detect_libcrypto {
    meta:
        description = "Detect usage of libcrypto (OpenSSL)"
        severity = "medium"
    strings:
        $a = "OpenSSL"
        $b = "libcrypto.so"
    condition:
        any of them
}
