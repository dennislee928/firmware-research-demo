rule detect_qnx_os {
    meta:
        description = "Detect QNX operating system components"
        author = "Dennis Lee"
        date = "2024-04-14"
    strings:
        $qnx_magic = "QNX6" ascii
        $qnx_proc = "procnto" ascii
        $qnx_sys = "syspage" ascii
        $qnx_dev = "devb-" ascii
        $qnx_fs = "fs-qnx6" ascii
    condition:
        any of them
}
