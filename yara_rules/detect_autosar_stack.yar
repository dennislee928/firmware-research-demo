rule detect_autosar_stack {
    meta:
        description = "Detect AUTOSAR stack components"
        author = "Dennis Lee"
        date = "2024-04-14"
    strings:
        $autosar_magic = "AUTOSAR" ascii
        $bsw_com = "Com_" ascii
        $bsw_pdu = "PduR_" ascii
        $bsw_can = "CanIf_" ascii
        $rte_api = "Rte_" ascii
        $mcal_api = "Mcal_" ascii
    condition:
        any of them
}
