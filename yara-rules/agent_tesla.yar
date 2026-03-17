rule AgentTesla_Stormshield {
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        version = "1.0"

    strings:
        $html_username = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        any of them
}

rule AgentTesla_Generic {
    meta:
        description = "Generic Agent Tesla strings"
        author = "Dennis Lee"
    strings:
        $a1 = "get_URL" ascii wide
        $a2 = "get_UserName" ascii wide
        $a3 = "get_Password" ascii wide
        $a4 = "GetSavedPasswords" ascii wide
        $a5 = "Microsoft.VisualBasic.MyServices" ascii wide
        $a6 = "GuidAttribute" ascii wide
        $a7 = "ComVisibleAttribute" ascii wide
    condition:
        uint16(0) == 0x5A4D and 4 of them
}
