rule AgentTesla_Combined {
    meta:
        description = "Combined detection for Agent Tesla variants"
        author = "Dennis Lee"

    strings:
        // Stormshield strings
        $h1 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $h2 = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        
        // InQuest strings
        $s1 = "get_kbok" ascii
        $s2 = "get_CH" ascii
        $s3 = "set_CH" ascii
        $s4 = "get_clp" ascii
        $s5 = "set_clp" ascii
        
        // Generic .NET / Stealer strings
        $g1 = "get_URL" ascii wide
        $g2 = "get_UserName" ascii wide
        $g3 = "get_Password" ascii wide
        $g4 = "GetSavedPasswords" ascii wide
        $g5 = "mscoree.dll" ascii wide
        $g6 = "Microsoft.VisualBasic" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($h*) or 3 of ($s*) or 3 of ($g*))
}
