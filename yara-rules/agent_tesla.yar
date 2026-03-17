rule AgentTesla_dotnet_detection {
    meta:
        description = "Detects Agent Tesla based on .NET artifacts and common strings"
        author = "Dennis Lee"
        hash = "535ada9c0c833577ab9489386fad8fc02e9629fe8d038e3dedb3db261868e0ed"

    strings:
        $s1 = "GetSavedPasswords" ascii wide
        $s2 = "get_URL" ascii wide
        $s3 = "get_UserName" ascii wide
        $s4 = "get_Password" ascii wide
        $s5 = "Microsoft.VisualBasic.MyServices" ascii wide
        $s6 = "GuidAttribute" ascii wide
        $s7 = "ComVisibleAttribute" ascii wide
        $s8 = "get_Keyboard" ascii wide
        $s9 = "get_Clipboard" ascii wide

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Generic_DotNet_Malware {
    meta:
        description = "Generic detection for suspicious .NET malware"
    strings:
        $msil = "BSJB" // .NET metadata header
        $v1 = "get_MachineName" ascii wide
        $v2 = "get_UserName" ascii wide
        $v3 = "GetForegroundWindow" ascii wide
        $v4 = "SetWindowsHookEx" ascii wide
        $v5 = "GetAsyncKeyState" ascii wide
    condition:
        uint16(0) == 0x5A4D and $msil and 3 of ($v*)
}
