rule detect_insecure_keys {
    meta:
        description = "Detect insecure keys and certificates in firmware"
        author = "Dennis Lee"
        date = "2024-04-14"
    strings:
        $private_key = "BEGIN PRIVATE KEY" ascii
        $rsa_key = "BEGIN RSA PRIVATE KEY" ascii
        $cert = "BEGIN CERTIFICATE" ascii
        $ssh_key = "BEGIN OPENSSH PRIVATE KEY" ascii
        $password = "password" nocase
        $secret = "secret" nocase
        $key = "key" nocase
    condition:
        any of them
}
