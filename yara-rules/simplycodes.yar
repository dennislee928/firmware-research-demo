import "hash"

rule SimplyCodes_PUP {
    meta:
        description = "Detects SimplyCodes suspicious sample by hash"
        author = "Dennis Lee"
        hash = "535ada9c0c833577ab9489386fad8fc02e9629fe8d038e3dedb3db261868e0ed"
        severity = "medium"
    condition:
        hash.sha256(0, filesize) == "535ada9c0c833577ab9489386fad8fc02e9629fe8d038e3dedb3db261868e0ed"
}
