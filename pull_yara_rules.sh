#!/bin/bash

# Configuration
RULES_DIR="./yara-rules"
TEMP_DIR="/tmp/yara_update"
mkdir -p "$RULES_DIR"
mkdir -p "$TEMP_DIR"

echo "Updating YARA rules..."

# List of official/authoritative rule URLs
# Keys cannot contain dots in some bash versions/shells, using underscores
declare -A RULES=(
    ["APT_Equation"]="https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Equation.yar"
    ["spy_equation_fiveeyes"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/spy_equation_fiveeyes.yar"
    ["apt_vpnfilter"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_vpnfilter.yar"
    ["apt_blackenergy"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_blackenergy.yar"
    ["apt_fancybear_dnc"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_fancybear_dnc.yar"
    ["apt_waterbear"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_waterbear.yar"
    ["apt_plead_downloader"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_plead_downloader.yar"
    ["gen_tscookie_rat"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_tscookie_rat.yar"
    ["apt_venom_linux_rootkit"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_venom_linux_rootkit.yar"
    ["Windows_Trojan_Generic"]="https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Generic.yar"
    ["Linux_Trojan_Generic"]="https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Generic.yar"
    ["Windows_Trojan_Trickbot"]="https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Trickbot.yar"
    ["Linux_Trojan_Mirai"]="https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Mirai.yar"
)

for key in "${!RULES[@]}"; do
    url="${RULES[$key]}"
    filename="${key}.yar"
    echo "Downloading $filename..."
    curl -sL "$url" -o "$TEMP_DIR/$filename"
    
    # Verify the download (basic check: file size > 100 bytes to avoid 404 pages)
    if [ $(stat -f%z "$TEMP_DIR/$filename" 2>/dev/null || stat -c%s "$TEMP_DIR/$filename") -gt 100 ]; then
        mv "$TEMP_DIR/$filename" "$RULES_DIR/$filename"
        echo "Successfully updated $filename"
    else
        echo "Failed to update $filename (possibly 404 or corrupted)"
        rm -f "$TEMP_DIR/$filename"
    fi
done

rm -rf "$TEMP_DIR"
echo "YARA rules update complete."
