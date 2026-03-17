#!/bin/bash

# Configuration: use script directory if PROJECT_DIR not set (portable across environments)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR}"
RULES_DIR="$PROJECT_DIR/yara-rules"
TEMP_DIR="/tmp/yara_update"

mkdir -p "$RULES_DIR"
mkdir -p "$TEMP_DIR"

echo "Updating YARA rules in $RULES_DIR..."

# List of official/authoritative rule URLs (Bash 3.2 compatible)
# Format: "filename|url"
# Comments indicate which malware sample source(s) each rule helps cover:
#   MalwareBazaar, VX-Underground, MalShare, VirusShare, theZoo, Malware-Database
#
# Neo23x0: exclude files that use LOKI/THOR external variables (generic_anomalies.yar,
# thor_inverse_matches.yar, gen_webshells_ext_vars.yar, general_cloaking.yar, yara_mixed_ext_vars.yar)
# to avoid "undefined identifier" errors when running YARA.

RULES=(
    # --- Existing: APT / Firmware / IoT (MalwareBazaar, theZoo, Malware-Database) ---
    "APT_Equation|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Equation.yar"
    "spy_equation_fiveeyes|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/spy_equation_fiveeyes.yar"
    "apt_vpnfilter|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_vpnfilter.yar"
    "apt_blackenergy|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_blackenergy.yar"
    "apt_fancybear_dnc|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_fancybear_dnc.yar"
    "apt_waterbear|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_waterbear.yar"
    "apt_plead_downloader|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_plead_downloader.yar"
    "gen_tscookie_rat|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_tscookie_rat.yar"
    "apt_venom_linux_rootkit|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_venom_linux_rootkit.yar"
    # --- Elastic: Generic Trojans (VirusShare, MalShare, all sources) ---
    "Windows_Trojan_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Generic.yar"
    "Linux_Trojan_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Generic.yar"
    "Windows_Trojan_Trickbot|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Trickbot.yar"
    "Linux_Trojan_Mirai|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_Mirai.yar"
    # --- Yara-Rules: MalwareBazaar / theZoo families (Emotet, Zeus, Mirai, WannaCry) ---
    "MALW_Emotet|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Emotet.yar"
    "MALW_Zeus|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Zeus.yar"
    "MALW_Mirai|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Mirai.yar"
    "RANSOM_MS17-010_Wannacrypt|https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_MS17-010_Wannacrypt.yar"
    # --- Neo23x0: Crime/ransom/emotet/zeus/mirai/qbot (MalwareBazaar, VirusShare, MalShare, theZoo) ---
    "crime_emotet|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_emotet.yar"
    "crime_wannacry|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_wannacry.yar"
    "crime_zeus_panda|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_zeus_panda.yar"
    "crime_mirai|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_mirai.yar"
    "crime_ransom_generic|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_ransom_generic.yar"
    "mal_qbot_payloads|https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/mal_qbot_payloads.yar"
    # --- Elastic: Ransomware / Info stealer / RedLine / Qbot (MalwareBazaar, VirusShare, theZoo) ---
    "Windows_Ransomware_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Ransomware_Generic.yar"
    "Windows_Ransomware_WannaCry|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Ransomware_WannaCry.yar"
    "Windows_Trojan_Emotet|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Emotet.yar"
    "Windows_Trojan_Zeus|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Zeus.yar"
    "Windows_Trojan_RedLineStealer|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_RedLineStealer.yar"
    "Windows_Trojan_Qbot|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Qbot.yar"
    "Windows_Infostealer_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Infostealer_Generic.yar"
    "Windows_Trojan_AgentTesla|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_AgentTesla.yar"
    # --- Elastic: PUP / macOS (broader coverage) ---
    "Windows_PUP_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_PUP_Generic.yar"
    "macOS_Trojan_Generic|https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/MacOS_Trojan_Generic.yar"
)

for rule in "${RULES[@]}"; do
    filename_base="${rule%%|*}"
    url="${rule#*|}"
    filename="${filename_base}.yar"

    echo "Downloading $filename..."
    curl -sL "$url" -o "$TEMP_DIR/$filename"

    # Check if file exists and is larger than 100 bytes (to avoid 404 pages)
    if [ -f "$TEMP_DIR/$filename" ]; then
        # Handle different 'stat' versions (BSD vs GNU)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            size=$(stat -f%z "$TEMP_DIR/$filename")
        else
            size=$(stat -c%s "$TEMP_DIR/$filename")
        fi

        if [ "$size" -gt 100 ]; then
            mv "$TEMP_DIR/$filename" "$RULES_DIR/$filename"
            echo "Successfully updated $filename"
        else
            echo "Skipped $filename (too small, likely 404)"
            rm -f "$TEMP_DIR/$filename"
        fi
    else
        echo "Failed to download $filename"
    fi
done

rm -rf "$TEMP_DIR"
echo "YARA rules update complete."
