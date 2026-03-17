#!/bin/bash
#===============================================================================
# 韌體分析自動化腳本
# 版本: 2.1
# 作者: Dennis Lee
# 描述: 自動化執行韌體分析，包含hexdump分析、YARA規則檢測、
#       binwalk分析，以及生成各類分析報告
#===============================================================================

# 嚴格模式，避免常見錯誤
set -euo pipefail

#===============================================================================
# 使用幫助
#===============================================================================
show_help() {
  echo "使用方式: $0 [選項] [韌體檔案路徑]"
  echo ""
  echo "選項:"
  echo "  -h, --help               顯示此幫助訊息"
  echo "  -f, --file <路徑>        指定單個韌體檔案進行分析"
  echo "  -d, --directory <路徑>   指定目錄，分析該目錄下所有韌體檔案"
  echo "  -e, --extension <副檔名> 與 -d 一起使用，指定要分析的檔案副檔名 (默認: .bin)"
  echo "  -r, --recursive          與 -d 一起使用，遞迴分析子目錄"
  echo "  -y, --yara-only          僅運行YARA規則檢測"
  echo "  -b, --binwalk-only       僅運行binwalk分析"
  echo "  -x, --extract            提取檔案系統 (與binwalk一起使用)"
  echo ""
  echo "範例:"
  echo "  $0                                  # 分析默認韌體檔案 (firmware.bin)"
  echo "  $0 -f firmware_samples/sample.bin   # 分析指定韌體檔案"
  echo "  $0 -d firmware_samples              # 分析指定目錄中的所有.bin檔案"
  echo "  $0 -d firmware_samples -e .img      # 分析指定目錄中的所有.img檔案"
  echo "  $0 -d firmware_samples -r           # 遞迴分析指定目錄及其子目錄中的所有.bin檔案"
  echo "  $0 -f firmware.bin -y               # 僅對指定檔案運行YARA規則檢測"
  echo "  $0 -f firmware.bin -b -x            # 僅對指定檔案運行binwalk分析並提取檔案系統"
}

# 處理命令行參數
TARGET_FILE=""
TARGET_DIR=""
FILE_EXTENSION=".bin"
RECURSIVE=0
YARA_ONLY=0
BINWALK_ONLY=0
EXTRACT_FILESYSTEM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -f|--file)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        TARGET_FILE="$2"
        shift 2
      else
        echo "錯誤: --file 需要一個檔案路徑參數" >&2
        exit 1
      fi
      ;;
    -d|--directory)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        TARGET_DIR="$2"
        shift 2
      else
        echo "錯誤: --directory 需要一個目錄路徑參數" >&2
        exit 1
      fi
      ;;
    -e|--extension)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        FILE_EXTENSION="$2"
        shift 2
      else
        echo "錯誤: --extension 需要一個副檔名參數" >&2
        exit 1
      fi
      ;;
    -r|--recursive)
      RECURSIVE=1
      shift
      ;;
    -y|--yara-only)
      YARA_ONLY=1
      shift
      ;;
    -b|--binwalk-only)
      BINWALK_ONLY=1
      shift
      ;;
    -x|--extract)
      EXTRACT_FILESYSTEM=1
      shift
      ;;
    *)
      # 如果沒有使用-f選項但提供了參數，視為韌體檔案路徑
      if [ -z "$TARGET_FILE" ] && [ -f "$1" ]; then
        TARGET_FILE="$1"
      fi
      shift
      ;;
  esac
done

#===============================================================================
# 配置變量
#===============================================================================
# 從環境變數獲取分析間隔（分鐘），默認為30分鐘
ANALYSIS_INTERVAL=${ANALYSIS_INTERVAL:-30}

# 設置工作目錄
WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
FIRMWARE_SAMPLES="$WORK_DIR/firmware_samples"
# 如果使用命令行參數指定了檔案，優先使用它
FIRMWARE_FILE="${TARGET_FILE:-$WORK_DIR/firmware.bin}"
FIRMWARE_NAME=$(basename "$FIRMWARE_FILE")
DATE_TAG="$(date "+%Y%m%d_%H%M%S")"
LOG_DIR="$WORK_DIR/logs"
LOG_FILE="$LOG_DIR/analysis_${FIRMWARE_NAME}_$DATE_TAG.log"
REPORT_DIR="$WORK_DIR/reports"
REPORT_FILE="$REPORT_DIR/report_${FIRMWARE_NAME}_$DATE_TAG.md"

# 顏色代碼
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 每次分析時會重置的狀態
PREPROCESS_SUMMARY="未進行額外預處理"
SIGNATURE_SUMMARY="不適用"
SIGNATURE_STATUS="not_applicable"
PE_SECURITY_SUMMARY="不適用"
PE_ASLR=""
PE_DEP=""

#===============================================================================
# 函數定義
#===============================================================================

# 記錄日誌的函數
log() {
  local level="$1"
  local message="$2"
  local color="$NC"
  
  case "$level" in
    "INFO")
      color="$BLUE"
      ;;
    "SUCCESS")
      color="$GREEN"
      ;;
    "WARNING")
      color="$YELLOW"
      ;;
    "ERROR")
      color="$RED"
      ;;
  esac
  
  echo -e "${color}[$(date "+%Y-%m-%d %H:%M:%S")] [$level] $message${NC}" | tee -a "$LOG_FILE"
}

# 檢查命令是否存在
check_command() {
  if ! command -v "$1" &> /dev/null; then
    log "WARNING" "命令 '$1' 未安裝，相關功能將被跳過"
    return 1
  fi
  return 0
}

lowercase_string() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

count_directory_files() {
  find "$1" -type f 2>/dev/null | wc -l | awk '{print $1}'
}

reset_analysis_state() {
  PREPROCESS_SUMMARY="未進行額外預處理"
  SIGNATURE_SUMMARY="不適用"
  SIGNATURE_STATUS="not_applicable"
  PE_SECURITY_SUMMARY="不適用"
  PE_ASLR=""
  PE_DEP=""
  SCAN_TARGET="$FIRMWARE_FILE"
}

# 初始化目錄結構
initialize_directories() {
  log "INFO" "初始化目錄結構..."
  mkdir -p "$WORK_DIR/binwalk-analysis"
  mkdir -p "$WORK_DIR/dependency-inventory"
  mkdir -p "$WORK_DIR/dynamic-analysis"
  mkdir -p "$WORK_DIR/hexdump-analysis"
  mkdir -p "$WORK_DIR/sample-coverage"
  mkdir -p "$WORK_DIR/reverse-engineering-hints"
  mkdir -p "$WORK_DIR/supply-chain-verification"
  mkdir -p "$WORK_DIR/yara-rules"
  mkdir -p "$WORK_DIR/screenshots/ghidra"
  mkdir -p "$WORK_DIR/preprocessed"
  mkdir -p "$LOG_DIR"
  mkdir -p "$REPORT_DIR"
  mkdir -p "$FIRMWARE_SAMPLES"
  log "SUCCESS" "目錄結構初始化完成"
}

# 創建示例韌體
create_sample_firmware() {
  log "INFO" "韌體文件不存在，創建模擬韌體..."
  cat > "$FIRMWARE_FILE" << 'EOF'
#!/bin/bash
echo "This is a simulated firmware"
# Network services
telnetd -p 2323
dropbear -p 22
# Security concerns
cat /etc/shadow
# Hardware interfaces
echo "CAN bus interface initialized"
# Some binary data
echo -e "\x7FELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03"
exit 0
EOF
  log "SUCCESS" "模擬韌體已創建: $FIRMWARE_FILE"
}

# 使用hexdump進行分析
perform_hexdump_analysis() {
  log "INFO" "步驟1：使用hexdump或xxd進行檢查"
  
  local hexdump_dir="$WORK_DIR/hexdump-analysis"
  local base_name=$(basename "$FIRMWARE_FILE")
  local full_dump="$hexdump_dir/${base_name}_full_dump_$DATE_TAG.txt"
  local telnetd_output="$hexdump_dir/${base_name}_telnetd_pattern_$DATE_TAG.txt"
  local security_output="$hexdump_dir/${base_name}_security_patterns_$DATE_TAG.txt"
  
  if [ -d "$SCAN_TARGET" ]; then
    find "$SCAN_TARGET" -type f > "$full_dump"
    grep -R -a -n "telnetd" "$SCAN_TARGET" > "$telnetd_output" || log "INFO" "未發現telnetd模式"
    grep -R -a -n -E "dropbear|/etc/shadow" "$SCAN_TARGET" > "$security_output" || log "INFO" "未發現dropbear或shadow模式"
    log "INFO" "生成提取內容清單: $full_dump"
  else
    # Try hexdump, fallback to xxd
    if command -v hexdump &> /dev/null; then
      hexdump -C "$FIRMWARE_FILE" > "$full_dump"
    elif command -v xxd &> /dev/null; then
      xxd "$FIRMWARE_FILE" > "$full_dump"
    else
      log "ERROR" "找不到 hexdump 或 xxd 工具，跳過此步驟"
      return 1
    fi
    
    log "INFO" "生成完整hexdump: $full_dump"
    
    grep -n "telnetd" "$full_dump" > "$telnetd_output" || log "INFO" "未發現telnetd模式"
    grep -n "dropbear\|shadow" "$full_dump" > "$security_output" || log "INFO" "未發現dropbear或shadow模式"
  fi
  
  if [ -f "$full_dump" ]; then
    # 將最新的分析結果建立軟鏈接
    ln -sf "$full_dump" "$hexdump_dir/full_dump.txt"
    ln -sf "$telnetd_output" "$hexdump_dir/telnetd_pattern.txt"
    ln -sf "$security_output" "$hexdump_dir/security_patterns.txt"
  fi
  
  log "SUCCESS" "hexdump分析完成"
}

# 創建YARA規則
create_yara_rules() {
  log "INFO" "步驟2：創建或更新YARA規則"
  
  local yara_dir="$WORK_DIR/yara-rules"
  
  # 檢查telnetd規則
  if [ ! -f "$yara_dir/telnetd_rule.yar" ]; then
    cat > "$yara_dir/telnetd_rule.yar" << 'EOF'
rule Detect_Telnetd {
    meta:
        description = "檢測韌體中的Telnet服務"
        author = "Dennis Lee"
        date = "2023-04-14"
        severity = "high"
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
}
EOF
    log "INFO" "已創建telnetd檢測規則"
  fi

  # 檢查網絡服務規則
  if [ ! -f "$yara_dir/network_services_rule.yar" ]; then
    cat > "$yara_dir/network_services_rule.yar" << 'EOF'
rule Detect_Network_Services {
    meta:
        description = "檢測韌體中的多種網絡服務"
        author = "Dennis Lee"
        date = "2023-04-14"
        severity = "medium"
    strings:
        $telnet = "telnetd"
        $ssh = "dropbear"
        $shadow = "/etc/shadow"
    condition:
        any of them
}
EOF
    log "INFO" "已創建網絡服務檢測規則"
  fi
  
  log "SUCCESS" "YARA規則已創建"
}

# 運行YARA規則
run_yara_rules() {
  log "INFO" "步驟3：運行YARA規則 (目標: $SCAN_TARGET)"
  
  if ! check_command "yara"; then
    return
  fi

  local yara_dir="$WORK_DIR/yara-rules"
  local base_name=$(basename "$FIRMWARE_FILE")
  
  # 遍歷所有 .yar 檔案並執行掃描
  for rule_file in "$yara_dir"/*.yar; do
    [ -e "$rule_file" ] || continue
    local rule_name=$(basename "$rule_file" .yar)
    local result_file="$yara_dir/${base_name}_${rule_name}_results_$DATE_TAG.txt"
    
    log "INFO" "正在掃描規則: $rule_name"
    : > "$result_file"
    
    if ! yara -r "$rule_file" "$SCAN_TARGET" > "$result_file" 2>/dev/null; then
      log "WARNING" "規則 $rule_name 執行失敗"
    fi
  done
  
  log "SUCCESS" "YARA規則運行完成"
}

# 使用binwalk分析
run_binwalk_analysis() {
  log "INFO" "步驟4：使用binwalk分析 (目標: $SCAN_TARGET)"
  
  if ! check_command "binwalk"; then
    return
  fi

  local binwalk_dir="$WORK_DIR/binwalk-analysis"
  local base_name=$(basename "$FIRMWARE_FILE")
  local result_file="$binwalk_dir/${base_name}_binwalk_results_$DATE_TAG.txt"
  
  # 如果是目錄，則針對目錄中的每個檔案執行
  if [ -d "$SCAN_TARGET" ]; then
    if ! binwalk -r "$SCAN_TARGET" > "$result_file" 2>/dev/null; then
      log "WARNING" "binwalk 無法完成遞迴掃描"
    fi
  else
    if ! binwalk "$SCAN_TARGET" > "$result_file" 2>/dev/null; then
      log "WARNING" "binwalk 無法分析檔案"
    fi
  fi
  
  # 提取文件系統（僅針對單個檔案）
  if [ "$EXTRACT_FILESYSTEM" -eq 1 ] && [ -f "$SCAN_TARGET" ]; then
    log "INFO" "提取文件系統..."
    binwalk -e "$SCAN_TARGET" --run-as=root -C "$binwalk_dir/${base_name}_extracted_$DATE_TAG" || log "WARNING" "無法提取文件系統"
  fi
  
  log "SUCCESS" "binwalk分析完成"
}

generate_dependency_inventory() {
  log "INFO" "步驟5：建立依賴盤點"

  local inventory_dir="$WORK_DIR/dependency-inventory"
  local base_name=$(basename "$FIRMWARE_FILE")
  local inventory_file="$inventory_dir/${base_name}_dependency_inventory_$DATE_TAG.txt"
  local scan_root="$SCAN_TARGET"
  local manifest_tmp
  local dependency_tmp
  local library_tmp
  local reference_tmp
  local manifest_count=0
  local dependency_count=0
  local library_count=0
  local reference_count=0

  manifest_tmp=$(mktemp)
  dependency_tmp=$(mktemp)
  library_tmp=$(mktemp)
  reference_tmp=$(mktemp)

  if [ -d "$scan_root" ]; then
    while IFS= read -r manifest; do
      [ -z "$manifest" ] && continue
      echo "${manifest#$scan_root/}" >> "$manifest_tmp"

      case "$(basename "$manifest")" in
        package.json|composer.json)
          if check_command "python3"; then
            python3 - "$manifest" <<'EOF' >> "$dependency_tmp" 2>/dev/null || true
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="ignore") as fh:
    data = json.load(fh)

for section in ("dependencies", "devDependencies", "require"):
    deps = data.get(section, {})
    if isinstance(deps, dict):
        for name in deps:
            print(name)
EOF
          fi
          ;;
        requirements.txt)
          grep -E -v '^[[:space:]]*($|#)' "$manifest" | sed 's/[<>=!~].*$//' >> "$dependency_tmp" || true
          ;;
        Gemfile)
          grep -E "^[[:space:]]*gem[[:space:]]+['\"]" "$manifest" | sed -E "s/^[[:space:]]*gem[[:space:]]+['\"]([^'\"]+)['\"].*/\1/" >> "$dependency_tmp" || true
          ;;
        go.mod)
          awk '
            /^require[[:space:]]*\($/ { in_block=1; next }
            in_block && /^\)/ { in_block=0; next }
            in_block && NF { print $1; next }
            /^require[[:space:]]+/ { print $2 }
          ' "$manifest" >> "$dependency_tmp" || true
          ;;
        Cargo.toml)
          awk '
            /^\[dependencies\]/ { in_block=1; next }
            /^\[/ && $0 !~ /^\[dependencies\]/ { in_block=0 }
            in_block && /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
              gsub(/[[:space:]]*=.*/, "", $0)
              gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
              print $0
            }
          ' "$manifest" >> "$dependency_tmp" || true
          ;;
      esac
    done < <(find "$scan_root" -type f \( \
      -name "package.json" -o \
      -name "requirements.txt" -o \
      -name "Pipfile" -o \
      -name "pyproject.toml" -o \
      -name "poetry.lock" -o \
      -name "Gemfile" -o \
      -name "go.mod" -o \
      -name "Cargo.toml" -o \
      -name "composer.json" -o \
      -name "pom.xml" -o \
      -name "build.gradle" -o \
      -name "build.gradle.kts" -o \
      -name "*.csproj" -o \
      -name "*.nuspec" \
    \) | sort)

    find "$scan_root" -type f \( \
      -name "*.so" -o -name "*.so.*" -o -name "*.dll" -o -name "*.dylib" -o -name "*.a" -o -name "*.jar" \
    \) | sed "s#^$scan_root/##" | sort -u > "$library_tmp" || true

    if command -v strings >/dev/null 2>&1; then
      while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        strings -a "$candidate" 2>/dev/null | \
          grep -Eo '([A-Za-z0-9._+-]+\.so(\.[0-9]+)*)|([A-Za-z0-9._+-]+\.dll)|([A-Za-z0-9._+-]+\.dylib)' | \
          sort -u | head -n 20 | while IFS= read -r ref; do
            [ -n "$ref" ] && echo "${candidate#$scan_root/} -> $ref" >> "$reference_tmp"
          done || true
      done < <(find "$scan_root" -type f | head -n 40)
    else
      while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        grep -aEo '([A-Za-z0-9._+-]+\.so(\.[0-9]+)*)|([A-Za-z0-9._+-]+\.dll)|([A-Za-z0-9._+-]+\.dylib)' "$candidate" | \
          sort -u | head -n 20 | while IFS= read -r ref; do
            [ -n "$ref" ] && echo "${candidate#$scan_root/} -> $ref" >> "$reference_tmp"
          done || true
      done < <(find "$scan_root" -type f | head -n 20)
    fi
  else
    if [[ "$scan_root" == *.so ]] || [[ "$scan_root" == *.dll ]] || [[ "$scan_root" == *.dylib ]] || [[ "$scan_root" == *.jar ]]; then
      echo "$(basename "$scan_root")" > "$library_tmp"
    fi

    if command -v strings >/dev/null 2>&1; then
      strings -a "$scan_root" 2>/dev/null | \
        grep -Eo '([A-Za-z0-9._+-]+\.so(\.[0-9]+)*)|([A-Za-z0-9._+-]+\.dll)|([A-Za-z0-9._+-]+\.dylib)' | \
        sort -u | head -n 20 | while IFS= read -r ref; do
          [ -n "$ref" ] && echo "$(basename "$scan_root") -> $ref" >> "$reference_tmp"
        done || true
    else
      grep -aEo '([A-Za-z0-9._+-]+\.so(\.[0-9]+)*)|([A-Za-z0-9._+-]+\.dll)|([A-Za-z0-9._+-]+\.dylib)' "$scan_root" | \
        sort -u | head -n 20 | while IFS= read -r ref; do
          [ -n "$ref" ] && echo "$(basename "$scan_root") -> $ref" >> "$reference_tmp"
        done || true
    fi
  fi

  sort -u "$manifest_tmp" -o "$manifest_tmp"
  sort -u "$dependency_tmp" -o "$dependency_tmp"
  sort -u "$library_tmp" -o "$library_tmp"
  sort -u "$reference_tmp" -o "$reference_tmp"

  manifest_count=$(grep -c . "$manifest_tmp" 2>/dev/null || true)
  dependency_count=$(grep -c . "$dependency_tmp" 2>/dev/null || true)
  library_count=$(grep -c . "$library_tmp" 2>/dev/null || true)
  reference_count=$(grep -c . "$reference_tmp" 2>/dev/null || true)

  cat > "$inventory_file" << EOF
scan_root=$scan_root
manifest_files=$manifest_count
declared_dependencies=$dependency_count
bundled_libraries=$library_count
binary_library_references=$reference_count

## Manifest Files
EOF

  if [ "$manifest_count" -gt 0 ]; then
    sed 's/^/MANIFEST /' "$manifest_tmp" >> "$inventory_file"
  else
    echo "MANIFEST none" >> "$inventory_file"
  fi

  cat >> "$inventory_file" << 'EOF'

## Declared Dependencies
EOF

  if [ "$dependency_count" -gt 0 ]; then
    sed 's/^/DEPENDENCY /' "$dependency_tmp" | head -n 200 >> "$inventory_file"
  else
    echo "DEPENDENCY none" >> "$inventory_file"
  fi

  cat >> "$inventory_file" << 'EOF'

## Bundled Libraries
EOF

  if [ "$library_count" -gt 0 ]; then
    sed 's/^/LIBRARY /' "$library_tmp" | head -n 200 >> "$inventory_file"
  else
    echo "LIBRARY none" >> "$inventory_file"
  fi

  cat >> "$inventory_file" << 'EOF'

## Binary References
EOF

  if [ "$reference_count" -gt 0 ]; then
    sed 's/^/BINARY_REF /' "$reference_tmp" | head -n 200 >> "$inventory_file"
  else
    echo "BINARY_REF none" >> "$inventory_file"
  fi

  rm -f "$manifest_tmp" "$dependency_tmp" "$library_tmp" "$reference_tmp"
  log "SUCCESS" "依賴盤點已生成: $inventory_file"
}

perform_dynamic_analysis() {
  log "INFO" "步驟6：執行動態分析預檢"

  local dynamic_dir="$WORK_DIR/dynamic-analysis"
  local base_name=$(basename "$FIRMWARE_FILE")
  local dynamic_file="$dynamic_dir/${base_name}_dynamic_analysis_$DATE_TAG.txt"
  local scan_root="$SCAN_TARGET"
  local service_tmp
  local indicator_tmp
  local probe_tmp
  local service_count=0
  local script_count=0
  local indicator_count=0
  local safe_probe_count=0

  service_tmp=$(mktemp)
  indicator_tmp=$(mktemp)
  probe_tmp=$(mktemp)

  if [ -d "$scan_root" ]; then
    while IFS= read -r candidate; do
      [ -z "$candidate" ] && continue
      echo "${candidate#$scan_root/}" >> "$service_tmp"

      grep -I -n -E 'ExecStart|ExecStartPre|ExecStartPost|ProgramArguments|Program|RunAtLoad|KeepAlive|systemctl|launchctl|service[[:space:]]+[A-Za-z0-9_.-]+[[:space:]]+start|telnetd|dropbear|sshd|httpd|nginx|iptables|ip[[:space:]]+link|ifconfig|modprobe|insmod|curl|wget|nc[[:space:]-]' "$candidate" | \
        head -n 10 | sed "s#^#${candidate#$scan_root/}:#" >> "$indicator_tmp" || true
    done < <(find "$scan_root" -type f \( \
      -name "*.service" -o \
      -name "*.plist" -o \
      -name "rc.local" -o \
      -path "*/init.d/*" -o \
      -name "*.desktop" -o \
      -name "entrypoint*" -o \
      -name "launch*" -o \
      -name "start*" -o \
      -name "run*" \
    \) | sort | head -n 50)

    while IFS= read -r script_candidate; do
      [ -z "$script_candidate" ] && continue
      script_count=$((script_count + 1))

      case "$script_candidate" in
        *.sh)
          if sh -n "$script_candidate" >/dev/null 2>&1; then
            echo "PROBE ${script_candidate#$scan_root/}: sh -n ok" >> "$probe_tmp"
          else
            echo "PROBE ${script_candidate#$scan_root/}: sh -n failed" >> "$probe_tmp"
          fi
          safe_probe_count=$((safe_probe_count + 1))
          ;;
        *.py)
          if check_command "python3"; then
            if python3 -m py_compile "$script_candidate" >/dev/null 2>&1; then
              echo "PROBE ${script_candidate#$scan_root/}: py_compile ok" >> "$probe_tmp"
            else
              echo "PROBE ${script_candidate#$scan_root/}: py_compile failed" >> "$probe_tmp"
            fi
            safe_probe_count=$((safe_probe_count + 1))
          fi
          ;;
        *.js)
          if check_command "node"; then
            if node --check "$script_candidate" >/dev/null 2>&1; then
              echo "PROBE ${script_candidate#$scan_root/}: node --check ok" >> "$probe_tmp"
            else
              echo "PROBE ${script_candidate#$scan_root/}: node --check failed" >> "$probe_tmp"
            fi
            safe_probe_count=$((safe_probe_count + 1))
          fi
          ;;
      esac

      grep -I -n -E 'telnetd|dropbear|sshd|httpd|nginx|systemctl|launchctl|service[[:space:]]+[A-Za-z0-9_.-]+[[:space:]]+start|curl|wget|nc[[:space:]-]|iptables|ip[[:space:]]+link|ifconfig|modprobe|insmod' "$script_candidate" | \
        head -n 10 | sed "s#^#${script_candidate#$scan_root/}:#" >> "$indicator_tmp" || true
    done < <(find "$scan_root" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.js" \) | sort | head -n 40)
  fi

  sort -u "$service_tmp" -o "$service_tmp"
  sort -u "$indicator_tmp" -o "$indicator_tmp"
  sort -u "$probe_tmp" -o "$probe_tmp"

  service_count=$(grep -c . "$service_tmp" 2>/dev/null || true)
  indicator_count=$(grep -c . "$indicator_tmp" 2>/dev/null || true)

  cat > "$dynamic_file" << EOF
scan_root=$scan_root
service_files=$service_count
script_candidates=$script_count
runtime_indicators=$indicator_count
safe_probes=$safe_probe_count

## Service And Launch Candidates
EOF

  if [ "$service_count" -gt 0 ]; then
    sed 's/^/SERVICE /' "$service_tmp" >> "$dynamic_file"
  else
    echo "SERVICE none" >> "$dynamic_file"
  fi

  cat >> "$dynamic_file" << 'EOF'

## Runtime Indicators
EOF

  if [ "$indicator_count" -gt 0 ]; then
    sed 's/^/INDICATOR /' "$indicator_tmp" | head -n 200 >> "$dynamic_file"
  else
    echo "INDICATOR none" >> "$dynamic_file"
  fi

  cat >> "$dynamic_file" << 'EOF'

## Safe Probes
EOF

  if [ "$safe_probe_count" -gt 0 ]; then
    cat "$probe_tmp" >> "$dynamic_file"
  else
    echo "PROBE none" >> "$dynamic_file"
  fi

  rm -f "$service_tmp" "$indicator_tmp" "$probe_tmp"
  log "SUCCESS" "動態分析預檢已生成: $dynamic_file"
}

generate_sample_coverage() {
  log "INFO" "步驟7：建立樣本覆蓋摘要"

  local coverage_dir="$WORK_DIR/sample-coverage"
  local base_name=$(basename "$FIRMWARE_FILE")
  local coverage_file="$coverage_dir/${base_name}_sample_coverage_$DATE_TAG.txt"
  local scan_root="$SCAN_TARGET"

  if check_command "python3"; then
    python3 - "$scan_root" "$coverage_file" <<'EOF'
from collections import Counter
import os
import sys

scan_root = sys.argv[1]
output_path = sys.argv[2]

script_exts = {".sh", ".py", ".pl", ".rb", ".js", ".bat", ".cmd", ".ps1", ".lua"}
archive_exts = {".zip", ".7z", ".tar", ".gz", ".xz", ".bz2", ".tgz", ".iso", ".dmg", ".pkg", ".msi"}
config_exts = {
    ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml", ".plist", ".toml",
    ".service", ".env", ".properties", ".reg"
}
library_exts = {".so", ".dll", ".dylib", ".a", ".jar"}
document_exts = {".txt", ".md", ".pdf", ".rtf", ".doc", ".docx", ".html", ".htm"}
certificate_exts = {".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx", ".key"}
binary_exts = {".bin", ".elf", ".exe", ".out", ".apk", ".app", ".run"} | library_exts
service_tokens = ("service", "launch", "startup", "start", "run", "daemon", "agent", "init", "entrypoint")
update_tokens = ("update", "upgrade", "installer", "install", "flash", "recovery", "firmware", "driver")


def iter_files(root):
    if os.path.isdir(root):
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                yield os.path.relpath(path, root), path
    elif os.path.exists(root):
        yield os.path.basename(root), root


def has_executable_hint(path, ext):
    if ext in binary_exts:
        return True
    try:
        return os.access(path, os.X_OK) and not os.path.isdir(path)
    except OSError:
        return False


files = []
for rel_path, full_path in iter_files(scan_root):
    try:
        size = os.path.getsize(full_path)
    except OSError:
        size = 0
    files.append((rel_path, full_path, size))

dir_count = 0
if os.path.isdir(scan_root):
    for _dirpath, dirnames, _filenames in os.walk(scan_root):
        dir_count += len(dirnames)

counts = Counter()
ext_counter = Counter()
largest = []
interesting = []

for rel_path, full_path, size in files:
    lower_rel = rel_path.lower()
    ext = os.path.splitext(lower_rel)[1] or "<noext>"
    ext_counter[ext] += 1
    largest.append((size, rel_path))

    reasons = []
    if has_executable_hint(full_path, ext):
      counts["executables"] += 1
      reasons.append("binary-or-executable")
    if ext in script_exts:
      counts["scripts"] += 1
      reasons.append("script")
    if ext in archive_exts:
      counts["archives"] += 1
      reasons.append("archive")
    if ext in config_exts:
      counts["configs"] += 1
      reasons.append("config")
    if ext in library_exts:
      counts["libraries"] += 1
      reasons.append("library")
    if ext in document_exts:
      counts["documents"] += 1
    if ext in certificate_exts:
      counts["certificates"] += 1
      reasons.append("certificate")

    if any(token in lower_rel for token in service_tokens):
      reasons.append("startup-or-service")
    if any(token in lower_rel for token in update_tokens):
      reasons.append("updater-or-recovery")

    if reasons:
      score = len(set(reasons))
      if size >= 1024 * 1024:
        score += 1
      interesting.append((score, size, rel_path, ", ".join(sorted(set(reasons)))))

largest.sort(key=lambda item: (-item[0], item[1]))
interesting.sort(key=lambda item: (-item[0], -item[1], item[2]))

with open(output_path, "w", encoding="utf-8") as fh:
    print(f"scan_root={scan_root}", file=fh)
    print(f"mode={'directory' if os.path.isdir(scan_root) else 'file'}", file=fh)
    print(f"total_files={len(files)}", file=fh)
    print(f"total_directories={dir_count}", file=fh)
    print(f"executables={counts['executables']}", file=fh)
    print(f"scripts={counts['scripts']}", file=fh)
    print(f"archives={counts['archives']}", file=fh)
    print(f"configs={counts['configs']}", file=fh)
    print(f"libraries={counts['libraries']}", file=fh)
    print(f"documents={counts['documents']}", file=fh)
    print(f"certificates={counts['certificates']}", file=fh)
    print(f"interesting_candidates={min(len(interesting), 15)}", file=fh)

    print("\n## Extension Breakdown", file=fh)
    if ext_counter:
        for ext, count in ext_counter.most_common(12):
            print(f"EXT {ext} {count}", file=fh)
    else:
        print("EXT none 0", file=fh)

    print("\n## Largest Files", file=fh)
    if largest:
        for size, rel_path in largest[:10]:
            print(f"LARGEST {rel_path} | {size} bytes", file=fh)
    else:
        print("LARGEST none", file=fh)

    print("\n## Interesting Candidates", file=fh)
    if interesting:
        for _score, size, rel_path, reason in interesting[:15]:
            print(f"CANDIDATE {rel_path} | {reason} | {size} bytes", file=fh)
    else:
        print("CANDIDATE none", file=fh)
EOF
  else
    cat > "$coverage_file" << EOF
scan_root=$scan_root
mode=unavailable
total_files=0
total_directories=0
executables=0
scripts=0
archives=0
configs=0
libraries=0
documents=0
certificates=0
interesting_candidates=0

## Extension Breakdown
EXT none 0

## Largest Files
LARGEST none

## Interesting Candidates
CANDIDATE none
EOF
  fi

  log "SUCCESS" "樣本覆蓋摘要已生成: $coverage_file"
}

generate_reverse_engineering_hints() {
  log "INFO" "步驟8：建立人工逆向輔助摘要"

  local reverse_dir="$WORK_DIR/reverse-engineering-hints"
  local base_name=$(basename "$FIRMWARE_FILE")
  local reverse_file="$reverse_dir/${base_name}_reverse_hints_$DATE_TAG.txt"
  local scan_root="$SCAN_TARGET"

  if check_command "python3"; then
    python3 - "$scan_root" "$reverse_file" <<'EOF'
import os
import re
import sys

scan_root = sys.argv[1]
output_path = sys.argv[2]

binary_exts = {".exe", ".dll", ".so", ".dylib", ".a", ".jar", ".bin", ".elf", ".out", ".apk", ".app", ".run"}
script_exts = {".sh", ".py", ".pl", ".rb", ".js", ".bat", ".cmd", ".ps1", ".lua"}
text_hint_exts = script_exts | {".json", ".xml", ".plist", ".txt", ".md", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".toml", ".html", ".htm"}
service_tokens = ("service", "launch", "startup", "start", "run", "daemon", "agent", "init", "entrypoint")
update_tokens = ("update", "upgrade", "installer", "install", "flash", "recovery", "firmware", "driver")
url_pattern = re.compile(r"https?://(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}[^\\s\"'<>]*")


def iter_files(root):
    if os.path.isdir(root):
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                yield os.path.relpath(path, root), path
    elif os.path.exists(root):
        yield os.path.basename(root), root


def is_executable(path, ext):
    if ext in binary_exts:
        return True
    try:
        return os.access(path, os.X_OK) and not os.path.isdir(path)
    except OSError:
        return False


candidates = []
service_count = 0
binary_count = 0
script_count = 0
url_hints = []
seen_urls = set()

for rel_path, full_path in iter_files(scan_root):
    lower_rel = rel_path.lower()
    ext = os.path.splitext(lower_rel)[1]
    size = 0
    try:
        size = os.path.getsize(full_path)
    except OSError:
        pass

    reasons = []
    if any(token in lower_rel for token in service_tokens):
        reasons.append("startup-hook")
        service_count += 1
    if is_executable(full_path, ext):
        reasons.append("binary-or-executable")
        binary_count += 1
    if ext in script_exts:
        reasons.append("script")
        script_count += 1
    if any(token in lower_rel for token in update_tokens):
        reasons.append("updater-recovery")

    if reasons:
        score = len(set(reasons))
        if size >= 1024 * 1024:
            score += 1
        candidates.append((score, size, rel_path, ", ".join(sorted(set(reasons)))))

    if len(url_hints) < 15 and (reasons or ext in text_hint_exts):
        try:
            with open(full_path, "rb") as fh:
                blob = fh.read(256 * 1024).decode("utf-8", "ignore")
        except OSError:
            blob = ""
        for match in url_pattern.findall(blob):
            cleaned = match.rstrip(").,;\"'")
            if cleaned and cleaned not in seen_urls:
                seen_urls.add(cleaned)
                url_hints.append((rel_path, cleaned))
            if len(url_hints) >= 15:
                break

candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))

with open(output_path, "w", encoding="utf-8") as fh:
    print(f"scan_root={scan_root}", file=fh)
    print(f"candidate_targets={min(len(candidates), 20)}", file=fh)
    print(f"service_targets={service_count}", file=fh)
    print(f"binary_targets={binary_count}", file=fh)
    print(f"script_targets={script_count}", file=fh)
    print(f"url_hints={len(url_hints)}", file=fh)

    print("\n## Candidate Targets", file=fh)
    if candidates:
        for _score, size, rel_path, reason in candidates[:20]:
            print(f"CANDIDATE {rel_path} | {reason} | {size} bytes", file=fh)
    else:
        print("CANDIDATE none", file=fh)

    print("\n## URL Hints", file=fh)
    if url_hints:
        for rel_path, url in url_hints:
            print(f"URL {rel_path} -> {url}", file=fh)
    else:
        print("URL none", file=fh)
EOF
  else
    cat > "$reverse_file" << EOF
scan_root=$scan_root
candidate_targets=0
service_targets=0
binary_targets=0
script_targets=0
url_hints=0

## Candidate Targets
CANDIDATE none

## URL Hints
URL none
EOF
  fi

  log "SUCCESS" "人工逆向輔助摘要已生成: $reverse_file"
}

verify_supply_chain_sources() {
  log "INFO" "步驟9：建立供應鏈來源檢核摘要"

  local supply_dir="$WORK_DIR/supply-chain-verification"
  local base_name=$(basename "$FIRMWARE_FILE")
  local supply_file="$supply_dir/${base_name}_supply_chain_$DATE_TAG.txt"
  local scan_root="$SCAN_TARGET"

  if check_command "python3"; then
    SIGNATURE_STATUS_ENV="$SIGNATURE_STATUS" \
    SIGNATURE_SUMMARY_ENV="$SIGNATURE_SUMMARY" \
    FIRMWARE_FILE_ENV="$FIRMWARE_FILE" \
    SCAN_TARGET_ENV="$scan_root" \
    python3 - "$supply_file" <<'EOF'
from collections import OrderedDict
import hashlib
import json
import os
import plistlib
import re
import sys

output_path = sys.argv[1]
firmware_file = os.environ.get("FIRMWARE_FILE_ENV", "")
scan_root = os.environ.get("SCAN_TARGET_ENV", "")
signature_status = os.environ.get("SIGNATURE_STATUS_ENV", "not_applicable")
signature_summary = os.environ.get("SIGNATURE_SUMMARY_ENV", "不適用")

url_pattern = re.compile(r"https?://(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}[^\\s\"'<>]*")
cert_exts = {".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx", ".key"}
binary_exts = {".exe", ".dll", ".so", ".dylib", ".a", ".jar", ".bin", ".elf", ".out", ".apk", ".app", ".run"}
text_hint_exts = {
    ".json", ".xml", ".plist", ".txt", ".md", ".cfg", ".conf", ".ini",
    ".yaml", ".yml", ".toml", ".html", ".htm", ".sh", ".py", ".js",
    ".ps1", ".bat", ".cmd", ".rb", ".pl", ".lua"
}
manifest_names = {"package.json", "composer.json", "Cargo.toml", "go.mod", "Info.plist", "pyproject.toml"}
update_tokens = ("update", "upgrade", "installer", "install", "flash", "recovery", "driver", "agent")


def sha256_file(path):
    if not path or not os.path.isfile(path):
        return "unavailable"
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(root):
    if os.path.isdir(root):
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                yield os.path.relpath(path, root), path
    elif os.path.isfile(root):
        yield os.path.basename(root), root


def add_manifest_hint(rel_path, hint, manifests):
    if hint:
        manifests.append(f"{rel_path} | {hint}")


publisher_hints = []
manifest_hints = []
registry_hints = []
url_refs = []
domain_refs = []
cert_files = []
update_hints = []
seen_urls = OrderedDict()
seen_domains = OrderedDict()


for rel_path, full_path in iter_files(scan_root):
    lower_rel = rel_path.lower()
    ext = os.path.splitext(lower_rel)[1]
    base_name = os.path.basename(full_path)

    if ext in cert_exts:
        cert_files.append(rel_path)

    if any(token in lower_rel for token in update_tokens):
        update_hints.append(rel_path)

    if base_name in manifest_names:
        try:
            if base_name == "package.json":
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
                name = data.get("name")
                version = data.get("version")
                repository = data.get("repository")
                homepage = data.get("homepage")
                registry_hints.append("npm")
                fields = []
                if name:
                    fields.append(f"name={name}")
                if version:
                    fields.append(f"version={version}")
                if isinstance(repository, str):
                    fields.append(f"repository={repository}")
                elif isinstance(repository, dict) and repository.get("url"):
                    fields.append(f"repository={repository['url']}")
                if homepage:
                    fields.append(f"homepage={homepage}")
                add_manifest_hint(rel_path, " | ".join(fields), manifest_hints)
            elif base_name == "composer.json":
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
                registry_hints.append("packagist")
                fields = []
                for key in ("name", "version", "homepage"):
                    value = data.get(key)
                    if value:
                        fields.append(f"{key}={value}")
                add_manifest_hint(rel_path, " | ".join(fields), manifest_hints)
            elif base_name == "Cargo.toml":
                registry_hints.append("crates.io")
                fields = []
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        stripped = line.strip()
                        if stripped.startswith(("name =", "version =", "repository =", "homepage =")):
                            fields.append(stripped.replace('"', ""))
                add_manifest_hint(rel_path, " | ".join(fields[:4]), manifest_hints)
            elif base_name == "go.mod":
                registry_hints.append("go-mod")
                module_line = ""
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.startswith("module "):
                            module_line = line.strip()
                            break
                add_manifest_hint(rel_path, module_line, manifest_hints)
            elif base_name == "pyproject.toml":
                registry_hints.append("pypi")
                add_manifest_hint(rel_path, "python build metadata present", manifest_hints)
            elif base_name == "Info.plist":
                with open(full_path, "rb") as fh:
                    data = plistlib.load(fh)
                fields = []
                for key in ("CFBundleIdentifier", "CFBundleName", "CFBundleVersion", "SUFeedURL"):
                    value = data.get(key)
                    if value:
                        fields.append(f"{key}={value}")
                add_manifest_hint(rel_path, " | ".join(fields), manifest_hints)
        except Exception:
            pass

    if base_name in manifest_names or ext in text_hint_exts or ext in binary_exts or any(token in lower_rel for token in update_tokens):
        try:
            with open(full_path, "rb") as fh:
                blob = fh.read(256 * 1024).decode("utf-8", "ignore")
        except OSError:
            blob = ""

        for match in url_pattern.findall(blob):
            cleaned = match.rstrip(").,;\"'")
            if cleaned and cleaned not in seen_urls:
                seen_urls[cleaned] = rel_path
            if len(seen_urls) >= 20:
                break


for url, rel_path in seen_urls.items():
    url_refs.append(f"{rel_path} -> {url}")
    try:
        domain = re.sub(r'^https?://', "", url).split("/")[0]
    except Exception:
        domain = ""
    if domain and domain not in seen_domains:
        seen_domains[domain] = True

for domain in seen_domains.keys():
    domain_refs.append(domain)

if firmware_file.lower().endswith((".exe", ".dll")):
    try:
        import pefile
        pe = pefile.PE(firmware_file)
        if hasattr(pe, "FileInfo"):
            for entry in pe.FileInfo:
                for table in getattr(entry, "StringTable", []):
                    for key, value in table.entries.items():
                        if key in {"CompanyName", "ProductName", "OriginalFilename", "FileDescription"}:
                            publisher_hints.append(f"{key}={value}")
    except Exception:
        pass

registry_hints = list(OrderedDict.fromkeys(registry_hints))
publisher_hints = list(OrderedDict.fromkeys(publisher_hints))
manifest_hints = manifest_hints[:15]
url_refs = url_refs[:15]
domain_refs = domain_refs[:15]
cert_files = cert_files[:15]
update_hints = list(OrderedDict.fromkeys(update_hints))[:15]

with open(output_path, "w", encoding="utf-8") as fh:
    print(f"source_file={firmware_file}", file=fh)
    print(f"scan_target={scan_root}", file=fh)
    print(f"source_sha256={sha256_file(firmware_file)}", file=fh)
    print(f"scan_target_sha256={sha256_file(scan_root)}", file=fh)
    print(f"signature_status={signature_status}", file=fh)
    print(f"signature_summary={signature_summary}", file=fh)
    print(f"certificate_files={len(cert_files)}", file=fh)
    print(f"url_references={len(url_refs)}", file=fh)
    print(f"domain_references={len(domain_refs)}", file=fh)
    print(f"manifest_provenance_entries={len(manifest_hints)}", file=fh)
    print(f"publisher_hints={len(publisher_hints)}", file=fh)
    print(f"registry_hints={len(registry_hints)}", file=fh)
    print(f"update_channel_hints={len(update_hints)}", file=fh)

    print("\n## Publisher Hints", file=fh)
    if publisher_hints:
        for hint in publisher_hints[:10]:
            print(f"PUBLISHER {hint}", file=fh)
    else:
        print("PUBLISHER none", file=fh)

    print("\n## Registry Hints", file=fh)
    if registry_hints:
        for hint in registry_hints:
            print(f"REGISTRY {hint}", file=fh)
    else:
        print("REGISTRY none", file=fh)

    print("\n## URL References", file=fh)
    if url_refs:
        for item in url_refs:
            print(f"URL {item}", file=fh)
    else:
        print("URL none", file=fh)

    print("\n## Domain References", file=fh)
    if domain_refs:
        for item in domain_refs:
            print(f"DOMAIN {item}", file=fh)
    else:
        print("DOMAIN none", file=fh)

    print("\n## Certificate Files", file=fh)
    if cert_files:
        for item in cert_files:
            print(f"CERT {item}", file=fh)
    else:
        print("CERT none", file=fh)

    print("\n## Manifest Provenance", file=fh)
    if manifest_hints:
        for item in manifest_hints:
            print(f"MANIFEST {item}", file=fh)
    else:
        print("MANIFEST none", file=fh)

    print("\n## Update Channel Hints", file=fh)
    if update_hints:
        for item in update_hints:
            print(f"UPDATE {item}", file=fh)
    else:
        print("UPDATE none", file=fh)
EOF
  else
    cat > "$supply_file" << EOF
source_file=$FIRMWARE_FILE
scan_target=$scan_root
source_sha256=unavailable
scan_target_sha256=unavailable
signature_status=$SIGNATURE_STATUS
signature_summary=$SIGNATURE_SUMMARY
certificate_files=0
url_references=0
domain_references=0
manifest_provenance_entries=0
publisher_hints=0
registry_hints=0
update_channel_hints=0

## Publisher Hints
PUBLISHER none

## Registry Hints
REGISTRY none

## URL References
URL none

## Domain References
DOMAIN none

## Certificate Files
CERT none

## Manifest Provenance
MANIFEST none

## Update Channel Hints
UPDATE none
EOF
  fi

  log "SUCCESS" "供應鏈來源檢核摘要已生成: $supply_file"
}

# 創建CAN協議日誌
create_can_log() {
  log "INFO" "附加資料：創建或更新模擬的CAN協議日誌"
  
  if [ ! -f "$WORK_DIR/can-log-demo.txt" ]; then
    cat > "$WORK_DIR/can-log-demo.txt" << 'EOF'
# 模擬CAN協議日誌
時間戳        ID      DLC     資料                          說明
1621234567    0x7DF   8       02 01 0C 00 00 00 00 00       請求引擎轉速
1621234568    0x7E8   8       03 41 0C FF 00 00 00 00       引擎轉速回應
1621234569    0x7DF   8       02 01 0D 00 00 00 00 00       請求車速
1621234570    0x7E8   8       03 41 0D 45 00 00 00 00       車速回應 (69 km/h)
1621234571    0x7DF   8       02 01 05 00 00 00 00 00       請求冷卻液溫度
1621234572    0x7E8   8       03 41 05 7B 00 00 00 00       冷卻液溫度回應 (83°C)
EOF
    log "SUCCESS" "CAN協議日誌已創建"
  fi
}

# 創建Ghidra分析筆記
create_ghidra_notes() {
  log "INFO" "附加資料：更新 Ghidra 分析筆記模板"
  
  cat > "$WORK_DIR/ghidra-notes.md" << 'EOF'
# Ghidra 分析筆記模板

此檔作為人工逆向的工作紀錄入口，避免再填入固定示範結論。

## 建議輸入
- `reverse-engineering-hints/`：優先匯入列出的候選可執行檔、啟動項與更新程式
- `sample-coverage/`：查看最大檔案與尚未展開的封裝內容
- `supply-chain-verification/`：比對雜湊、簽章、來源 URL 與發行者資訊

## 建議檢查項目
- 入口點、初始化流程、服務註冊與更新機制
- 網路請求、版本檢查、憑證處理與簽章驗證路徑
- 韌體寫入、恢復模式、權限提升與持久化邏輯

## 記錄欄位
- 分析檔案：
- 入口函數/主要模組：
- 關鍵字串/URL：
- 可疑 API 或系統呼叫：
- 後續驗證動作：
EOF
  log "SUCCESS" "Ghidra分析筆記模板已更新"
}

# 根據規則名稱獲取分類
get_yara_category() {
  local rule_name="$1"
  case "$rule_name" in
    telnetd_rule|network_services_rule)
      echo "網路服務 (Network Services)"
      ;;
    APT_Equation|spy_equation_fiveeyes|apt_venom_linux_rootkit|lojax)
      echo "韌體持久化與根檢測 (Firmware Persistence & Rootkits)"
      ;;
    apt_waterbear|apt_plead_downloader|gen_tscookie_rat|apt_blackenergy|apt_fancybear_dnc|apt_blacktech|apt_volt_typhoon|agent_tesla)
      echo "高級持續性威脅工具 (APT Toolsets)"
      ;;
    apt_vpnfilter|Linux_Trojan_Mirai)
      echo "IoT 與路由器惡意軟體 (IoT & Router Malware)"
      ;;
    Windows_Trojan_Generic|Linux_Trojan_Generic|macOS_Trojan_Generic|Windows_Trojan_Trickbot|Windows_PUP_Generic)
      echo "通用惡意軟體與特洛伊木馬 (General Malware & Trojans)"
      ;;
    *)
      echo "其他檢測規則 (Other Detections)"
      ;;
  esac
}

# 創建安全分析報告
create_security_report() {
  log "INFO" "步驟10：創建安全分析報告"

  local base_name
  base_name=$(basename "$FIRMWARE_FILE")
  local dependency_dir="$WORK_DIR/dependency-inventory"
  local dynamic_dir="$WORK_DIR/dynamic-analysis"
  local coverage_dir="$WORK_DIR/sample-coverage"
  local reverse_dir="$WORK_DIR/reverse-engineering-hints"
  local supply_dir="$WORK_DIR/supply-chain-verification"
  local hexdump_dir="$WORK_DIR/hexdump-analysis"
  local yara_dir="$WORK_DIR/yara-rules"
  local binwalk_dir="$WORK_DIR/binwalk-analysis"
  local dependency_file="$dependency_dir/${base_name}_dependency_inventory_$DATE_TAG.txt"
  local dynamic_file="$dynamic_dir/${base_name}_dynamic_analysis_$DATE_TAG.txt"
  local coverage_file="$coverage_dir/${base_name}_sample_coverage_$DATE_TAG.txt"
  local reverse_file="$reverse_dir/${base_name}_reverse_hints_$DATE_TAG.txt"
  local supply_file="$supply_dir/${base_name}_supply_chain_$DATE_TAG.txt"
  local telnetd_pattern_file="$hexdump_dir/${base_name}_telnetd_pattern_$DATE_TAG.txt"
  local security_pattern_file="$hexdump_dir/${base_name}_security_patterns_$DATE_TAG.txt"
  local binwalk_file="$binwalk_dir/${base_name}_binwalk_results_$DATE_TAG.txt"
  local file_size
  file_size="$(du -h "$FIRMWARE_FILE" | cut -f1)"
  local file_type="未知"
  local scan_target_description="原始檔案"
  local evidence_count=0
  local risk_count=0
  local recommendation_count=0
  
  # YARA 命中跟蹤
  local YARA_HITS_LIST=""
  local total_yara_hits=0
  local YARA_TOOL_MISSING=0
  if ! command -v yara &> /dev/null; then
    YARA_TOOL_MISSING=1
  fi

  local telnetd_found=0
  local dropbear_found=0
  local shadow_found=0
  local telnetd_example=""
  local dropbear_example=""
  local shadow_example=""
  local binwalk_excerpt=""
  local dynamic_service_count=0
  local dynamic_indicator_count=0
  local dynamic_probe_count=0
  local dependency_manifest_count=0
  local dependency_declared_count=0
  local dependency_library_count=0
  local dependency_reference_count=0
  local coverage_total_files=0
  local coverage_total_directories=0
  local coverage_interesting_count=0
  local reverse_candidate_count=0
  local reverse_service_count=0
  local reverse_binary_count=0
  local reverse_script_count=0
  local reverse_url_count=0
  local supply_source_sha="unavailable"
  local supply_signature_status="not_applicable"
  local supply_signature_summary="不適用"
  local supply_certificate_count=0
  local supply_url_count=0
  local supply_domain_count=0
  local supply_manifest_count=0
  local supply_publisher_count=0
  local supply_registry_count=0
  local supply_update_count=0
  local dynamic_indicator_excerpt=""
  local dependency_manifest_excerpt=""
  local dependency_declared_excerpt=""
  local coverage_candidate_excerpt=""
  local reverse_candidate_excerpt=""
  local reverse_url_excerpt=""
  local supply_publisher_excerpt=""
  local supply_manifest_excerpt=""
  local supply_url_excerpt=""

  if check_command "file"; then
    file_type=$(file -b "$FIRMWARE_FILE" 2>/dev/null || echo "未知")
  fi

  if [ -d "$SCAN_TARGET" ]; then
    scan_target_description="提取後目錄 $(basename "$SCAN_TARGET")，包含 $(count_directory_files "$SCAN_TARGET") 個檔案"
  elif [ "$SCAN_TARGET" != "$FIRMWARE_FILE" ]; then
    local scan_target_type="未知"
    if check_command "file"; then
      scan_target_type=$(file -b "$SCAN_TARGET" 2>/dev/null || echo "未知")
    fi
    scan_target_description="轉換後檔案 $(basename "$SCAN_TARGET") (${scan_target_type})"
  fi

  if [ -s "$telnetd_pattern_file" ] && grep -q "telnetd" "$telnetd_pattern_file" 2>/dev/null; then
    telnetd_found=1
    telnetd_example=$(head -n 1 "$telnetd_pattern_file" | tr -d '\r')
  fi

  if [ -s "$security_pattern_file" ] && grep -q "dropbear" "$security_pattern_file" 2>/dev/null; then
    dropbear_found=1
    dropbear_example=$(grep "dropbear" "$security_pattern_file" | head -n 1 | tr -d '\r')
  fi

  if [ -s "$security_pattern_file" ] && grep -q "shadow" "$security_pattern_file" 2>/dev/null; then
    shadow_found=1
    shadow_example=$(grep "shadow" "$security_pattern_file" | head -n 1 | tr -d '\r')
  fi

  # 收集 YARA 命中資訊
  for result_file in "$yara_dir/${base_name}"_*_results_"$DATE_TAG".txt; do
    [ -e "$result_file" ] || continue
    if [ -s "$result_file" ]; then
      local rule_filename=$(basename "$result_file" "_results_$DATE_TAG.txt")
      rule_filename=${rule_filename#${base_name}_}
      local hits=$(grep -v '^$' "$result_file" | wc -l | awk '{print $1}')
      if [ "$hits" -gt 0 ]; then
        YARA_HITS_LIST="${YARA_HITS_LIST}${rule_filename}|${hits}
"
        total_yara_hits=$((total_yara_hits + hits))
      fi
    fi
  done

  if [ -f "$binwalk_file" ]; then
    binwalk_excerpt=$(grep -v '^[[:space:]]*$' "$binwalk_file" | head -n 8 || true)
  fi

  if [ -f "$dynamic_file" ]; then
    dynamic_service_count=$(grep '^service_files=' "$dynamic_file" | cut -d= -f2 || true)
    dynamic_indicator_count=$(grep '^runtime_indicators=' "$dynamic_file" | cut -d= -f2 || true)
    dynamic_probe_count=$(grep '^safe_probes=' "$dynamic_file" | cut -d= -f2 || true)
    dynamic_indicator_excerpt=$(grep '^INDICATOR ' "$dynamic_file" | sed 's/^INDICATOR //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
  fi

  if [ -f "$dependency_file" ]; then
    dependency_manifest_count=$(grep '^manifest_files=' "$dependency_file" | cut -d= -f2 || true)
    dependency_declared_count=$(grep '^declared_dependencies=' "$dependency_file" | cut -d= -f2 || true)
    dependency_library_count=$(grep '^bundled_libraries=' "$dependency_file" | cut -d= -f2 || true)
    dependency_reference_count=$(grep '^binary_library_references=' "$dependency_file" | cut -d= -f2 || true)
    dependency_manifest_excerpt=$(grep '^MANIFEST ' "$dependency_file" | sed 's/^MANIFEST //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
    dependency_declared_excerpt=$(grep '^DEPENDENCY ' "$dependency_file" | sed 's/^DEPENDENCY //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 5 || true)
  fi

  if [ -f "$coverage_file" ]; then
    coverage_total_files=$(grep '^total_files=' "$coverage_file" | cut -d= -f2 || true)
    coverage_total_directories=$(grep '^total_directories=' "$coverage_file" | cut -d= -f2 || true)
    coverage_interesting_count=$(grep '^interesting_candidates=' "$coverage_file" | cut -d= -f2 || true)
    coverage_candidate_excerpt=$(grep '^CANDIDATE ' "$coverage_file" | sed 's/^CANDIDATE //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 4 || true)
  fi

  if [ -f "$reverse_file" ]; then
    reverse_candidate_count=$(grep '^candidate_targets=' "$reverse_file" | cut -d= -f2 || true)
    reverse_service_count=$(grep '^service_targets=' "$reverse_file" | cut -d= -f2 || true)
    reverse_binary_count=$(grep '^binary_targets=' "$reverse_file" | cut -d= -f2 || true)
    reverse_script_count=$(grep '^script_targets=' "$reverse_file" | cut -d= -f2 || true)
    reverse_url_count=$(grep '^url_hints=' "$reverse_file" | cut -d= -f2 || true)
    reverse_candidate_excerpt=$(grep '^CANDIDATE ' "$reverse_file" | sed 's/^CANDIDATE //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 4 || true)
    reverse_url_excerpt=$(grep '^URL ' "$reverse_file" | sed 's/^URL //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
  fi

  if [ -f "$supply_file" ]; then
    supply_source_sha=$(grep '^source_sha256=' "$supply_file" | cut -d= -f2- || true)
    supply_signature_status=$(grep '^signature_status=' "$supply_file" | cut -d= -f2- || true)
    supply_signature_summary=$(grep '^signature_summary=' "$supply_file" | cut -d= -f2- || true)
    supply_certificate_count=$(grep '^certificate_files=' "$supply_file" | cut -d= -f2 || true)
    supply_url_count=$(grep '^url_references=' "$supply_file" | cut -d= -f2 || true)
    supply_domain_count=$(grep '^domain_references=' "$supply_file" | cut -d= -f2 || true)
    supply_manifest_count=$(grep '^manifest_provenance_entries=' "$supply_file" | cut -d= -f2 || true)
    supply_publisher_count=$(grep '^publisher_hints=' "$supply_file" | cut -d= -f2 || true)
    supply_registry_count=$(grep '^registry_hints=' "$supply_file" | cut -d= -f2 || true)
    supply_update_count=$(grep '^update_channel_hints=' "$supply_file" | cut -d= -f2 || true)
    supply_publisher_excerpt=$(grep '^PUBLISHER ' "$supply_file" | sed 's/^PUBLISHER //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
    supply_manifest_excerpt=$(grep '^MANIFEST ' "$supply_file" | sed 's/^MANIFEST //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
    supply_url_excerpt=$(grep '^URL ' "$supply_file" | sed 's/^URL //' | grep -vi '^[[:space:]]*none[[:space:]]*$' | head -n 3 || true)
  fi

  dynamic_service_count=${dynamic_service_count:-0}
  dynamic_indicator_count=${dynamic_indicator_count:-0}
  dynamic_probe_count=${dynamic_probe_count:-0}
  dependency_manifest_count=${dependency_manifest_count:-0}
  dependency_declared_count=${dependency_declared_count:-0}
  dependency_library_count=${dependency_library_count:-0}
  dependency_reference_count=${dependency_reference_count:-0}
  coverage_total_files=${coverage_total_files:-0}
  coverage_total_directories=${coverage_total_directories:-0}
  coverage_interesting_count=${coverage_interesting_count:-0}
  reverse_candidate_count=${reverse_candidate_count:-0}
  reverse_service_count=${reverse_service_count:-0}
  reverse_binary_count=${reverse_binary_count:-0}
  reverse_script_count=${reverse_script_count:-0}
  reverse_url_count=${reverse_url_count:-0}
  supply_certificate_count=${supply_certificate_count:-0}
  supply_url_count=${supply_url_count:-0}
  supply_domain_count=${supply_domain_count:-0}
  supply_manifest_count=${supply_manifest_count:-0}
  supply_publisher_count=${supply_publisher_count:-0}
  supply_registry_count=${supply_registry_count:-0}
  supply_update_count=${supply_update_count:-0}
  supply_signature_status=${supply_signature_status:-not_applicable}
  supply_signature_summary=${supply_signature_summary:-不適用}
  supply_source_sha=${supply_source_sha:-unavailable}

  cat > "$REPORT_FILE" << EOF
# 韌體安全分析報告

## 基本資訊
- **韌體名稱**: ${base_name}
- **分析時間**: $(date "+%Y-%m-%d %H:%M:%S")
- **原始檔案大小**: ${file_size}
- **原始檔案類型**: ${file_type}

## 預處理摘要
- ${PREPROCESS_SUMMARY}
- **實際掃描目標**: ${scan_target_description}
EOF

  echo "" >> "$REPORT_FILE"
  echo "## 觀察到的證據" >> "$REPORT_FILE"

  if [ $telnetd_found -eq 1 ]; then
    echo "- 字串掃描命中 telnetd。示例: ${telnetd_example}" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ $dropbear_found -eq 1 ]; then
    echo "- 字串掃描命中 dropbear。示例: ${dropbear_example}" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ $shadow_found -eq 1 ]; then
    echo "- 字串掃描命中 /etc/shadow。示例: ${shadow_example}" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ $total_yara_hits -gt 0 ]; then
    echo "- YARA 規則掃描命中，共計 ${total_yara_hits} 處匹配。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ "$SIGNATURE_STATUS" != "not_applicable" ]; then
    echo "- 數位簽章檢查: ${SIGNATURE_SUMMARY}" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ "$PE_SECURITY_SUMMARY" != "不適用" ]; then
    echo "- PE 安全旗標: ${PE_SECURITY_SUMMARY}" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ -f "$dynamic_file" ]; then
    echo "- 動態分析預檢識別 ${dynamic_service_count} 個啟動/服務檔、${dynamic_indicator_count} 個行為指標，執行 ${dynamic_probe_count} 次安全探針。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ -f "$dependency_file" ]; then
    echo "- 依賴盤點識別 ${dependency_manifest_count} 份 manifest、${dependency_declared_count} 個宣告依賴、${dependency_library_count} 個打包函式庫，以及 ${dependency_reference_count} 個二進位函式庫引用。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ -f "$coverage_file" ]; then
    echo "- 樣本覆蓋摘要盤點 ${coverage_total_files} 個檔案、${coverage_total_directories} 個目錄，標記 ${coverage_interesting_count} 個高優先候選。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ -f "$reverse_file" ]; then
    echo "- 人工逆向輔助摘要鎖定 ${reverse_candidate_count} 個候選目標，涵蓋 ${reverse_service_count} 個啟動項、${reverse_binary_count} 個可執行檔與 ${reverse_url_count} 個 URL 線索。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ -f "$supply_file" ]; then
    echo "- 供應鏈來源檢核整理 ${supply_manifest_count} 筆 manifest 來源、${supply_publisher_count} 筆發行者提示、${supply_url_count} 個來源 URL；簽章狀態為 ${supply_signature_summary}。" >> "$REPORT_FILE"
    evidence_count=$((evidence_count + 1))
  fi

  if [ $evidence_count -eq 0 ]; then
    echo "- 本次自動化分析未命中高信心字串或 YARA 規則。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 風險評估" >> "$REPORT_FILE"

  if [ $telnetd_found -eq 1 ]; then
    if [ $risk_count -eq 0 ]; then
      echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
      echo "|------|----------|------|" >> "$REPORT_FILE"
    fi
    echo "| telnetd | 高 | 命中字串或規則，代表可能暴露未加密管理介面 |" >> "$REPORT_FILE"
    risk_count=$((risk_count + 1))
  fi

  # 根據 YARA 命中動態添加風險
  if [ -n "$YARA_HITS_LIST" ]; then
    echo "$YARA_HITS_LIST" | while IFS='|' read -r rule hits; do
      [ -z "$rule" ] && continue
      if [ $risk_count -eq 0 ]; then
        echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
        echo "|------|----------|------|" >> "$REPORT_FILE"
      fi
      local category=$(get_yara_category "$rule")
      echo "| YARA: $rule | 高 | 屬於 [$category] 分類，發現具體惡意特徵或敏感服務 |" >> "$REPORT_FILE"
      risk_count=$((risk_count + 1))
    done
  fi

  if [ $dropbear_found -eq 1 ]; then
    if [ $risk_count -eq 0 ]; then
      echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
      echo "|------|----------|------|" >> "$REPORT_FILE"
    fi
    echo "| dropbear | 中 | 發現 SSH 服務實作，需要進一步確認版本與配置 |" >> "$REPORT_FILE"
    risk_count=$((risk_count + 1))
  fi

  if [ $shadow_found -eq 1 ]; then
    if [ $risk_count -eq 0 ]; then
      echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
      echo "|------|----------|------|" >> "$REPORT_FILE"
    fi
    echo "| /etc/shadow | 中 | 發現密碼資料路徑參考，需確認檔案保護與權限控制 |" >> "$REPORT_FILE"
    risk_count=$((risk_count + 1))
  fi

  if [ "$SIGNATURE_STATUS" = "invalid_or_untrusted" ] || [ "$SIGNATURE_STATUS" = "unverified" ]; then
    if [ $risk_count -eq 0 ]; then
      echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
      echo "|------|----------|------|" >> "$REPORT_FILE"
    fi
    echo "| 數位簽章 | 中 | 無法建立有效信任鏈，需人工確認來源與完整性 |" >> "$REPORT_FILE"
    risk_count=$((risk_count + 1))
  fi

  if [ "$PE_ASLR" = "False" ] || [ "$PE_DEP" = "False" ]; then
    if [ $risk_count -eq 0 ]; then
      echo "| 項目 | 風險等級 | 依據 |" >> "$REPORT_FILE"
      echo "|------|----------|------|" >> "$REPORT_FILE"
    fi
    echo "| PE 安全旗標 | 中 | 執行檔未完整啟用 ASLR 或 DEP |" >> "$REPORT_FILE"
    risk_count=$((risk_count + 1))
  fi

  if [ $risk_count -eq 0 ]; then
    echo "- 目前沒有足夠證據支持高或中風險結論；這只表示本次自動檢查未命中。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 緩解建議" >> "$REPORT_FILE"

  if [ $telnetd_found -eq 1 ] || echo "$YARA_HITS_LIST" | grep -q "^telnetd_rule|"; then
    echo "- 若非必要，停用 telnetd 並改用受管控的 SSH。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ $dropbear_found -eq 1 ]; then
    echo "- 核對 dropbear 版本、認證配置與已知漏洞。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ $shadow_found -eq 1 ]; then
    echo "- 檢查密碼資料是否可被未授權程序讀取，並驗證檔案權限。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ "$SIGNATURE_STATUS" = "invalid_or_untrusted" ] || [ "$SIGNATURE_STATUS" = "unverified" ]; then
    echo "- 以可信 CA 或供應商鏈重新驗證簽章，必要時比對雜湊來源。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ "$PE_ASLR" = "False" ] || [ "$PE_DEP" = "False" ]; then
    echo "- 重新檢視編譯選項，補齊 ASLR 與 DEP 等基礎防護。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ -f "$coverage_file" ] && [ "$coverage_interesting_count" -gt 0 ]; then
    echo "- 先檢查樣本覆蓋摘要中的高優先候選與最大檔案，確認是否仍有巢狀封裝或未展開內容。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ -f "$reverse_file" ] && [ "$reverse_candidate_count" -gt 0 ]; then
    echo "- 依人工逆向輔助摘要優先分析啟動項、更新器與可執行檔，再進入 Ghidra/IDA 驗證關鍵流程。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ -f "$supply_file" ]; then
    echo "- 以供應鏈來源檢核摘要中的 SHA-256、簽章、manifest 與來源 URL，比對官方發佈管道與內部白名單。" >> "$REPORT_FILE"
    recommendation_count=$((recommendation_count + 1))
  fi

  if [ $recommendation_count -eq 0 ]; then
    echo "- 本次未形成額外緩解建議；請保留原始樣本與分析產物以便後續複驗。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 動態分析摘要" >> "$REPORT_FILE"

  if [ -f "$dynamic_file" ]; then
    echo "- 啟動/服務候選: ${dynamic_service_count}" >> "$REPORT_FILE"
    echo "- 行為指標: ${dynamic_indicator_count}" >> "$REPORT_FILE"
    echo "- 安全探針: ${dynamic_probe_count}" >> "$REPORT_FILE"
    if [ -n "$dynamic_indicator_excerpt" ]; then
      echo '```text' >> "$REPORT_FILE"
      printf '%s\n' "$dynamic_indicator_excerpt" >> "$REPORT_FILE"
      echo '```' >> "$REPORT_FILE"
    fi
  else
    echo "- 本次未生成動態分析摘要。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 依賴盤點摘要" >> "$REPORT_FILE"

  if [ -f "$dependency_file" ]; then
    echo "- Manifest 檔案: ${dependency_manifest_count}" >> "$REPORT_FILE"
    echo "- 宣告依賴: ${dependency_declared_count}" >> "$REPORT_FILE"
    echo "- 打包函式庫: ${dependency_library_count}" >> "$REPORT_FILE"
    echo "- 二進位函式庫引用: ${dependency_reference_count}" >> "$REPORT_FILE"
    if [ -n "$dependency_manifest_excerpt" ] || [ -n "$dependency_declared_excerpt" ]; then
      echo '```text' >> "$REPORT_FILE"
      [ -n "$dependency_manifest_excerpt" ] && printf 'Manifest:\n%s\n' "$dependency_manifest_excerpt" >> "$REPORT_FILE"
      [ -n "$dependency_declared_excerpt" ] && printf 'Dependencies:\n%s\n' "$dependency_declared_excerpt" >> "$REPORT_FILE"
      echo '```' >> "$REPORT_FILE"
    fi
  else
    echo "- 本次未生成依賴盤點摘要。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 樣本覆蓋摘要" >> "$REPORT_FILE"

  if [ -f "$coverage_file" ]; then
    echo "- 檔案總數: ${coverage_total_files}" >> "$REPORT_FILE"
    echo "- 目錄總數: ${coverage_total_directories}" >> "$REPORT_FILE"
    echo "- 高優先候選: ${coverage_interesting_count}" >> "$REPORT_FILE"
    if [ -n "$coverage_candidate_excerpt" ]; then
      echo '```text' >> "$REPORT_FILE"
      printf '%s\n' "$coverage_candidate_excerpt" >> "$REPORT_FILE"
      echo '```' >> "$REPORT_FILE"
    fi
  else
    echo "- 本次未生成樣本覆蓋摘要。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 人工逆向輔助摘要" >> "$REPORT_FILE"

  if [ -f "$reverse_file" ]; then
    echo "- 候選目標: ${reverse_candidate_count}" >> "$REPORT_FILE"
    echo "- 啟動項: ${reverse_service_count}" >> "$REPORT_FILE"
    echo "- 可執行檔: ${reverse_binary_count}" >> "$REPORT_FILE"
    echo "- 腳本: ${reverse_script_count}" >> "$REPORT_FILE"
    echo "- URL 線索: ${reverse_url_count}" >> "$REPORT_FILE"
    if [ -n "$reverse_candidate_excerpt" ] || [ -n "$reverse_url_excerpt" ]; then
      echo '```text' >> "$REPORT_FILE"
      [ -n "$reverse_candidate_excerpt" ] && printf 'Targets:\n%s\n' "$reverse_candidate_excerpt" >> "$REPORT_FILE"
      [ -n "$reverse_url_excerpt" ] && printf 'URLs:\n%s\n' "$reverse_url_excerpt" >> "$REPORT_FILE"
      echo '```' >> "$REPORT_FILE"
    fi
  else
    echo "- 本次未生成人工逆向輔助摘要。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 供應鏈來源檢核摘要" >> "$REPORT_FILE"

  if [ -f "$supply_file" ]; then
    echo "- SHA-256: ${supply_source_sha}" >> "$REPORT_FILE"
    echo "- 簽章狀態: ${supply_signature_summary}" >> "$REPORT_FILE"
    echo "- 憑證檔案: ${supply_certificate_count}" >> "$REPORT_FILE"
    echo "- 來源 URL: ${supply_url_count}" >> "$REPORT_FILE"
    echo "- 來源網域: ${supply_domain_count}" >> "$REPORT_FILE"
    echo "- Manifest 來源欄位: ${supply_manifest_count}" >> "$REPORT_FILE"
    echo "- 發行者提示: ${supply_publisher_count}" >> "$REPORT_FILE"
    echo "- 套件註冊表提示: ${supply_registry_count}" >> "$REPORT_FILE"
    echo "- 更新通道提示: ${supply_update_count}" >> "$REPORT_FILE"
    if [ -n "$supply_publisher_excerpt" ] || [ -n "$supply_manifest_excerpt" ] || [ -n "$supply_url_excerpt" ]; then
      echo '```text' >> "$REPORT_FILE"
      [ -n "$supply_publisher_excerpt" ] && printf 'Publisher:\n%s\n' "$supply_publisher_excerpt" >> "$REPORT_FILE"
      [ -n "$supply_manifest_excerpt" ] && printf 'Manifest:\n%s\n' "$supply_manifest_excerpt" >> "$REPORT_FILE"
      [ -n "$supply_url_excerpt" ] && printf 'URLs:\n%s\n' "$supply_url_excerpt" >> "$REPORT_FILE"
      echo '```' >> "$REPORT_FILE"
    fi
  else
    echo "- 本次未生成供應鏈來源檢核摘要。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## YARA規則檢測結果" >> "$REPORT_FILE"

  if [ "$YARA_TOOL_MISSING" -eq 1 ]; then
    echo "- **警告: 未安裝 YARA 工具，跳過掃描。**" >> "$REPORT_FILE"
  elif [ -z "$YARA_HITS_LIST" ]; then
    echo "- 本次掃描未命中任何已知的 YARA 安全規則。" >> "$REPORT_FILE"
  else
    # 按分類展示 (Bash 3.2 compatible)
    local cats=$(echo "$YARA_HITS_LIST" | while IFS='|' read -r rule hits; do
      [ -z "$rule" ] && continue
      get_yara_category "$rule"
    done | sort -u)
    
    echo "$cats" | while IFS= read -r cat; do
      [ -z "$cat" ] && continue
      echo "### $cat" >> "$REPORT_FILE"
      echo "$YARA_HITS_LIST" | while IFS='|' read -r rule hits; do
        [ -z "$rule" ] && continue
        if [ "$(get_yara_category "$rule")" = "$cat" ]; then
          echo "- $rule: 命中 (${hits} 處)" >> "$REPORT_FILE"
        fi
      done
    done
  fi

  echo "" >> "$REPORT_FILE"
  echo "## Binwalk 摘要" >> "$REPORT_FILE"

  if [ -n "$binwalk_excerpt" ]; then
    echo '```text' >> "$REPORT_FILE"
    printf '%s\n' "$binwalk_excerpt" >> "$REPORT_FILE"
    echo '```' >> "$REPORT_FILE"
  else
    echo "- 未檢測到可解析的 binwalk 特徵，或此步驟未產生輸出。" >> "$REPORT_FILE"
  fi

  echo "" >> "$REPORT_FILE"
  echo "## 結論" >> "$REPORT_FILE"

  if [ $risk_count -gt 0 ]; then
    echo "此報告僅列出本次自動化流程實際命中的證據與風險，並補充樣本覆蓋、人工逆向與供應鏈來源線索。" >> "$REPORT_FILE"
  else
    echo "本次自動化檢查未命中高信心風險訊號，但已額外整理樣本覆蓋、人工逆向候選與供應鏈來源線索；仍建議在隔離環境完成人工驗證。" >> "$REPORT_FILE"
  fi

  cp "$REPORT_FILE" "$WORK_DIR/simulated_report.md"
  log "SUCCESS" "安全分析報告已創建: $REPORT_FILE"
}

# 創建截圖說明
create_screenshot_readme() {
  log "INFO" "附加資料：創建或更新截圖說明"
  
  if [ ! -f "$WORK_DIR/screenshots/README.txt" ]; then
    cat > "$WORK_DIR/screenshots/README.txt" << 'EOF'
# 截圖說明

此目錄包含以下分析截圖：

## Ghidra 分析截圖
- strings_view.png: Ghidra的已定義字串視圖，顯示找到的telnetd和dropbear字串
- function_graph.png: 網絡服務初始化函數的圖形視圖
- disassembly.png: 關鍵代碼區段的反組譯視圖

## Binwalk 分析截圖
- binwalk_output.png: binwalk分析結果，顯示韌體結構
- extraction_process.png: 韌體提取過程

## YARA 規則測試截圖
- yara_detection.png: YARA規則檢測結果

請注意：實際練習時，您應該替換這些說明為真實的截圖。
EOF
    log "SUCCESS" "截圖說明已創建"
  fi
}

# 檢查目錄結構
check_directory_structure() {
  log "INFO" "檢查目錄結構是否完整"
  
  local REQUIRED_FILES=(
    "$FIRMWARE_FILE"
    "$WORK_DIR/binwalk-analysis"
    "$WORK_DIR/dependency-inventory"
    "$WORK_DIR/dynamic-analysis"
    "$WORK_DIR/hexdump-analysis/full_dump.txt"
    "$WORK_DIR/sample-coverage"
    "$WORK_DIR/reverse-engineering-hints"
    "$WORK_DIR/supply-chain-verification"
    "$WORK_DIR/yara-rules/telnetd_rule.yar"
    "$WORK_DIR/yara-rules/network_services_rule.yar"
    "$WORK_DIR/ghidra-notes.md"
    "$WORK_DIR/simulated_report.md"
    "$WORK_DIR/can-log-demo.txt"
    "$WORK_DIR/screenshots/README.txt"
  )

  local missing=0
  for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -e "$file" ]; then
      log "WARNING" "文件或目錄不存在: $file"
      missing=1
    fi
  done

  if [ $missing -eq 0 ]; then
    log "SUCCESS" "目錄結構完整性檢查通過"
  else
    log "WARNING" "目錄結構不完整，請檢查上述警告"
  fi
}

# 全局掃描目標（檔案或目錄）
SCAN_TARGET=""

# 預處理複雜檔案格式
preprocess_file() {
  local input_file="$1"
  local ext="${input_file##*.}"
  local ext_lower
  local base_name=$(basename "$input_file")
  local out_dir="$WORK_DIR/preprocessed/${base_name}_${DATE_TAG}_extracted"
  local converted_file="$WORK_DIR/preprocessed/${base_name}_${DATE_TAG}.img"
  
  SCAN_TARGET="$input_file"
  log "INFO" "預處理檔案: $input_file (格式: $ext)"
  ext_lower=$(lowercase_string "$ext")
  
  case "$ext_lower" in
    dmg)
      if check_command "dmg2img"; then
        log "INFO" "轉換 DMG 為 IMG..."
        if dmg2img "$input_file" "$converted_file"; then
          SCAN_TARGET="$converted_file"
          PREPROCESS_SUMMARY="已將 DMG 轉換為 IMG: $(basename "$converted_file")"
        else
          log "WARNING" "DMG 轉換失敗，回退至原始檔案"
          PREPROCESS_SUMMARY="DMG 轉換失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 dmg2img，直接分析原始檔案"
      fi
      ;;
    iso)
      if check_command "7z"; then
        log "INFO" "提取 ISO 內容..."
        mkdir -p "$out_dir"
        if 7z x "$input_file" "-o$out_dir" -y > /dev/null 2>&1; then
          SCAN_TARGET="$out_dir"
          PREPROCESS_SUMMARY="已提取 ISO 內容至 $(basename "$out_dir")，共 $(count_directory_files "$out_dir") 個檔案"
        else
          log "WARNING" "ISO 提取失敗，回退至原始檔案"
          PREPROCESS_SUMMARY="ISO 提取失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 7z，直接分析原始檔案"
      fi
      ;;
    pkg)
      if check_command "7z"; then
        log "INFO" "提取 PKG 封裝內容..."
        mkdir -p "$out_dir"
        if 7z x "$input_file" "-o$out_dir" -y > /dev/null 2>&1; then
          SCAN_TARGET="$out_dir"
          PREPROCESS_SUMMARY="已提取 PKG 內容至 $(basename "$out_dir")，共 $(count_directory_files "$out_dir") 個檔案"
        else
          log "WARNING" "PKG 提取失敗，回退至原始檔案"
          PREPROCESS_SUMMARY="PKG 提取失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 7z，直接分析原始檔案"
      fi
      verify_signature "$input_file"
      ;;
    exe)
      if check_command "7z"; then
        log "INFO" "嘗試提取 Windows 執行檔內容..."
        mkdir -p "$out_dir"
        if 7z x "$input_file" "-o$out_dir" -y > /dev/null 2>&1; then
          SCAN_TARGET="$out_dir"
          PREPROCESS_SUMMARY="已提取 EXE 內容至 $(basename "$out_dir")，共 $(count_directory_files "$out_dir") 個檔案"
        else
          log "WARNING" "EXE 提取失敗，直接分析原始檔案"
          PREPROCESS_SUMMARY="EXE 提取失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 7z，直接分析原始檔案"
      fi
      verify_signature "$input_file"
      check_pe_security "$input_file"
      ;;
    msi)
      if check_command "msiextract"; then
        log "INFO" "提取 MSI 安裝包內容..."
        mkdir -p "$out_dir"
        if msiextract "$input_file" -C "$out_dir"; then
          SCAN_TARGET="$out_dir"
          PREPROCESS_SUMMARY="已提取 MSI 內容至 $(basename "$out_dir")，共 $(count_directory_files "$out_dir") 個檔案"
        else
          log "WARNING" "MSI 提取失敗，直接分析原始檔案"
          PREPROCESS_SUMMARY="MSI 提取失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 msiextract，直接分析原始檔案"
      fi
      verify_signature "$input_file"
      ;;
    zip|7z|tar|gz|xz)
      if check_command "7z"; then
        log "INFO" "解壓縮檔案..."
        mkdir -p "$out_dir"
        if 7z x "$input_file" "-o$out_dir" -y > /dev/null 2>&1; then
          SCAN_TARGET="$out_dir"
          PREPROCESS_SUMMARY="已解壓縮至 $(basename "$out_dir")，共 $(count_directory_files "$out_dir") 個檔案"
        else
          log "WARNING" "壓縮檔提取失敗，直接分析原始檔案"
          PREPROCESS_SUMMARY="壓縮檔提取失敗，直接分析原始檔案"
        fi
      else
        PREPROCESS_SUMMARY="缺少 7z，直接分析原始檔案"
      fi
      ;;
    *)
      PREPROCESS_SUMMARY="未進行額外預處理，直接分析原始檔案"
      ;;
  esac
}

# 驗證數位簽章
verify_signature() {
  local file="$1"
  local log_file="$LOG_DIR/signature_check_$(basename "$file").txt"
  local file_lower
  log "INFO" "正在驗證數位簽章: $file"
  file_lower=$(lowercase_string "$file")
  
  if [[ "$file_lower" == *.exe ]] || [[ "$file_lower" == *.msi ]]; then
    if check_command "osslsigncode"; then
      if osslsigncode verify "$file" > "$log_file" 2>&1; then
        log "SUCCESS" "數位簽章驗證通過"
        SIGNATURE_STATUS="valid"
        SIGNATURE_SUMMARY="數位簽章驗證通過"
      elif grep -qi "No signature found" "$log_file"; then
        log "WARNING" "未發現數位簽章"
        SIGNATURE_STATUS="missing"
        SIGNATURE_SUMMARY="未發現 Authenticode 簽章"
      elif grep -qi 'Use the "-CAfile" option' "$log_file"; then
        log "WARNING" "偵測到簽章資訊，但無法在目前環境完成信任鏈驗證"
        SIGNATURE_STATUS="unverified"
        SIGNATURE_SUMMARY="偵測到簽章資訊，但缺少 CA 憑證鏈，無法完成信任驗證"
      else
        log "WARNING" "數位簽章無效或未簽署"
        SIGNATURE_STATUS="invalid_or_untrusted"
        SIGNATURE_SUMMARY="數位簽章驗證失敗或來源不受信任"
      fi
    else
      SIGNATURE_STATUS="tool_missing"
      SIGNATURE_SUMMARY="缺少 osslsigncode，未執行簽章檢查"
    fi
  elif [[ "$file_lower" == *.pkg ]]; then
    log "INFO" "檢查 PKG 簽名資訊..."
    if check_command "7z"; then
      if 7z l "$file" > "$log_file" 2>&1 && grep -qi "signature" "$log_file"; then
        log "SUCCESS" "發現簽名資訊"
        SIGNATURE_STATUS="present"
        SIGNATURE_SUMMARY="封裝內容中發現簽名相關資訊"
      else
        log "WARNING" "未發現明顯簽名資訊"
        SIGNATURE_STATUS="missing"
        SIGNATURE_SUMMARY="未發現明顯簽名資訊"
      fi
    else
      SIGNATURE_STATUS="tool_missing"
      SIGNATURE_SUMMARY="缺少 7z，未執行 PKG 簽章檢查"
    fi
  fi
}

# 檢查 PE 安全特性 (ASLR, DEP 等)
check_pe_security() {
  local file="$1"
  local output_file="$LOG_DIR/pe_security_$(basename "$file").txt"
  log "INFO" "檢查 PE 安全特性: $file"

  if ! check_command "python3"; then
    PE_SECURITY_SUMMARY="缺少 python3，未檢查 PE 安全旗標"
    return
  fi

  if python3 - "$file" > "$output_file" 2>&1 <<'EOF'
import sys

try:
    import pefile
except Exception as exc:
    print(f"Error: {exc}")
    raise SystemExit(2)

path = sys.argv[1]

try:
    pe = pefile.PE(path)
    aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
    dep = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
    print(f"ASLR: {aslr}")
    print(f"DEP: {dep}")
except Exception as exc:
    print(f"Error: {exc}")
    raise SystemExit(1)
EOF
  then
    PE_ASLR=$(grep '^ASLR:' "$output_file" | awk '{print $2}')
    PE_DEP=$(grep '^DEP:' "$output_file" | awk '{print $2}')
    PE_SECURITY_SUMMARY="ASLR=${PE_ASLR:-未知}, DEP=${PE_DEP:-未知}"
    log "INFO" "PE 安全特性: $PE_SECURITY_SUMMARY"
  else
    PE_SECURITY_SUMMARY="無法解析 PE 安全旗標"
    log "WARNING" "$PE_SECURITY_SUMMARY"
  fi
}

# 分析單個檔案
analyze_single_file() {
  local file_path="$1"
  log "INFO" "開始分析檔案: $file_path"
  
  # 更新全局變數
  FIRMWARE_FILE="$file_path"
  FIRMWARE_NAME=$(basename "$file_path")
  DATE_TAG="$(date "+%Y%m%d_%H%M%S")"
  LOG_FILE="$LOG_DIR/analysis_${FIRMWARE_NAME}_$DATE_TAG.log"
  REPORT_FILE="$REPORT_DIR/report_${FIRMWARE_NAME}_$DATE_TAG.md"
  reset_analysis_state
  
  # 執行預處理
  preprocess_file "$FIRMWARE_FILE"
  
  # 根據選項執行不同的分析
  if [ $YARA_ONLY -eq 1 ]; then
    run_yara_rules
  elif [ $BINWALK_ONLY -eq 1 ]; then
    run_binwalk_analysis
  else
    # 執行完整分析
    perform_hexdump_analysis
    run_yara_rules
    run_binwalk_analysis
    generate_dependency_inventory
    perform_dynamic_analysis
    generate_sample_coverage
    generate_reverse_engineering_hints
    verify_supply_chain_sources
    create_security_report
  fi
  
  log "SUCCESS" "檔案分析完成: $file_path"
}

# 分析目錄中的所有檔案
analyze_directory() {
  local dir_path="$1"
  local extension="$2"
  local recursive="$3"
  
  log "INFO" "分析目錄: $dir_path (檔案類型: *$extension)"
  
  # 構建查找命令
  local find_cmd="find \"$dir_path\""
  if [ $recursive -eq 0 ]; then
    find_cmd="$find_cmd -maxdepth 1"
  fi
  find_cmd="$find_cmd -type f -name \"*$extension\""
  
  # 執行查找並分析每個檔案
  local file_count=0
  while IFS= read -r file; do
    analyze_single_file "$file"
    file_count=$((file_count + 1))
  done < <(eval "$find_cmd")
  
  if [ $file_count -eq 0 ]; then
    log "WARNING" "在目錄 $dir_path 中未發現 *$extension 檔案"
  else
    log "SUCCESS" "已完成對 $file_count 個檔案的分析"
  fi
}

#===============================================================================
# 主執行流程
#===============================================================================

# 顯示介紹橫幅
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}                    韌體分析自動化腳本 v2.1                     ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}作者: Dennis Lee${NC}"
echo -e "${YELLOW}分析間隔: ${ANALYSIS_INTERVAL}分鐘${NC}"
echo -e "${YELLOW}當前時間: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 初始化日誌目錄
mkdir -p "$LOG_DIR"

# 記錄啟動信息
log "INFO" "韌體分析自動化腳本啟動"

# 初始化目錄結構
initialize_directories

# 檢查是否提供了目錄而非單個檔案
if [ -n "$TARGET_DIR" ]; then
  if [ ! -d "$TARGET_DIR" ]; then
    log "ERROR" "指定的目錄不存在: $TARGET_DIR"
    exit 1
  fi
  analyze_directory "$TARGET_DIR" "$FILE_EXTENSION" "$RECURSIVE"
else
  # 檢查韌體文件是否存在
  if [ ! -f "$FIRMWARE_FILE" ]; then
    if [ -n "$TARGET_FILE" ]; then
      log "ERROR" "指定的檔案不存在: $FIRMWARE_FILE"
      exit 1
    else
      create_sample_firmware
    fi
  fi
  
  # 記錄檔案信息
  log "INFO" "韌體文件: $FIRMWARE_FILE"
  log "INFO" "日誌文件: $LOG_FILE"
  log "INFO" "報告文件: $REPORT_FILE"
  
  # 分析單個檔案
  analyze_single_file "$FIRMWARE_FILE"
  
  # 如果不是只運行部分分析，則創建其他資料
  if [ $YARA_ONLY -eq 0 ] && [ $BINWALK_ONLY -eq 0 ]; then
    create_can_log
    create_ghidra_notes
    create_screenshot_readme
  fi
  
  # 檢查目錄結構完整性
  check_directory_structure
  
  # 完成
  log "SUCCESS" "韌體分析完成，報告已生成: $REPORT_FILE"
fi

echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}                       分析完成                                  ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}您可以在以下位置查看報告:${NC}"
echo -e "${YELLOW}  - $REPORT_DIR/${NC}"
echo -e "${BLUE}====================================================================${NC}" 
