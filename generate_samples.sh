#!/bin/bash
#===============================================================================
# 韌體樣本生成腳本
# 描述: 生成多種格式的模擬韌體樣本，用於測試分析工具
#===============================================================================

SAMPLE_DIR="./firmware_samples"
mkdir -p "$SAMPLE_DIR"

echo "正在生成測試樣本於 $SAMPLE_DIR ..."

# 1. 基礎二進位檔案 (.bin)
echo "生成 iot_gateway.bin ..."
cat > "$SAMPLE_DIR/iot_gateway.bin" << 'EOF'
[FIRMWARE HEADER]
Version: 1.2.3
Arch: arm64
[FILESYSTEM]
/etc/shadow: root:$1$v9.D0376$K9F....:18451:0:99999:7:::
/usr/sbin/telnetd -p 23
/usr/bin/dropbear -p 22
[BINARY DATA]
\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00
EOF

# 2. 壓縮包 (.zip)
if command -v zip &> /dev/null || command -v 7z &> /dev/null; then
  echo "生成 camera_patch.zip ..."
  TEMP_FS=$(mktemp -d)
  mkdir -p "$TEMP_FS/etc" "$TEMP_FS/bin"
  echo "root:x:0:0:root:/root:/bin/sh" > "$TEMP_FS/etc/passwd"
  echo "telnetd" > "$TEMP_FS/bin/telnetd"
  if command -v zip &> /dev/null; then
    (cd "$TEMP_FS" && zip -r "$OLDPWD/$SAMPLE_DIR/camera_patch.zip" .) &> /dev/null
  else
    7z a "$SAMPLE_DIR/camera_patch.zip" "$TEMP_FS/*" &> /dev/null
  fi
  rm -rf "$TEMP_FS"
else
  echo "Skip zip (tools not found)"
fi

# 3. Windows 執行檔 (.exe) - 模擬
echo "生成 legacy_updater.exe ..."
cat > "$SAMPLE_DIR/legacy_updater.exe" << 'EOF'
MZ......................This program cannot be run in DOS mode.
[PE HEADER]
Characteristics: ASLR=False, DEP=False
[STRINGS]
C:\Windows\System32\cmd.exe
admin_password_backdoor
telnetd.exe
EOF

# 4. Apple 安裝包 (.pkg) - 模擬
echo "生成 macos_driver.pkg ..."
echo "PKG_HEADER_V2" > "$SAMPLE_DIR/macos_driver.pkg"
echo "Payload: root_access_utility" >> "$SAMPLE_DIR/macos_driver.pkg"
echo "/etc/shadow" >> "$SAMPLE_DIR/macos_driver.pkg"

# 5. 磁碟鏡像 (.iso) - 模擬
echo "生成 recovery_disk.iso ..."
dd if=/dev/zero of="$SAMPLE_DIR/recovery_disk.iso" bs=1024 count=100 2>/dev/null
echo "CD001 - ISO9660 RECOVERY" >> "$SAMPLE_DIR/recovery_disk.iso"
echo "Found: dropbear ssh server" >> "$SAMPLE_DIR/recovery_disk.iso"

# 6. MSI 安裝包 (.msi) - 模擬
echo "生成 service_config.msi ..."
cat > "$SAMPLE_DIR/service_config.msi" << 'EOF'
[MSI DATABASE]
Property: ProductName = VulnerableService
CustomAction: net user /add backdor pass123
EOF

echo "✅ 樣本生成完成！"
ls -lh "$SAMPLE_DIR"
