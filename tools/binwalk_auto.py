#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime

class BinwalkAuto:
    def __init__(self):
        self.output_dir = "unpacked"
        self.firmware_dir = "firmware_samples"
        
    def run_binwalk(self, firmware_file):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(self.output_dir, f"{os.path.basename(firmware_file)}_{timestamp}")
        
        # 創建輸出目錄
        os.makedirs(output_path, exist_ok=True)
        
        # 執行 binwalk
        cmd = [
            "binwalk",
            "-eM",  # 提取所有發現的檔案
            "-C", output_path,  # 指定輸出目錄
            firmware_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(f"Binwalk 執行完成，輸出保存在: {output_path}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Binwalk 執行錯誤: {e}")
            return None
    
    def process_all_firmware(self):
        for firmware in os.listdir(self.firmware_dir):
            if firmware.endswith(('.bin', '.img', '.chk')):
                firmware_path = os.path.join(self.firmware_dir, firmware)
                print(f"處理韌體: {firmware}")
                self.run_binwalk(firmware_path)

if __name__ == "__main__":
    auto = BinwalkAuto()
    auto.process_all_firmware()
