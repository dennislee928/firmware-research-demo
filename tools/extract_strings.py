#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path
from datetime import datetime

class StringExtractor:
    def __init__(self):
        self.firmware_dir = "firmware_samples"
        self.output_dir = "unpacked"
        
    def extract_ascii_strings(self, data, min_length=4):
        pattern = b'[\x20-\x7E]{%d,}' % min_length
        return re.findall(pattern, data)
    
    def extract_unicode_strings(self, data, min_length=4):
        pattern = b'(?:[\x00-\x7F][\x00]){%d,}' % min_length
        return re.findall(pattern, data)
    
    def process_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
            
        ascii_strings = self.extract_ascii_strings(data)
        unicode_strings = self.extract_unicode_strings(data)
        
        return {
            'ascii': [s.decode('ascii') for s in ascii_strings],
            'unicode': [s.decode('utf-16') for s in unicode_strings]
        }
    
    def save_results(self, results, firmware_file):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(
            self.output_dir,
            f"{os.path.basename(firmware_file)}_{timestamp}_strings.txt"
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# 字串提取結果 - {os.path.basename(firmware_file)}\n\n")
            
            f.write("## ASCII 字串\n")
            for string in results['ascii']:
                f.write(f"{string}\n")
            
            f.write("\n## Unicode 字串\n")
            for string in results['unicode']:
                f.write(f"{string}\n")
    
    def process_all_firmware(self):
        for firmware in os.listdir(self.firmware_dir):
            if firmware.endswith(('.bin', '.img', '.chk')):
                firmware_path = os.path.join(self.firmware_dir, firmware)
                print(f"處理韌體: {firmware}")
                results = self.process_file(firmware_path)
                self.save_results(results, firmware_path)

def extract_strings(file_path, min_length=4):
    """從二進制文件中提取 ASCII 字符串"""
    strings = []
    current_string = ""
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # 可打印 ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(f"0x{i-len(current_string):X}: {current_string}")
                current_string = ""
                
        # 處理最後一個字符串
        if len(current_string) >= min_length:
            strings.append(f"0x{len(data)-len(current_string):X}: {current_string}")
            
    except Exception as e:
        print(f"錯誤：無法讀取文件 {file_path}: {str(e)}")
        return []
        
    return strings

def main():
    if len(sys.argv) != 2:
        print("使用方法: python extract_strings.py <file_path>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"錯誤：文件不存在 {file_path}")
        sys.exit(1)
        
    # 提取字符串
    strings = extract_strings(file_path)
    
    # 生成輸出文件名
    output_file = f"{Path(file_path).stem}_strings.txt"
    
    # 寫入文件
    try:
        with open(output_file, 'w') as f:
            for string in strings:
                f.write(f"{string}\n")
        print(f"字符串已提取到: {output_file}")
    except Exception as e:
        print(f"錯誤：無法寫入文件 {output_file}: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
