#!/usr/bin/env python3
import os
import re
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

if __name__ == "__main__":
    extractor = StringExtractor()
    extractor.process_all_firmware()
