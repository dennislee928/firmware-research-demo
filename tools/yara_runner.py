#!/usr/bin/env python3
import yara
import os
from datetime import datetime

class YaraRunner:
    def __init__(self):
        self.rules_dir = "yara_rules"
        self.firmware_dir = "firmware_samples"
        self.reports_dir = "reports"
        
    def compile_rules(self):
        rules = {}
        for rule_file in os.listdir(self.rules_dir):
            if rule_file.endswith('.yar'):
                rule_path = os.path.join(self.rules_dir, rule_file)
                try:
                    rules[rule_file] = yara.compile(filepath=rule_path)
                except yara.SyntaxError as e:
                    print(f"規則編譯錯誤 {rule_file}: {e}")
        return rules
    
    def scan_firmware(self, rules, firmware_file):
        results = {}
        with open(firmware_file, 'rb') as f:
            firmware_data = f.read()
            
        for rule_name, rule in rules.items():
            matches = rule.match(data=firmware_data)
            if matches:
                results[rule_name] = [str(match) for match in matches]
        
        return results
    
    def generate_report(self, results, firmware_file):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(
            self.reports_dir,
            f"{os.path.basename(firmware_file)}_{timestamp}_yara_scan.md"
        )
        
        with open(report_file, 'w') as f:
            f.write(f"# YARA 掃描報告 - {os.path.basename(firmware_file)}\n\n")
            f.write(f"掃描時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for rule_name, matches in results.items():
                f.write(f"## {rule_name}\n")
                if matches:
                    f.write("發現匹配:\n")
                    for match in matches:
                        f.write(f"- {match}\n")
                else:
                    f.write("未發現匹配\n")
                f.write("\n")
    
    def run_scan(self):
        rules = self.compile_rules()
        for firmware in os.listdir(self.firmware_dir):
            if firmware.endswith(('.bin', '.img', '.chk')):
                firmware_path = os.path.join(self.firmware_dir, firmware)
                print(f"掃描韌體: {firmware}")
                results = self.scan_firmware(rules, firmware_path)
                self.generate_report(results, firmware_path)

if __name__ == "__main__":
    runner = YaraRunner()
    runner.run_scan()
