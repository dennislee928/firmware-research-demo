#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import yara
import magic
from pathlib import Path
from colorama import init, Fore, Style

# 初始化 colorama
init()

class FirmwareAnalyzer:
    def __init__(self):
        self.rules_dir = "yara_rules"
        self.firmware_dir = "firmware_samples"
        self.reports_dir = "reports"
        self.rules = self._load_yara_rules()
        
    def _load_yara_rules(self):
        """載入所有 YARA 規則"""
        rules = {}
        for rule_file in Path(self.rules_dir).glob("*.yar"):
            try:
                rules[rule_file.stem] = yara.compile(str(rule_file))
                print(f"{Fore.GREEN}[+] 成功載入規則: {rule_file.name}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] 載入規則 {rule_file.name} 失敗: {str(e)}{Style.RESET_ALL}")
        return rules
    
    def analyze_firmware(self, firmware_path):
        """分析韌體檔案"""
        if not os.path.exists(firmware_path):
            print(f"{Fore.RED}[-] 檔案不存在: {firmware_path}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] 開始分析: {firmware_path}{Style.RESET_ALL}")
        
        # 獲取檔案類型
        file_type = magic.from_file(firmware_path)
        print(f"{Fore.YELLOW}[*] 檔案類型: {file_type}{Style.RESET_ALL}")
        
        # 執行 YARA 規則掃描
        print(f"\n{Fore.CYAN}[*] 執行 YARA 規則掃描{Style.RESET_ALL}")
        for rule_name, rule in self.rules.items():
            try:
                matches = rule.match(firmware_path)
                if matches:
                    print(f"{Fore.GREEN}[+] 規則 {rule_name} 匹配成功{Style.RESET_ALL}")
                    for match in matches:
                        print(f"    - 匹配: {match.rule}")
                        print(f"    - 嚴重性: {match.meta.get('severity', 'unknown')}")
                else:
                    print(f"{Fore.YELLOW}[-] 規則 {rule_name} 未匹配{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] 執行規則 {rule_name} 時出錯: {str(e)}{Style.RESET_ALL}")
    
    def analyze_all_firmware(self):
        """分析所有韌體檔案"""
        firmware_files = list(Path(self.firmware_dir).glob("*.bin"))
        if not firmware_files:
            print(f"{Fore.YELLOW}[!] 未找到韌體檔案{Style.RESET_ALL}")
            return
        
        for firmware in firmware_files:
            self.analyze_firmware(str(firmware))

def main():
    analyzer = FirmwareAnalyzer()
    analyzer.analyze_all_firmware()

if __name__ == "__main__":
    main() 