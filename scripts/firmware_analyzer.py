#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import yara
import argparse
from pathlib import Path
from typing import Dict, List, Optional

class FirmwareAnalyzer:
    def __init__(self, rules_path: str):
        """初始化分析器，載入 YARA 規則"""
        self.rules = self._load_rules(rules_path)
        self.risk_levels = {
            'high': ['telnetd', 'dropbear', 'backdoor'],
            'medium': ['libcrypto', 'busybox', 'openssl'],
            'low': ['common_lib', 'standard_service']
        }

    def _load_rules(self, rules_path: str) -> yara.Rules:
        """載入 YARA 規則"""
        try:
            if os.path.isdir(rules_path):
                # 如果是目錄，編譯所有 .yar 檔案
                rules = {}
                for file in Path(rules_path).glob('*.yar'):
                    rules[file.stem] = str(file)
                return yara.compile(filepaths=rules)
            else:
                # 如果是單一檔案，直接編譯
                return yara.compile(filepath=rules_path)
        except yara.Error as e:
            print(f"載入 YARA 規則時發生錯誤: {e}")
            raise

    def _determine_risk_level(self, matches: List[yara.Match]) -> str:
        """根據匹配的規則判斷風險等級"""
        matched_rules = [match.rule for match in matches]
        
        # 檢查高風險規則
        if any(any(risk in rule.lower() for risk in self.risk_levels['high']) 
               for rule in matched_rules):
            return '高'
        
        # 檢查中風險規則
        if any(any(risk in rule.lower() for risk in self.risk_levels['medium']) 
               for rule in matched_rules):
            return '中'
        
        return '低'

    def scan_file(self, file_path: str) -> Dict:
        """掃描單一檔案"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            matches = self.rules.match(data=data)
            risk_level = self._determine_risk_level(matches)
            
            return {
                'file': file_path,
                'matches': [{
                    'rule': match.rule,
                    'strings': [str(s) for s in match.strings]
                } for match in matches],
                'risk_level': risk_level
            }
        except Exception as e:
            print(f"掃描檔案 {file_path} 時發生錯誤: {e}")
            return {
                'file': file_path,
                'error': str(e)
            }

    def scan_directory(self, directory: str) -> List[Dict]:
        """掃描目錄中的所有檔案"""
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                results.append(self.scan_file(file_path))
        return results

    def print_report(self, results: List[Dict]):
        """輸出分析報告"""
        for result in results:
            print(f"\n掃描檔案: {result['file']}")
            print("-" * 20)
            
            if 'error' in result:
                print(f"錯誤: {result['error']}")
                continue
            
            for match in result['matches']:
                print(f"匹配規則: {match['rule']}")
                print("  字串:")
                for string in match['strings']:
                    print(f"    {string}")
            
            print(f"\n初步風險等級: {result['risk_level']}")
            print("-" * 20)

def main():
    parser = argparse.ArgumentParser(description='韌體分析工具')
    parser.add_argument('target', help='要分析的韌體檔案或目錄')
    parser.add_argument('--rules', required=True, help='YARA 規則檔案或目錄')
    
    args = parser.parse_args()
    
    analyzer = FirmwareAnalyzer(args.rules)
    
    if os.path.isfile(args.target):
        results = [analyzer.scan_file(args.target)]
    else:
        results = analyzer.scan_directory(args.target)
    
    analyzer.print_report(results)

if __name__ == '__main__':
    main() 