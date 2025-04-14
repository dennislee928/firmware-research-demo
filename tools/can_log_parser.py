#!/usr/bin/env python3
import sys
import json
import yaml
from datetime import datetime
import re

def parse_can_log(log_file):
    messages = []
    errors = []
    
    with open(log_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            try:
                # 解析每一行 CAN 訊息
                timestamp, can_id, data_len, data = [x.strip() for x in line.split(',')]
                
                # 驗證數據格式
                if not re.match(r'^0x[0-9A-F]+$', can_id):
                    errors.append(f"無效的 CAN ID 格式: {can_id}")
                    continue
                    
                data_bytes = data.split()
                if len(data_bytes) != int(data_len):
                    errors.append(f"數據長度不匹配: 預期 {data_len} 但實際為 {len(data_bytes)}")
                    continue
                    
                # 檢查數據是否為有效的十六進制
                for byte in data_bytes:
                    if not re.match(r'^[0-9A-F]{2}$', byte):
                        errors.append(f"無效的數據格式: {data}")
                        break
                else:
                    messages.append({
                        'timestamp': timestamp,
                        'can_id': can_id,
                        'data_length': int(data_len),
                        'data': data_bytes
                    })
                    
            except ValueError as e:
                errors.append(f"解析錯誤: {str(e)}")
                
    return messages, errors

def main():
    if len(sys.argv) != 2:
        print("使用方法: python can_log_parser.py <log_file>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    messages, errors = parse_can_log(log_file)
    
    # 生成輸出文件名
    base_name = log_file.rsplit('.', 1)[0]
    json_file = f"{base_name}_parser_output.json"
    yaml_file = f"{base_name}_anomaly_flags.yaml"
    
    # 輸出 JSON 結果
    with open(json_file, 'w') as f:
        json.dump({
            'messages': messages,
            'errors': errors,
            'summary': {
                'total_messages': len(messages),
                'total_errors': len(errors),
                'timestamp': datetime.now().isoformat()
            }
        }, f, indent=2)
        
    # 輸出 YAML 異常標記
    with open(yaml_file, 'w') as f:
        yaml.dump({
            'anomalies': errors,
            'timestamp': datetime.now().isoformat()
        }, f, default_flow_style=False)
        
    print(f"解析完成！")
    print(f"JSON 輸出: {json_file}")
    print(f"YAML 輸出: {yaml_file}")
    
if __name__ == "__main__":
    main()
