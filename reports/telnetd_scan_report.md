# Telnetd 掃描報告

## 掃描概述

- 掃描時間：YYYY-MM-DD HH:MM:SS
- 掃描目標：firmware_samples/infotainment_netgear.chk
- 使用規則：yara_rules/detect_telnetd.yar

## 掃描結果

| 項目         | 結果  |
| ------------ | ----- |
| Telnetd 存在 | 是/否 |
| 監聽端口     | 23    |
| 版本資訊     | -     |

## 風險評估

- 風險等級：高/中/低
- 影響範圍：遠程訪問、未加密通訊
- 建議措施：禁用 telnetd，改用 SSH

## 詳細發現

1. 發現位置：/usr/sbin/telnetd
2. 配置文件：/etc/inetd.conf
3. 啟動腳本：/etc/init.d/telnet

## 建議

1. 立即禁用 telnet 服務
2. 改用 SSH 進行遠程管理
3. 更新韌體版本
