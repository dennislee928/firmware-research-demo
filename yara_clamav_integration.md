# YARA 與 ClamAV 在韌體分析中的整合應用

這份文件簡要介紹了 YARA 和 ClamAV 的基本概念與使用方式，並探討如何在韌體分析中整合這兩種工具，以提升惡意軟體和潛在威脅的檢測能力，特別是針對車用電子元件。

## 1. YARA 的基本概念與用途

**YARA 是一個旨在協助識別與分類惡意軟體的工具** [1, 2]。它透過使用者定義的規則，基於**文字或二進制模式**在檔案中進行匹配 [1]。YARA 規則可以描述惡意軟體的特徵，例如特定的字串、十六進制模式或行為模式 [3]。

**用途：**
*   **惡意軟體分析與檢測**：識別已知的惡意軟體家族或變種 [4].
*   **威脅情資共享**：安全研究人員可以分享他們創建的 YARA 規則，以協助社群檢測新的威脅 [5].
*   **靜態檔案分析**：在不執行程式碼的情況下分析檔案內容 [5].
*   **事件響應**：在受感染的系統中搜尋與特定威脅相關的檔案 [6].

## 2. 針對車用常見元件的 YARA 規則範例

以下展示了幾個針對車用常見元件（如 busybox, openssl）的簡單 YARA 規則。請注意，這些是基礎範例，實際應用中可能需要更複雜的規則以避免誤報。

### 針對 Busybox 的規則

Busybox 是一個為嵌入式系統提供許多標準 Unix 工具的單一可執行檔。以下規則嘗試識別包含 Busybox 特有字串的檔案：

```yara
rule automotive_busybox_strings
{
    meta:
        author = "Your Name"
        description = "Detects files likely containing Busybox"
        date = "2024-11-16"
    strings:
        $a = "BusyBox v" ascii wide nocase
        $b = "applets:" ascii wide
        $c = "Usage: busybox [function] [arguments]..." ascii wide
    condition:
        all of ($a, $b, $c)
}

這個規則會尋找檔案中是否同時包含 "BusyBox v"、"applets:" 和 "Usage: busybox" 這三個字串（忽略大小寫）。
針對 OpenSSL 的規則
OpenSSL 是一個廣泛使用的加密函式庫。以下規則嘗試識別包含 OpenSSL 特有版本字串的檔案：

rule automotive_openssl_version_string
{
    meta:
        author = "Your Name"
        description = "Detects files containing OpenSSL version strings"
        date = "2024-11-16"
    strings:
        $a = "OpenSSL " ascii wide
        $b = "TLSv1." ascii wide
        $c = "SSLv3 " ascii wide
    condition:
        $a and ( $b or $c )
}

這個規則會尋找包含 "OpenSSL " 字串，並且同時包含 "TLSv1." 或 "SSLv3 " 字串的檔案。更精確的規則可以針對特定的 OpenSSL 版本漏洞（如
 中提到的）進行編寫。
3. 使用 yara-python 在 CLI 進行掃描
yara-python 是 YARA 的 Python 介面，允許在 Python 腳本中使用 YARA 規則
。雖然沒有直接提供 CLI 工具，但我們可以編寫一個簡單的 Python 腳本來實現 CLI 掃描功能。
安裝 yara-python：
首先，您需要安裝 yara-python 函式庫
：

pip install yara-python

CLI 掃描範例腳本 (scan_file.py)：

import yara
import sys

if len(sys.argv) != 3:
    print("Usage: python scan_file.py <rules_file> <target_file>")
    sys.exit(1)

rules_file = sys.argv[10]
target_file = sys.argv[11]

try:
    rules = yara.compile(filepath=rules_file)
    with open(target_file, 'rb') as f:
        matches = rules.match(data=f.read())

    if matches:
        print(f"Matches found in {target_file}:")
        for match in matches:
            print(f"  Rule: {match.rule}")
            for string in match.strings:
                print(f"    String Identifier: {string.identifier}, Offset: {string.offset}, Value: {string.value}")
    else:
        print(f"No matches found in {target_file}.")

except yara.Error as e:
    print(f"Error compiling rules: {e}")
except FileNotFoundError:
    print(f"Error: File not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

使用方式：
1.
將您的 YARA 規則儲存到一個檔案中（例如 automotive_rules.yara）。
2.
將上面的 Python 腳本儲存為 scan_file.py。
3.
在終端機中執行掃描：
輸出範例：
如果找到匹配，輸出可能如下所示：

Matches found in /path/to/your/firmware/file:
  Rule: automotive_busybox_strings
    String Identifier: $a, Offset: 12345, Value: b'BusyBox v1.35.0'
    String Identifier: $b, Offset: 13000, Value: b'applets: ...'
    String Identifier: $c, Offset: 13500, Value: b'Usage: busybox [function] [arguments]...'

4. 補充 ClamAV 的使用方式
ClamAV 是一個開源的反病毒工具包
。它主要用於電子郵件閘道的掃描，但也提供命令列掃描工具 clamscan，可以用於掃描檔案和目錄
.
掃描解包的韌體目錄：
假設您已經使用如 binwalk
 等工具解包了韌體檔案，並得到一個包含解包內容的目錄（例如 firmware_extracted）。您可以使用 clamscan 命令來掃描這個目錄：

clamscan -r firmware_extracted

•
-r 或 --recursive：遞迴掃描指定目錄下的所有子目錄和檔案
.
常用選項：
•
-v 或 --verbose：顯示詳細的掃描資訊
.
•
--infected：只顯示被感染的檔案。
•
--remove：移除被感染的檔案（謹慎使用）。
•
--move=<directory>：將被感染的檔案移動到指定的目錄。
•
-l <logfile> 或 --log=<logfile>：將掃描結果記錄到指定的檔案
.
•
-d <signature_file>：從指定的簽名檔載入病毒定義
. 預設情況下，clamscan 會載入透過 freshclam 更新的官方病毒庫
.
•
--exclude=<pattern>：排除符合指定模式的檔案或目錄。
掃描特定檔案類型：
您可以使用 --include 和 --exclude 選項來限制掃描的檔案類型。例如，只掃描可執行檔：

clamscan -r --include='*.elf' firmware_extracted

輸出範例：
ClamAV 的掃描輸出可能如下所示：

firmware_extracted/bin/busybox: OK
firmware_extracted/lib/libcrypto.so.1.1: OK
firmware_extracted/sbin/init: Linux.Malware.Agent-123 FOUND
firmware_extracted/etc/passwd: OK

----------- SCAN SUMMARY -----------
Known viruses: 8634517
Engine version: 0.103.10
Scanned directories: 15
Scanned files: 123
Infected files: 1
Data scanned: 12.34 MB
Data read: 15.67 MB
Time: 15.230 sec

在這個範例中，firmware_extracted/sbin/init 被 ClamAV 偵測為 Linux.Malware.Agent-123。
5. 韌體掃描流程圖

flowchart TD
    A[Firmware] --> B(YARA Scan);
    B -- Match --> C[Match Result (YARA)];
    A --> D(ClamAV Scan);
    D -- Hit --> E[Match Result (ClamAV)];
    C --> F[Report];
    E --> F;

這個流程圖展示了韌體檔案首先被 YARA 掃描，然後再被 ClamAV 掃描。兩個工具的匹配結果最終會匯總到一份報告中。
補充結果輸出樣式範例：
結合 YARA 和 ClamAV 的掃描結果，最終報告可能包含以下資訊：
CLI Log 顯示 YARA matches：

YARA Scan Results:
------------------
Matches found in firmware_extracted/bin/app:
  Rule: automotive_busybox_strings
    String Identifier: $a, Offset: 1020, Value: b'BusyBox v1.35.0'
    String Identifier: $b, Offset: 1500, Value: b'applets: ...'
    String Identifier: $c, Offset: 2000, Value: b'Usage: busybox [function] [arguments]...'

Matches found in firmware_extracted/lib/libcrypto.so.1.1:
  Rule: automotive_openssl_version_string
    String Identifier: $a, Offset: 5678, Value: b'OpenSSL 1.1.1w'
    String Identifier: $b, Offset: 6000, Value: b'TLSv1.2'

CLI Log 顯示 ClamAV hits：

ClamAV Scan Results:
-------------------
firmware_extracted/sbin/malicious_binary: Linux.Trojan.Evil FOUND

透過整合 YARA 和 ClamAV，我們可以利用 YARA 的彈性規則匹配能力來檢測特定的模式和行為，同時使用 ClamAV 的廣泛病毒庫來識別已知的惡意軟體，從而更全面地分析韌體的安全性。
