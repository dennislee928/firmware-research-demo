# 韌體元件偵測報告 (`component_detection.md`)

本文旨在說明 BusyBox、telnetd 與 libcrypto 這三個常見於韌體中的元件的功能，並示範如何使用 YARA 規則來偵測它們。

## 1. BusyBox、telnetd、libcrypto 在韌體中的功能

*   **BusyBox**: BusyBox 是一個將許多常見的 **小型 Linux 命令列工具** 整合到單一可執行檔的工具 [1]。由於其體積小巧，因此常被應用於 **嵌入式系統** 和系統開機時的 `initrd` 程序中 [1]。BusyBox 提供了例如 `ls`、`cp`、`mv`、`vi` 等常用命令的基本功能 [1, 2]。不同的 BusyBox 編譯版本可能包含不同的 applet（功能） [1, 3, 4]。

*   **telnetd**: `telnetd` 是一個 **Telnet 伺服器**。Telnet 是一種網路協定，允許使用者透過文字介面 **遠端登入** 到伺服器並執行命令。在韌體中包含 `telnetd`，表示該設備可能允許使用者透過 Telnet 連線進行管理或存取。

*   **libcrypto**: `libcrypto` 是 **OpenSSL 專案中的核心加密函式庫** [5]。OpenSSL 是一個非常流行的函式庫，提供了各種 **加密演算法**、**安全通訊協定** (例如 TLS/SSL)、以及 **憑證管理** 等功能 [5]。`libcrypto` 負責提供底層的加密運算，例如對稱加密、非對稱加密、雜湊演算法等。韌體中使用 `libcrypto` 通常是為了實現資料的 **加密保護**、**安全驗證** 或建立 **安全連線**。

## 2. 示範 YARA 規則來偵測這些元件

以下提供一些簡單的 YARA 規則範例，用於偵測 BusyBox、telnetd 和使用了 libcrypto 的元件。這些規則主要基於程式中可能包含的特定字串。

```yara
rule detect_busybox {
  meta:
    description = "Detect BusyBox executable"
    author = "Your Name"
    date = "2024-11-16"
  strings:
    $a = "BusyBox v" ascii wide nocase
    $b = "applets:" ascii wide nocase
  condition:
    all of ($a, $b)
}

rule detect_telnetd {
  meta:
    description = "Detect telnetd executable or related strings"
    author = "Your Name"
    date = "2024-11-16"
  strings:
    $a = "telnetd" ascii wide nocase
    $b = "Telnet Server" ascii wide nocase
  condition:
    any of ($a, $b)
}

rule detect_libcrypto {
  meta:
    description = "Detect usage of libcrypto (OpenSSL)"
    author = "Your Name"
    date = "2024-11-16"
  strings:
    $a = "OpenSSL" ascii wide
    $b = "libcrypto.so" ascii wide
  condition:
    any of ($a, $b)
}

說明:
•
detect_busybox: 此規則尋找包含 "BusyBox v" 和 "applets:" 字串（忽略大小寫）的檔案，這兩個字串通常出現在執行 busybox 不帶任何參數時的輸出中
。
•
detect_telnetd: 此規則尋找包含 "telnetd" 或 "Telnet Server" 字串（忽略大小寫）的檔案，這些字串可能出現在 telnetd 可執行檔或相關設定檔中。
•
detect_libcrypto: 此規則尋找包含 "OpenSSL" 或 "libcrypto.so" 字串的檔案，前者是 OpenSSL 的常見標識，後者是其動態函式庫的常見名稱。
注意: 這些是非常基礎的規則，可能產生誤報或漏報。更精確的偵測通常需要分析二進制模式。
3. 用  CLI 或  套件執行掃描，附上結果
假設我們有一個名為 firmware.bin 的韌體檔案，並且已將上述 YARA 規則儲存為 detection_rules.yar。
使用 yara CLI 執行掃描:
在終端機中執行以下命令：

yara detection_rules.yar firmware.bin

可能的輸出結果範例：

detect_busybox firmware.bin
detect_libcrypto firmware.bin

這個結果表示 firmware.bin 檔案符合了 detect_busybox 和 detect_libcrypto 這兩個規則。
使用 yara-python 套件執行掃描:
首先確保您已安裝 yara-python 套件：

pip install yara-python

然後，您可以編寫一個 Python 腳本來執行掃描：

import yara

rules = yara.compile(filepath='detection_rules.yar')
matches = rules.match(data=open('firmware.bin', 'rb').read())

for match in matches:
    print(f"Match found for rule: {match.rule}")

可能的輸出結果範例：

Match found for rule: detect_busybox
Match found for rule: detect_libcrypto

這個結果與使用 yara CLI 的結果相同，表明在 firmware.bin 中偵測到了 BusyBox 和使用了 libcrypto 的元件。
4. 使用 mermaid 畫一個 ：

flowchart LR
    A[Extracted File] --> B{YARA Scan};
    B -- Match: busybox, openssl --> C[Result Summary];
    B -- No Match --> C;

這個流程圖描述了對提取出的檔案進行 YARA 掃描的過程。如果掃描結果匹配了關於 busybox 或 openssl 的規則，則會在結果摘要中標示出來。如果沒有匹配，也會產生結果摘要。
額外補充：元件功能與安全風險等級
元件
	
功能
	
安全風險等級
BusyBox
	
提供多個小型 Linux 命令列工具的基本功能，用於嵌入式系統和開機過程
	
中
telnetd
	
提供 Telnet 伺服器功能，允許遠端文字介面登入和執行命令
	
高
libcrypto
	
提供底層的加密演算法和安全通訊協定功能
	
中至高
安全風險等級說明:
•
BusyBox: BusyBox 本身是一個工具集合，其安全風險取決於所包含的 applet 以及這些 applet 是否存在漏洞。若包含不必要的或有已知漏洞的 applet，則可能構成安全風險。
•
telnetd: Telnet 是一種 不加密 的通訊協定，所有傳輸的資料（包括登入憑證和命令）都是明文的。因此，在生產環境或不可信任的網路中使用 telnetd 會導致嚴重的安全風險，容易被竊聽和中間人攻擊。
•
libcrypto: libcrypto 的安全風險主要來自其 實現中的漏洞 (例如 Heartbleed
) 以及 不正確的使用。儘管加密本身是保護安全的重要手段，但如果函式庫存在漏洞或開發者使用不當，反而會引入安全風險。因此，及時更新 OpenSSL 版本以修補已知漏洞至關重要。
