# 韌體逆向工程分析

本文件將介紹如何對韌體進行逆向工程分析，主要涵蓋使用 `binwalk` 進行解包、使用 `Ghidra` 或 `IDA Pro` 進行靜態分析，以及在 ELF/ARM 二進制檔案中尋找關鍵元素。

## 1. 使用 binwalk 對韌體進行解包

**Binwalk** 是一款用於搜尋給定的二進制映像檔中嵌入的檔案和可執行代碼的工具 [1]。它特別設計用於識別韌體映像中的檔案和代碼 [1]。Binwalk 使用 `libmagic` 庫，因此與為 Unix `file` 實用程式創建的 magic 簽名相容 [1]。它還包含一個自定義 magic 簽名檔案，其中包含韌體映像中常見檔案（如壓縮/歸檔檔案、韌體標頭、Linux 核心、引導載入器、檔案系統等）的改進簽名 [1]。

### 解包過程

要使用 Binwalk 解包韌體映像，可以使用 `-e` 選項 [2]。此選項會自動提取已知的檔案類型 [3]。

執行指令範例：

```bash
binwalk -e firmware.img

Binwalk 在執行後會列出在韌體映像中找到的各種簽名和檔案
。提取的檔案會被放置在名為 _<filename>.extracted 的資料夾中，其中 <filename> 是被提取的檔案名
。
注意事項
•
遺失的提取工具: Binwalk 依賴於其他外部工具來提取某些檔案類型。如果在提取過程中遇到警告訊息，例如 "Extractor.execute failed to run external extractor 'sasquatch ...' : [Errno 2] No such file or directory: 'sasquatch'"
，表示您的系統可能缺少提取特定檔案格式所需的工具，您需要手動安裝這些工具。
•
符號連結 (Symlinks): 在提取檔案系統時，Binwalk 有時會遇到指向提取目錄之外的符號連結。出於安全考量，Binwalk 會將這些連結的目標更改為 /dev/null
。您需要注意這些警告，並在必要時手動檢查原始的符號連結目標。
•
輸出目錄: Binwalk 會在目前工作目錄下創建一個以原始韌體檔案名加上 .extracted 後綴的資料夾來存放提取的內容
。請確保您在執行 Binwalk 時有足夠的磁碟空間和寫入權限。
•
大型二進制檔案: 對於非常大的韌體映像，解包過程可能需要一些時間。
2. 使用 Ghidra 或 IDA Pro 進行靜態分析
靜態分析是在不執行程式碼的情況下分析二進制檔案的過程。Ghidra 是一款由美國國家安全局 (NSA) 開發並於 2019 年開源的免費逆向工程工具
。它可以反組譯二進制檔案，並提供反編譯功能，將組合語言轉換為類似 C 語言的偽代碼。IDA Pro 是一款商業級的反組譯器，被逆向工程師廣泛使用多年。Hex-Rays，IDA Pro 的開發者，也發布了一個免費版本
。
Ghidra 分析流程
1.
啟動 Ghidra: 運行 Ghidra 安裝目錄中的 ghidraRun.bat (Windows) 或 ghidraRun (Linux/macOS)
。
2.
創建新專案: 選擇 File -> New Project 並創建一個 Non-shared Project
。
3.
匯入二進制檔案: 在新專案中，選擇 File -> Import File... 並選擇您從 Binwalk 解包後得到的 ELF 檔案或其他二進制檔案
。
4.
選擇處理器: 匯入檔案時，Ghidra 可能會詢問檔案格式和處理器架構。您需要根據目標韌體的資訊選擇正確的處理器架構（例如 ARM Cortex-M4
）和 endianness（例如 Little Endian
）。如果 Ghidra 無法自動識別，您需要手動指定。
5.
分析二進制檔案: 匯入後，Ghidra 會詢問是否要分析二進制檔案。通常使用預設設定即可，但有時啟用 ARM Aggressive Instruction Finder 可能會有幫助
。點擊 Analyze 開始自動分析。
6.
檢視分析結果: 分析完成後，Ghidra 會顯示 CodeBrowser 視窗
，其中包含反組譯後的程式碼、函數列表、符號表等資訊。
7.
使用反編譯器: 在 Listing 視窗中選中一個函數，按下 P 鍵可以打開 Decompiler 視窗，查看類似 C 語言的偽代碼
。
IDA Pro 分析流程
IDA Pro 的基本使用流程類似 Ghidra：
1.
啟動 IDA Pro: 運行 IDA Pro 的可執行檔。
2.
載入檔案: 選擇 File -> Load file 並選擇要分析的二進制檔案
.
3.
配置載入器: IDA Pro 會嘗試自動識別檔案類型和處理器架構。如有必要，您可以手動配置載入器選項。
4.
等待自動分析: IDA Pro 會自動執行初步的分析。
5.
檢視反組譯結果: 分析完成後，您會在 IDA View 視窗中看到反組譯後的程式碼
。您可以使用 Space 鍵在圖形視圖和線性視圖之間切換
。
6.
使用反編譯器: 如果您的 IDA Pro 版本包含 Hex-Rays 反編譯器，您可以在 IDA View 視窗中選中一個函數，然後按下 F5 鍵來生成偽代碼並在 Pseudocode 視窗中查看
。
3. 如何在 ELF/ARM binary 中尋找 main, strings, libc 呼叫
尋找  函數
•
Ghidra: 在 Ghidra 的 Symbol Tree 視窗中，展開 Functions 目錄，通常可以找到名為 main 的函數。如果沒有直接找到，可以尋找 entry 函數，許多情況下 entry 函數會調用 main 函數
。
•
IDA Pro: 在 IDA Pro 的 Functions window (可通過 View -> Open subviews -> Functions 打開) 中，尋找名為 main 的函數
。IDA Pro 通常也能夠識別程序的入口點。
尋找字串 (Strings)
•
獨立工具 (strings): 在 Linux 或 macOS 環境下，可以使用 strings 命令列工具來提取二進制檔案中的可列印字串
。這對於快速了解程式中可能包含的訊息（例如錯誤訊息、檔案路徑、URL 等）非常有用
。
•
執行指令範例：
•
-n 7 表示只顯示長度至少為 7 個字元的字串，| less 用於分頁顯示輸出
。您也可以使用 grep 過濾輸出
。
•
-t x 選項可以在每個字串前面顯示其在檔案中的十六進制偏移量
。
•
Ghidra: 在 Ghidra 中，可以打開 Window -> Defined Strings 視窗來查看 Ghidra 自動識別的字串。您也可以使用 Search -> For String... 來搜尋特定的字串。
•
IDA Pro: 在 IDA Pro 中，可以打開 Strings window (可通過 View -> Open subviews -> Strings 打開) 來查看 IDA Pro 識別的字串。
尋找  呼叫
libc 是 C 標準函式庫，提供了許多常用的函數。在分析二進制檔案時，識別對 libc 函數的呼叫可以幫助理解程式的功能。
•
Ghidra: 在 Ghidra 的反組譯或反編譯視圖中，可以尋找以常見 libc 函數名稱開頭的函數呼叫，例如 printf、strcpy、malloc、free、fopen、fclose 等。Ghidra 通常會標記出外部函數呼叫。您也可以在 Symbol Tree 的 External Symbols 目錄下查看程式引用的外部符號，這些很可能包含 libc 函數。
•
IDA Pro: 在 IDA Pro 的反組譯或反編譯視圖中，可以尋找以常見 libc 函數名稱開頭的函數呼叫。IDA Pro 也會在 Imports 視窗 (可通過 View -> Open subviews -> Imports 打開) 中列出程式引用的外部庫函數。
分析時，注意這些函數的參數和返回值，可以幫助理解程式的行為。例如，對 strcpy 的呼叫需要仔細檢查目標緩衝區的大小，以判斷是否存在緩衝區溢出的風險。
4. Mermaid 流程圖

flowchart TD
    A[firmware.img] --> B(binwalk);
    B --> C{ELF file};
    C --> D(Ghidra);
    D --> E{call graph};
    E --> F{觀察漏洞點};

此流程圖展示了基本的韌體漏洞分析流程：從韌體映像檔開始，使用 binwalk 解包得到 ELF 檔案，然後使用 Ghidra 進行分析，觀察函數調用圖，最終尋找潛在的漏洞點。
補充
•
執行時指令：
•
分析到的可疑 function：
•
在靜態分析中，以下類型的函數可能需要特別關注，因為它們可能與安全漏洞相關：
◦
字串操作函數: strcpy、sprintf、strcat 等（可能導致緩衝區溢出）。
◦
記憶體操作函數: memcpy、memmove 等（可能導致越界讀寫）。
◦
網路相關函數: socket、bind、listen、accept、connect、recv、send 等（可能存在網路服務漏洞）。
◦
輸入驗證相關函數: 缺乏或不當的輸入驗證是常見的漏洞來源。
◦
特權操作相關函數: 任何執行提升權限操作的函數都需要仔細檢查。
◦
加密相關函數: 使用弱加密算法或不安全的加密實作可能導致安全問題。例如，如果程式中使用了如 [前次對話] 提到的 libcrypto (OpenSSL)
，需要檢查其使用方式是否存在已知的漏洞。
◦
與硬體互動的函數: 這些函數可能存在與硬體相關的漏洞。
◦
包含 "password"、"secret"、"key" 等關鍵字的函數名: 這些函數可能處理敏感資訊。
◦
與 telnetd [前次對話] 等高風險服務相關的函數: 這些服務容易受到攻擊。
•
可用 Ghidra snapshot 放入 screenshots/ 目錄做對照：
•
您可以在 Ghidra 中隨時拍攝當前分析狀態的快照，並將其儲存在 screenshots/ 目錄中以便後續參考或與他人分享。
1.
在 Ghidra 的 CodeBrowser 視窗中，調整視圖到您想要保存的狀態（例如，特定的函數反編譯結果、函數調用圖等）。
2.
使用作業系統的截圖工具（例如 Windows 的 Snipping Tool，macOS 的 Shift-Command-4，Linux 的 gnome-screenshot 或 scrot）截取當前 Ghidra 視窗的畫面。
3.
將截圖保存到您專案目錄下的 screenshots/ 資料夾中。如果該資料夾不存在，請先創建它：
4.
在您的 markdown 文件中，您可以使用圖片連結語法 ![snapshot description](screenshots/your_snapshot.png) 來引用這些截圖。例如：
•
請確保您的 screenshots/ 資料夾位於相對於 firmware_reverse_eng.md 檔案的正確路徑。
結論
韌體逆向工程是一個複雜但至關重要的過程，可以幫助我們理解嵌入式系統的運作方式並發現潛在的安全漏洞。透過使用 binwalk 進行解包和 Ghidra 或 IDA Pro 進行靜態分析，我們可以深入了解韌體的內部結構和程式邏輯，並為後續的安全分析和漏洞挖掘奠定基礎。
