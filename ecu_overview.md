# 車用 ECU 概觀

## 1. 什麼是 ECU？在車內有哪些功能分類？

**ECU (Electronic Control Unit)**，中文稱為**電子控制單元**，是汽車中負責控制一個或多個電子系統或子系統的嵌入式系統 [沒有相關資訊]。現代汽車包含許多 ECU，它們協同工作以實現車輛的各種功能。

根據功能，ECU 可以大致分類如下（此分類並非 AUTOSAR 標準定義，而是業界常見的劃分）：

*   **動力總成控制 (Powertrain Control):**
    *   **Engine ECU (引擎控制單元):** 控制燃油噴射、點火、排放控制等，以優化引擎性能和效率 [沒有相關資訊]。
    *   **Transmission ECU (變速箱控制單元):** 控制自動變速箱的換檔邏輯和操作 [沒有相關資訊]。
    *   **Motor Control Unit (馬達控制單元):** 控制電動車或混合動力車的驅動馬達 [沒有相關資訊]。
*   **車身電子 (Body Electronics):**
    *   **Body ECU (車身控制單元):** 控制車窗、車鎖、照明、雨刷、空調等舒適性和便利性功能 [沒有相關資訊]。
    *   **Instrument Cluster (儀表板):** 顯示車速、轉速、油量等車輛資訊 [沒有相關資訊]。
    *   **Airbag Control Unit (氣囊控制單元):** 在碰撞發生時觸發安全氣囊 [沒有相關資訊]。
*   **底盤控制 (Chassis Control):**
    *   **Brake ECU (煞車控制單元):** 控制 ABS (防鎖死煞車系統)、ESP (電子穩定程序) 等安全系統 [沒有相關資訊]。
    *   **Steering ECU (轉向控制單元):** 控制電子助力轉向系統 [沒有相關資訊]。
    *   **Suspension ECU (懸吊控制單元):** 控制主動懸吊系統以提高行駛舒適性和操控性 [沒有相關資訊]。
*   **資訊娛樂系統 (Infotainment):**
    *   **Head Unit (主機):** 提供音訊、導航、媒體播放、車輛資訊顯示等功能 [沒有相關資訊]。
    *   **Telematics ECU (車載資通訊單元):** 提供網路連接、緊急呼叫、遠程診斷等服務 [沒有相關資訊]。
*   **駕駛輔助系統 (Advanced Driver-Assistance Systems, ADAS):**
    *   **Camera ECU (攝影機控制單元):** 處理來自車載攝影機的影像數據，用於環景監控、車道保持輔助等功能 [沒有相關資訊]。
    *   **Radar ECU (雷達控制單元):** 處理來自雷達感測器的數據，用於自動緊急煞車、ACC (主動巡航控制) 等功能 [沒有相關資訊]。

## 2. 與 CAN Bus 的通訊關係（簡單流程）

**CAN Bus (Controller Area Network)** 是一種常見的車用網路技術，用於讓不同的 ECU 之間能夠互相通訊 [1]。ECU 通過 CAN Bus 交換訊息，以協調車輛的各種操作。

簡單的通訊流程如下：

1.  **ECU 產生訊息:** 當一個 ECU 需要將資訊傳送給其他 ECU 時，它會將資訊封裝成一個 CAN 訊息，包含訊息的 ID (識別符)、數據內容等 [1, 2]。
2.  **訊息傳送至 CAN Bus:** ECU 將封裝好的 CAN 訊息發送到 CAN Bus 網路 [1, 2]。CAN Bus 是一個兩線式的匯流排系統 [沒有相關資訊]。
3.  **所有 ECU 接收訊息:** 連接到 CAN Bus 上的所有 ECU 都會接收到這個訊息 [1, 2]。
4.  **ECU 判斷是否處理:** 每個 ECU 會根據 CAN 訊息中的 ID 判斷這個訊息是否是發送給自己的，如果是，則會解析並處理訊息中的數據 [1, 2]。如果不是，則會忽略該訊息 [沒有相關資訊]。
5.  **執行相應操作:** 接收到訊息並處理的 ECU 會根據訊息內容執行相應的操作，例如控制某個硬體、更新內部狀態等 [沒有相關資訊]。

Copperhill Technologies 提供的產品和服務涵蓋了 CAN Bus、CAN FD 等技術，以及基於 Arduino、Raspberry Pi 等平台的 CAN Bus 介面和解決方案 [1, 3, 4]。

## 3. AUTOSAR 架構與 ECU 的角色分工

**AUTOSAR (AUTomotive Open System ARchitecture)** 是一個開放的汽車軟體架構標準，旨在提高汽車電子系統的複雜性管理、軟體的可重用性和可交換性 [5]。

在 AUTOSAR 架構中，一個 ECU 會包含以下主要層級 [6]：

*   **應用層 (Application Layer):** 包含特定車輛功能 (例如 ABS 控制、引擎管理) 的軟體組件 (Software Components) [7, 8]。
*   **運行時環境 (Runtime Environment, RTE):** 提供應用層軟體組件之間的通訊和與基礎軟體 (BSW) 的互動 [7]。RTE 抽象了底層硬體和通訊細節 [7]。
*   **基礎軟體 (Basic Software, BSW):** 包含標準化的軟體模組，提供底層的功能，例如：
    *   **系統服務 (System Services):** 作業系統 (OS)、Watchdog 管理器、診斷服務等 [7, 9]。
    *   **記憶體 (Memory):** 提供對非揮發性記憶體 (Flash、EEPROM) 的存取 [7, 9]。
    *   **通訊 (Communication):** 包含整個 AUTOSAR 通訊堆疊 (COM-Stack)，例如 CAN、以太網路、網路管理等 [7, 9]。
    *   **I/O 硬體抽象 (IO HW-Abstraction):** 提供對感測器和致動器的硬體介面抽象 [7, 9]。
*   **複雜驅動 (Complex Drivers):** 用於控制複雜或非標準化的硬體 [7]。

**ECU 在 AUTOSAR 架構中的角色**是作為這些軟體層的**執行載體**。每個 ECU 根據其負責的功能，會配置和部署相應的 AUTOSAR 軟體模組和應用軟體組件。ECU 的配置 (ECU Configuration) 是 AUTOSAR 中非常重要的一環，AUTOSAR 提供了一套詳細的規範 (如 `AUTOSAR_TPS_ECUConfiguration.pdf` [5]) 來描述如何配置 ECU 中的各個軟體模組，包括參數定義 (ECU Configuration Parameter Definition) 和實際的配置值 (ECU Configuration Value) [10]。

AUTOSAR 的 ECU 配置流程涉及 **ECU 提取 (ECU Extract)** 和 **BSW 模組交付包 (BSW Module Delivered Bundle)** 作為輸入，通過 **準備 ECU 配置 (Prepare ECU Configuration)** 和 **配置 BSW 和 RTE (Configure BSW and RTE)** 等活動，最終生成 **ECU 配置值 (ECU Configuration Values)** 和其他輸出 [11, 12]。

## 4. ECU → CAN → Application Stack 的訊號流程 (Mermaid)

```mermaid
graph TB
    subgraph ECU
        direction LR
        App1((Application Software 1)) --> RTE
        App2((Application Software 2)) --> RTE
        RTE --> ComMgt(Communication Management)
        ComMgt --> PduR(PDU Router)
        PduR --> CanIf(CAN Interface)
        CanIf --> CanDrv(CAN Driver)
    end

    CanDrv -- CAN訊號 --> CAN((CAN Bus))

    subgraph Other ECU
        direction LR
        OtherCanDrv(CAN Driver) --> OtherCanIf(CAN Interface)
        OtherCanIf --> OtherPduR(PDU Router)
        OtherPduR --> OtherComMgt(Communication Management)
        OtherComMgt --> OtherRTE(RTE)
        OtherRTE --> OtherApp((Application Software))
    end

    CAN --> OtherCanDrv

流程說明:
1.
應用軟體組件 (例如 App1) 需要發送訊息時，會通過運行時環境 (RTE) 將資料傳遞給通訊管理模組 (ComMgt)。
2.
通訊管理模組 (ComMgt) 將資料轉發給 PDU 路由器 (PduR)，PduR 負責將 PDU (Protocol Data Unit) 路由到正確的通訊介面。
3.
對於 CAN 通訊，PDU 會被路由到 CAN 介面 (CanIf)。
4.
CAN 介面 (CanIf) 會處理 PDU，並將其傳遞給底層的 CAN 驅動程式 (CanDrv)。
5.
CAN 驅動程式 (CanDrv) 負責將訊息編碼並通過 CAN Bus 物理層傳輸出去。
6.
CAN Bus 上的其他 ECU 的 CAN 驅動程式 (OtherCanDrv) 會接收到這個訊號。
7.
接收端 ECU 的 CAN 驅動程式將訊號解碼並傳遞給 CAN 介面 (OtherCanIf)。
8.
CAN 介面將數據傳遞給 PDU 路由器 (OtherPduR)。
9.
PDU 路由器根據訊息 ID 將數據路由到上層的通訊管理模組 (OtherComMgt)。
10.
通訊管理模組將數據通過運行時環境 (OtherRTE) 傳遞給接收端的應用軟體組件 (OtherApp)。
5. 常見的 ECU 與其用途
ECU 類型
	
主要用途
Body ECU
	
控制車窗、車鎖、照明、雨刷、空調等車身舒適性和便利性功能
Engine ECU
	
控制引擎燃油噴射、點火、排放控制，優化引擎性能和效率
Transmission ECU
	
控制自動變速箱的換檔邏輯和操作
Brake ECU
	
控制 ABS、ESP 等煞車安全系統
Steering ECU
	
控制電子助力轉向系統
Instrument Cluster
	
顯示車速、轉速、油量等車輛資訊
Infotainment
	
提供音訊、導航、媒體播放、車輛資訊顯示等功能
Airbag ECU
	
在碰撞發生時觸發安全氣囊
Gateway ECU
	
連接車輛內不同的網路 (例如 CAN、LIN、乙太網路)，實現不同網路之間的通訊和路由
