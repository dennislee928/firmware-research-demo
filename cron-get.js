// 使用 Cloudflare Workers 的環境變數
const API_URL = "https://openapi.twse.com.tw/v1/opendata/t187ap19";

// 初始化資料庫
async function initDB(db) {
  // 修正 SQL 語句，放在單行中
  await db.exec(
    "CREATE TABLE IF NOT EXISTS trading_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, trading_month TEXT, new_accounts TEXT, closed_accounts TEXT, total_accounts TEXT, trading_accounts TEXT, trading_users TEXT, order_count TEXT, order_amount TEXT, trade_count TEXT, trade_amount TEXT, avg_trade_amount TEXT, company_trade_count TEXT, company_trade_amount TEXT, company_trade_ratio_count TEXT, company_trade_ratio_amount TEXT, market_trade_count TEXT, market_trade_amount TEXT, market_trade_ratio_count TEXT, market_trade_ratio_amount TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
  );
}

// 檢查回應是否為有效的 JSON
async function isValidJSON(response) {
  const contentType = response.headers.get("content-type");
  if (!contentType || !contentType.includes("application/json")) {
    console.error(`非 JSON 回應，Content-Type: ${contentType}`);
    return false;
  }

  try {
    // 嘗試獲取文本內容並解析 JSON
    const text = await response.text();
    if (
      text.trim().startsWith("<!DOCTYPE") ||
      text.trim().startsWith("<html")
    ) {
      console.error("回應是 HTML 而不是 JSON");
      console.error("回應內容片段:", text.substring(0, 100));
      return false;
    }

    JSON.parse(text);
    return true;
  } catch (error) {
    console.error("JSON 解析錯誤:", error.message);
    return false;
  }
}

// 獲取交易統計資料的函數
async function fetchTradingStats(db) {
  try {
    console.log("開始獲取電子式交易統計資訊...");
    console.log("使用 API 端點:", API_URL);

    // 設定請求選項
    const options = {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": "Cloudflare Worker",
        "If-Modified-Since": "Mon, 26 Jul 1997 05:00:00 GMT",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
      },
    };

    const response = await fetch(API_URL, options);

    // 檢查 HTTP 狀態
    if (!response.ok) {
      console.error(`API 回應狀態碼: ${response.status}`);
      console.error(`API 回應狀態文本: ${response.statusText}`);

      // 嘗試讀取錯誤回應內容
      const errorText = await response.text();
      console.error("錯誤回應內容:", errorText.substring(0, 200));

      throw new Error(`API 回應狀態碼: ${response.status}`);
    }

    // 取得回應的完整 URL (包含重定向後的 URL)
    console.log("實際回應 URL:", response.url);

    // 檢查回應標頭
    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    console.log("回應標頭:", headers);

    // 直接讀取回應內容
    const responseText = await response.text();
    console.log("回應內容片段:", responseText.substring(0, 200));

    // 檢查是否為有效的 JSON
    try {
      const dataArray = JSON.parse(responseText);
      const timestamp = new Date().toISOString();

      // 檢查資料結構
      if (!Array.isArray(dataArray)) {
        console.log("API 回應不是陣列:", dataArray);
        throw new Error("API 回應格式不正確: 預期陣列但接收到其他格式");
      }

      if (dataArray.length === 0) {
        console.log("API 回應陣列為空");
        throw new Error("API 回應陣列為空");
      }

      console.log("API 回應資料:", dataArray);

      // 取得陣列中的第一個元素作為資料
      const data = dataArray[0];
      console.log("處理資料項目:", data);

      // 儲存到 D1 資料庫 - 修改為單行 SQL
      const stmt = db.prepare(
        "INSERT INTO trading_stats (timestamp, trading_month, new_accounts, closed_accounts, total_accounts, trading_accounts, trading_users, order_count, order_amount, trade_count, trade_amount, avg_trade_amount, company_trade_count, company_trade_amount, company_trade_ratio_count, company_trade_ratio_amount, market_trade_count, market_trade_amount, market_trade_ratio_count, market_trade_ratio_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      );

      await stmt
        .bind(
          timestamp,
          data.成交月份 || "",
          data.本月新增戶數 || "",
          data.本月註銷戶數 || "",
          data.累計開戶數 || "",
          data.本月交易戶數 || "",
          data.本月交易人數 || "",
          data.委託筆數 || "",
          data.委託金額 || "",
          data.成交筆數 || "",
          data.成交金額 || "",
          data.平均每筆成交金額 || "",
          data.公司總成交筆數 || "",
          data.公司總成交金額 || "",
          data["占公司成交比率(筆數)"] || "",
          data["占公司成交比率(金額)"] || "",
          data["市場成交總筆數(買賣合計)"] || "",
          data["市場成交總金額(買賣合計)"] || "",
          data["占市場成交比率(筆數)"] || "",
          data["占市場成交比率(金額)"] || ""
        )
        .run();

      // 記錄重要資訊
      console.log(`成交月份: ${data.成交月份 || "N/A"}`);
      console.log(`本月交易戶數: ${data.本月交易戶數 || "N/A"}`);
      console.log(`成交金額: ${data.成交金額 || "N/A"}`);
      console.log(
        `占市場成交比率(金額): ${data["占市場成交比率(金額)"] || "N/A"}`
      );

      return new Response(
        JSON.stringify({
          success: true,
          message: "資料獲取成功",
          timestamp: timestamp,
          data: data,
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    } catch (jsonError) {
      console.error("解析 JSON 失敗:", jsonError.message);
      throw new Error(
        `解析 JSON 失敗: ${
          jsonError.message
        }, 回應內容: ${responseText.substring(0, 100)}`
      );
    }
  } catch (error) {
    console.error(`獲取資料失敗: ${error.message}`);
    console.error(`錯誤堆疊: ${error.stack}`);
    return new Response(
      JSON.stringify({
        success: false,
        message: error.message,
        error_stack: error.stack,
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}

// 處理 HTTP 請求
export default {
  async fetch(request, env) {
    try {
      // 解析請求 URL
      const url = new URL(request.url);
      const path = url.pathname;

      // 初始化資料庫
      await initDB(env.DB);

      // 路由處理
      if (path === "/fetch") {
        // 手動觸發資料獲取
        return await fetchTradingStats(env.DB);
      } else if (path === "/check") {
        // 查詢最近的資料
        const result = await env.DB.prepare(
          "SELECT * FROM trading_stats ORDER BY id DESC LIMIT 5"
        ).all();
        return new Response(
          JSON.stringify({
            success: true,
            message: "查詢最近資料成功",
            data: result.results,
          }),
          {
            headers: { "Content-Type": "application/json" },
          }
        );
      } else if (path === "/") {
        // 簡單的 HTML 首頁，提供手動操作按鈕
        return new Response(
          `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TWSE 交易統計資料獲取器</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
              h1 { color: #333; }
              .btn { 
                display: inline-block; padding: 10px 15px; 
                background: #4CAF50; color: white; border: none; 
                cursor: pointer; margin-right: 10px; border-radius: 4px;
                text-decoration: none;
              }
              .btn:hover { background: #45a049; }
              pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow: auto; }
              #result { margin-top: 20px; }
            </style>
          </head>
          <body>
            <h1>TWSE 交易統計資料獲取器</h1>
            <p>使用下方按鈕手動觸發資料獲取或查詢資料庫中的數據。</p>
            
            <button class="btn" onclick="fetchData()">立即獲取資料</button>
            <button class="btn" onclick="checkData()">查詢最近資料</button>
            
            <div id="result"></div>
            
            <script>
              async function fetchData() {
                const resultElement = document.getElementById('result');
                resultElement.innerHTML = '處理中，請稍候...';
                
                try {
                  const response = await fetch('/fetch');
                  const data = await response.json();
                  resultElement.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                } catch (error) {
                  resultElement.innerHTML = '<pre>錯誤: ' + error.message + '</pre>';
                }
              }
              
              async function checkData() {
                const resultElement = document.getElementById('result');
                resultElement.innerHTML = '處理中，請稍候...';
                
                try {
                  const response = await fetch('/check');
                  const data = await response.json();
                  resultElement.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                } catch (error) {
                  resultElement.innerHTML = '<pre>錯誤: ' + error.message + '</pre>';
                }
              }
            </script>
          </body>
          </html>
        `,
          {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          }
        );
      } else {
        // 404 錯誤
        return new Response("找不到頁面", { status: 404 });
      }
    } catch (error) {
      return new Response(
        JSON.stringify({
          success: false,
          message: error.message,
          stack: error.stack,
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },

  // 設定定時任務
  async scheduled(event, env) {
    try {
      // 初始化資料庫
      await initDB(env.DB);

      // 執行獲取資料的任務
      await fetchTradingStats(env.DB);
    } catch (error) {
      console.error(`排程任務錯誤: ${error.message}`);
      console.error(error.stack);
    }
  },
};
