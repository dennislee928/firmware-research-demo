const cron = require("node-cron");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const moment = require("moment");

// 設定日誌目錄
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// 設定資料儲存目錄
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

// 使用 Cloudflare Workers 的環境變數
const API_URL = "https://openapi.twse.com.tw/v1/statistics/electronic_trading";
const KV_NAMESPACE = "TRADING_STATS"; // 在 Cloudflare Workers 中設定的 KV 命名空間

// 記錄日誌的函數
function logMessage(message) {
  const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
  const logMessage = `[${timestamp}] ${message}\n`;
  const logFile = path.join(
    logDir,
    `trading_stats_${moment().format("YYYY-MM-DD")}.log`
  );

  fs.appendFile(logFile, logMessage, (err) => {
    if (err) console.error("寫入日誌失敗:", err);
  });

  console.log(logMessage);
}

// 儲存資料的函數
async function saveData(data) {
  try {
    const timestamp = moment().format("YYYY-MM-DD_HH-mm-ss");
    const fileName = `trading_stats_${timestamp}.json`;
    const filePath = path.join(dataDir, fileName);

    await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2));
    logMessage(`資料已儲存至: ${fileName}`);
  } catch (error) {
    logMessage(`儲存資料失敗: ${error.message}`);
  }
}

// 初始化資料庫
async function initDB(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS trading_stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      trading_month TEXT,
      new_accounts TEXT,
      closed_accounts TEXT,
      total_accounts TEXT,
      trading_accounts TEXT,
      trading_users TEXT,
      order_count TEXT,
      order_amount TEXT,
      trade_count TEXT,
      trade_amount TEXT,
      avg_trade_amount TEXT,
      company_trade_count TEXT,
      company_trade_amount TEXT,
      company_trade_ratio_count TEXT,
      company_trade_ratio_amount TEXT,
      market_trade_count TEXT,
      market_trade_amount TEXT,
      market_trade_ratio_count TEXT,
      market_trade_ratio_amount TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// 獲取交易統計資料的函數
async function fetchTradingStats(db) {
  try {
    console.log("開始獲取電子式交易統計資訊...");

    const response = await fetch(API_URL);
    const data = await response.json();
    const timestamp = new Date().toISOString();

    // 儲存到 D1 資料庫
    await db
      .prepare(
        `
      INSERT INTO trading_stats (
        timestamp, trading_month, new_accounts, closed_accounts,
        total_accounts, trading_accounts, trading_users, order_count,
        order_amount, trade_count, trade_amount, avg_trade_amount,
        company_trade_count, company_trade_amount, company_trade_ratio_count,
        company_trade_ratio_amount, market_trade_count, market_trade_amount,
        market_trade_ratio_count, market_trade_ratio_amount
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .bind(
        timestamp,
        data.成交月份,
        data.本月新增戶數,
        data.本月註銷戶數,
        data.累計開戶數,
        data.本月交易戶數,
        data.本月交易人數,
        data.委託筆數,
        data.委託金額,
        data.成交筆數,
        data.成交金額,
        data.平均每筆成交金額,
        data.公司總成交筆數,
        data.公司總成交金額,
        data.占公司成交比率筆數,
        data.占公司成交比率金額,
        data.市場成交總筆數,
        data.市場成交總金額,
        data.占市場成交比率筆數,
        data.占市場成交比率金額
      )
      .run();

    // 記錄重要資訊
    console.log(`成交月份: ${data.成交月份}`);
    console.log(`本月交易戶數: ${data.本月交易戶數}`);
    console.log(`成交金額: ${data.成交金額}`);
    console.log(`占市場成交比率(金額): ${data.占市場成交比率(金額)}`);

    return new Response(
      JSON.stringify({
        success: true,
        message: "資料獲取成功",
        timestamp: timestamp,
      }),
      {
        headers: { "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error(`獲取資料失敗: ${error.message}`);
    return new Response(
      JSON.stringify({
        success: false,
        message: error.message,
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
    // 初始化資料庫
    await initDB(env.DB);

    // 只允許 POST 請求
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    // 執行獲取資料的任務
    return await fetchTradingStats(env.DB);
  },

  // 設定定時任務
  async scheduled(event, env, ctx) {
    // 初始化資料庫
    await initDB(env.DB);

    // 執行獲取資料的任務
    await fetchTradingStats(env.DB);
  },
};

// 設定 cron 任務，每分鐘執行一次
cron.schedule("* * * * *", () => {
  fetchTradingStats();
});

logMessage("電子式交易統計資訊獲取服務已啟動");
