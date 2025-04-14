import fs from "fs";
import path from "path";

export default function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ message: "僅支持GET請求" });
  }

  try {
    const reportDir = "/firmware-analysis/reports";

    // 檢查報告目錄是否存在
    if (!fs.existsSync(reportDir)) {
      return res.status(200).json({ reports: [] });
    }

    // 讀取目錄中的所有檔案
    const files = fs.readdirSync(reportDir);

    // 過濾出.md檔案並獲取檔案信息
    const reports = files
      .filter((file) => file.endsWith(".md"))
      .map((filename) => {
        const filePath = path.join(reportDir, filename);
        const stats = fs.statSync(filePath);

        return {
          filename,
          date: stats.mtime.toISOString(),
          size: stats.size,
        };
      })
      // 根據日期排序（最新的在前）
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    // 返回報告列表
    res.status(200).json({ reports });
  } catch (error) {
    console.error("獲取報告列表錯誤:", error);
    res
      .status(500)
      .json({ message: "獲取報告列表時發生錯誤", error: error.message });
  }
}
