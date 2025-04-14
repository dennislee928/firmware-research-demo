import fs from "fs";
import path from "path";

export default function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ message: "僅支持GET請求" });
  }

  try {
    const { filename } = req.query;

    // 安全檢查，防止目錄遍歷攻擊
    if (
      filename.includes("..") ||
      filename.includes("/") ||
      !filename.endsWith(".md")
    ) {
      return res.status(400).json({ message: "無效的檔案名稱" });
    }

    const reportPath = path.join("/firmware-analysis/reports", filename);

    // 檢查檔案是否存在
    if (!fs.existsSync(reportPath)) {
      return res.status(404).json({ message: "找不到報告檔案" });
    }

    // 讀取報告內容
    const content = fs.readFileSync(reportPath, "utf8");

    // 設置適當的內容類型
    res.setHeader("Content-Type", "text/markdown");

    // 返回報告內容
    res.status(200).send(content);
  } catch (error) {
    console.error("讀取報告錯誤:", error);
    res
      .status(500)
      .json({ message: "讀取報告時發生錯誤", error: error.message });
  }
}
