import fs from "fs";
import path from "path";

export default function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ message: "僅支持GET請求" });
  }

  try {
    const { jobId } = req.query;

    // 檢查任務狀態文件是否存在
    const statusFilePath = `/firmware-analysis/logs/job_${jobId}.json`;

    if (!fs.existsSync(statusFilePath)) {
      return res.status(404).json({ message: "找不到指定的分析任務" });
    }

    // 讀取任務狀態
    const jobStatus = JSON.parse(fs.readFileSync(statusFilePath, "utf8"));

    // 返回給客戶端
    res.status(200).json(jobStatus);
  } catch (error) {
    console.error("狀態檢查錯誤:", error);
    res
      .status(500)
      .json({ message: "檢查分析狀態時發生錯誤", error: error.message });
  }
}
