import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "僅支持POST請求" });
  }

  try {
    // 執行設定cron的腳本
    const { stdout, stderr } = await execAsync(
      "cd /firmware-analysis && ./setup_cron.sh"
    );

    if (stderr && stderr.length > 0) {
      console.warn("Cron設定警告:", stderr);
    }

    // 返回成功信息
    res.status(200).json({
      message: "已成功設置定時分析任務",
      details: stdout,
    });
  } catch (error) {
    console.error("Cron設定錯誤:", error);
    res.status(500).json({
      message: "設置定時分析任務時發生錯誤",
      error: error.message,
      stderr: error.stderr,
    });
  }
}
