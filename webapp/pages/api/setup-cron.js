import { spawn } from "child_process";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "僅支持POST請求" });
  }

  try {
    const child = spawn("./setup_cron.sh", [], {
      cwd: "/firmware-analysis",
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => { stdout += data.toString(); });
    child.stderr.on("data", (data) => { stderr += data.toString(); });

    child.on("close", (code) => {
      if (code === 0) {
        res.status(200).json({
          message: "已成功設置定時分析任務",
          details: stdout,
        });
      } else {
        res.status(500).json({
          message: "設置定時分析任務時發生錯誤",
          error: `腳本退出碼: ${code}`,
          stderr,
        });
      }
    });
  } catch (error) {
    console.error("Cron設定錯誤:", error);
    res.status(500).json({
      message: "設置定時分析任務時發生錯誤",
      error: error.message,
    });
  }
}
