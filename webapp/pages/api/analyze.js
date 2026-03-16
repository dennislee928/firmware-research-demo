import { IncomingForm } from "formidable";
import fs from "fs";
import path from "path";
import { spawn } from "child_process";

// 禁用內建的bodyParser，因為我們使用formidable來解析表單數據
export const config = {
  api: {
    bodyParser: false,
  },
};

const ANALYSIS_DIR = "/firmware-analysis";
const UPLOAD_DIR = path.join(ANALYSIS_DIR, "firmware_samples");
const LOG_DIR = path.join(ANALYSIS_DIR, "logs");

// 確保目錄存在
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// 讀取表單數據（包括檔案）
const readFormData = async (req) => {
  return new Promise((resolve, reject) => {
    const form = new IncomingForm({
      uploadDir: UPLOAD_DIR,
      keepExtensions: true,
      maxFileSize: 100 * 1024 * 1024, // 100MB limit
    });

    form.parse(req, (err, fields, files) => {
      if (err) return reject(err);
      resolve({ fields, files });
    });
  });
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "僅支持POST請求" });
  }

  try {
    const jobId = Date.now().toString();
    const { fields, files } = await readFormData(req);
    
    console.log(`[Job ${jobId}] Received fields:`, JSON.stringify(fields));
    console.log(`[Job ${jobId}] Received files keys:`, Object.keys(files));
    
    let targetPath = "";
    const args = [];

    if (files.firmware) {
      const firmware = Array.isArray(files.firmware) ? files.firmware[0] : files.firmware;
      targetPath = firmware.filepath;
      
      const allowedExtensions = [".bin", ".img", ".fw", ".pkg", ".dmg", ".iso", ".zip", ".7z", ".tar", ".gz"];
      const fileExtension = path.extname(firmware.originalFilename || "").toLowerCase();

      if (!allowedExtensions.includes(fileExtension) && fileExtension !== "") {
        return res.status(400).json({
          message: "不支援的檔案類型，僅支援 .bin, .img, .fw, .pkg, .dmg 格式",
        });
      }
      args.push("-f", targetPath);
    } else if (fields.scanDirectory) {
      targetPath = String(fields.scanDirectory);
      // Basic path validation - restrict to ANALYSIS_DIR for safety
      if (!targetPath.startsWith(ANALYSIS_DIR)) {
         return res.status(400).json({ message: "無效的掃描目錄" });
      }
      args.push("-d", targetPath);
      
      if (fields.fileExtension) {
        args.push("-e", String(fields.fileExtension));
      }
    } else {
      return res.status(400).json({ message: "未提供韌體檔案或掃描目錄" });
    }

    // Add options
    if (fields.yaraOnly === "true") args.push("-y");
    if (fields.binwalkOnly === "true") args.push("-b");
    if (fields.extractFilesystem === "true") args.push("-x");
    if (fields.recursive === "true") args.push("-r");

    const jobFile = path.join(LOG_DIR, `job_${jobId}.json`);
    const jobData = {
      id: jobId,
      command: `./firmware_analyzer.sh ${args.join(" ")}`,
      status: "pending",
      startTime: new Date().toISOString(),
      targetPath,
    };

    fs.writeFileSync(jobFile, JSON.stringify(jobData, null, 2));

    // Spawn process securely
    const child = spawn("./firmware_analyzer.sh", args, {
      cwd: ANALYSIS_DIR,
      env: { ...process.env, PATH: process.env.PATH + ":/usr/local/bin" }
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => { stdout += data.toString(); });
    child.stderr.on("data", (data) => { stderr += data.toString(); });

    child.on("close", (code) => {
      const status = code === 0 ? "completed" : "failed";
      const finishedJobData = {
        ...jobData,
        status,
        finishTime: new Date().toISOString(),
        exitCode: code,
        stdout: stdout.slice(-10000), // Keep last 10KB
        stderr: stderr.slice(-10000),
      };
      fs.writeFileSync(jobFile, JSON.stringify(finishedJobData, null, 2));
    });

    res.status(200).json({
      message: "分析任務已啟動",
      jobId,
    });
  } catch (error) {
    console.error("分析錯誤:", error);
    res.status(500).json({ message: "分析過程中發生錯誤", error: error.message });
  }
}
