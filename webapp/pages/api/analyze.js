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
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024;
const parsedMaxUploadBytes = Number.parseInt(process.env.MAX_UPLOAD_BYTES || "", 10);
const MAX_UPLOAD_BYTES = Number.isFinite(parsedMaxUploadBytes) && parsedMaxUploadBytes > 0
  ? parsedMaxUploadBytes
  : DEFAULT_MAX_UPLOAD_BYTES;
const MAX_JOB_OUTPUT_CHARS = 20000;
const MAX_STREAM_BUFFER_CHARS = 200000;

// 確保目錄存在
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

const formatBytes = (bytes) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "未知";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  const digits = value >= 10 || unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(digits)}${units[unitIndex]}`;
};

const sanitizeStreamText = (chunk) =>
  chunk
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r+/g, "\n")
    .replace(/[^\x09\x0A\x20-\uFFFF]/g, "");

const trimOutput = (text, limit = MAX_STREAM_BUFFER_CHARS) =>
  text.length > limit ? text.slice(-limit) : text;

const createStreamLogger = (jobId, label, sink, append) => {
  let pending = "";

  return {
    handle(data) {
      const sanitized = sanitizeStreamText(data.toString());
      if (!sanitized) return;

      append(sanitized);
      pending += sanitized;

      const lines = pending.split("\n");
      pending = lines.pop() ?? "";

      for (const line of lines) {
        if (line.trim().length === 0) continue;
        sink.write(`[Job ${jobId} ${label}] ${line}\n`);
      }
    },
    flush() {
      const line = pending.trim();
      if (line) {
        sink.write(`[Job ${jobId} ${label}] ${line}\n`);
      }
      pending = "";
    },
  };
};

// 讀取表單數據（包括檔案）
const readFormData = async (req) => {
  return new Promise((resolve, reject) => {
    const form = new IncomingForm({
      uploadDir: UPLOAD_DIR,
      keepExtensions: true,
      maxFileSize: MAX_UPLOAD_BYTES,
      maxTotalFileSize: MAX_UPLOAD_BYTES,
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
    const getFieldValue = (val) => {
      if (Array.isArray(val)) return val[0];
      return val;
    };
    
    console.log(`[Job ${jobId}] Received fields:`, JSON.stringify(fields));
    console.log(`[Job ${jobId}] Received files keys:`, Object.keys(files));
    
    let targetPath = "";
    const args = [];

    if (files.firmware) {
      const firmware = Array.isArray(files.firmware) ? files.firmware[0] : files.firmware;
      targetPath = firmware.filepath;
      
      const allowedExtensions = [".bin", ".img", ".fw", ".pkg", ".dmg", ".iso", ".zip", ".7z", ".tar", ".gz", ".exe", ".msi"];
      const fileExtension = path.extname(firmware.originalFilename || "").toLowerCase();

      if (!allowedExtensions.includes(fileExtension) && fileExtension !== "") {
        return res.status(400).json({
          message: "不支援的檔案類型，僅支援 .bin, .img, .fw, .pkg, .dmg 格式",
        });
      }
      args.push("-f", targetPath);
    } else if (getFieldValue(fields.scanDirectory)) {
      targetPath = String(getFieldValue(fields.scanDirectory));
      // Basic path validation - restrict to ANALYSIS_DIR for safety
      if (!targetPath.startsWith(ANALYSIS_DIR)) {
         return res.status(400).json({ message: "無效的掃描目錄" });
      }
      args.push("-d", targetPath);
      
      if (getFieldValue(fields.fileExtension)) {
        args.push("-e", String(getFieldValue(fields.fileExtension)));
      }
    } else {
      return res.status(400).json({ message: "未提供韌體檔案或掃描目錄" });
    }

    // Add options
    if (getFieldValue(fields.yaraOnly) === "true") args.push("-y");
    if (getFieldValue(fields.binwalkOnly) === "true") args.push("-b");
    if (getFieldValue(fields.extractFilesystem) === "true") args.push("-x");
    if (!files.firmware && getFieldValue(fields.recursive) === "true") args.push("-r");
    
    const scanDir = getFieldValue(fields.scanDirectory);
    if (scanDir) {
       // logic for scan directory...
    }

    const jobFile = path.join(LOG_DIR, `job_${jobId}.json`);
    const jobData = {
      id: jobId,
      command: `./firmware_analyzer.sh ${args.join(" ")}`,
      status: "pending",
      startTime: new Date().toISOString(),
      targetPath,
    };

    fs.writeFileSync(jobFile, JSON.stringify(jobData, null, 2));
    console.log(`[Job ${jobId}] Spawning: ./firmware_analyzer.sh ${args.join(" ")}`);

    // Spawn process securely
    const child = spawn("./firmware_analyzer.sh", args, {
      cwd: ANALYSIS_DIR,
      env: { ...process.env, PATH: process.env.PATH + ":/usr/local/bin" }
    });

    let stdout = "";
    let stderr = "";

    const stdoutLogger = createStreamLogger(jobId, "STDOUT", process.stdout, (chunk) => {
      stdout = trimOutput(stdout + chunk);
    });
    const stderrLogger = createStreamLogger(jobId, "STDERR", process.stderr, (chunk) => {
      stderr = trimOutput(stderr + chunk);
    });

    child.stdout.on("data", (data) => {
      stdoutLogger.handle(data);
    });

    child.stderr.on("data", (data) => {
      stderrLogger.handle(data);
    });

    child.on("error", (err) => {
      console.error(`[Job ${jobId}] Spawn error:`, err);
      const errorJobData = {
        ...jobData,
        status: "failed",
        finishTime: new Date().toISOString(),
        error: err.message,
        stdout,
        stderr
      };
      fs.writeFileSync(jobFile, JSON.stringify(errorJobData, null, 2));
    });

    child.on("close", (code) => {
      stdoutLogger.flush();
      stderrLogger.flush();
      console.log(`[Job ${jobId}] Process exited with code ${code}`);
      const status = code === 0 ? "completed" : "failed";
      const finishedJobData = {
        ...jobData,
        status,
        finishTime: new Date().toISOString(),
        exitCode: code,
        stdout: stdout.slice(-MAX_JOB_OUTPUT_CHARS),
        stderr: stderr.slice(-MAX_JOB_OUTPUT_CHARS),
      };
      fs.writeFileSync(jobFile, JSON.stringify(finishedJobData, null, 2));
    });

    res.status(200).json({
      message: "分析任務已啟動",
      jobId,
    });
  } catch (error) {
    console.error("分析錯誤:", error);
    if (error?.httpCode === 413 || error?.code === 1009) {
      return res.status(413).json({
        message: `上傳檔案超過限制，目前上限為 ${formatBytes(MAX_UPLOAD_BYTES)}`,
        error: error.message,
      });
    }
    res.status(500).json({ message: "分析過程中發生錯誤", error: error.message });
  }
}
