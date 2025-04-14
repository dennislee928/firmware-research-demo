import { IncomingForm } from "formidable";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// 禁用內建的bodyParser，因為我們使用formidable來解析表單數據
export const config = {
  api: {
    bodyParser: false,
  },
};

// 讀取表單數據（包括檔案）
const readFormData = async (req) => {
  return new Promise((resolve, reject) => {
    const form = new IncomingForm({
      uploadDir: "/firmware-analysis/firmware_samples",
      keepExtensions: true,
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
    // 產生唯一的任務ID
    const jobId = Date.now().toString();

    // 解析表單數據
    const { fields, files } = await readFormData(req);

    console.log("上傳檔案信息:", files);
    if (files.firmware) {
      // 檢查是否為陣列
      const firmware = Array.isArray(files.firmware)
        ? files.firmware[0]
        : files.firmware;
      console.log("檔案屬性:", {
        filepath: firmware.filepath,
        originalFilename: firmware.originalFilename,
        newFilename: firmware.newFilename,
        mimetype: firmware.mimetype,
      });

      // 使用正確的檔案路徑
      const targetPath = firmware.filepath;

      // 可以添加檢查允許的擴展名
      const allowedExtensions = [".bin", ".img", ".fw", ".pkg", ".dmg"];
      const fileExtension =
        firmware && firmware.originalFilename
          ? path.extname(firmware.originalFilename).toLowerCase()
          : "";

      if (!allowedExtensions.includes(fileExtension)) {
        return res.status(400).json({
          message: "不支援的檔案類型，僅支援 .bin, .img, .fw, .pkg, .dmg 格式",
        });
      }

      // 構建命令
      let analysisCommand = "cd /firmware-analysis && ";
      analysisCommand += `./firmware_analyzer.sh -f "${targetPath}"`;

      // 添加分析選項
      if (fields.yaraOnly === "true") {
        analysisCommand += " -y";
      }

      if (fields.binwalkOnly === "true") {
        analysisCommand += " -b";
      }

      if (fields.extractFilesystem === "true") {
        analysisCommand += " -x";
      }

      if (fields.recursive === "true") {
        analysisCommand += " -r";
      }

      // 將分析命令寫入暫存檔以便後續檢查
      fs.writeFileSync(
        `/firmware-analysis/logs/job_${jobId}.json`,
        JSON.stringify({
          id: jobId,
          command: analysisCommand,
          status: "pending",
          startTime: new Date().toISOString(),
          targetPath,
        })
      );

      // 非同步執行命令
      exec(analysisCommand, (error, stdout, stderr) => {
        // 更新任務狀態
        const status = error ? "failed" : "completed";
        fs.writeFileSync(
          `/firmware-analysis/logs/job_${jobId}.json`,
          JSON.stringify({
            id: jobId,
            command: analysisCommand,
            status,
            finishTime: new Date().toISOString(),
            error: error ? error.message : null,
            stdout,
            stderr,
          })
        );
      });

      // 返回任務ID給客戶端
      res.status(200).json({
        message: "分析任務已啟動",
        jobId,
      });
    } else if (fields.scanDirectory) {
      // 使用目錄掃描
      let analysisCommand = "cd /firmware-analysis && ";
      analysisCommand += `./firmware_analyzer.sh -d "${fields.scanDirectory}"`;

      // 添加檔案副檔名（如果有）
      if (fields.fileExtension) {
        analysisCommand += ` -e "${fields.fileExtension}"`;
      }

      // 添加分析選項
      if (fields.yaraOnly === "true") {
        analysisCommand += " -y";
      }

      if (fields.binwalkOnly === "true") {
        analysisCommand += " -b";
      }

      if (fields.extractFilesystem === "true") {
        analysisCommand += " -x";
      }

      if (fields.recursive === "true") {
        analysisCommand += " -r";
      }

      // 將分析命令寫入暫存檔以便後續檢查
      fs.writeFileSync(
        `/firmware-analysis/logs/job_${jobId}.json`,
        JSON.stringify({
          id: jobId,
          command: analysisCommand,
          status: "pending",
          startTime: new Date().toISOString(),
          targetPath: fields.scanDirectory,
        })
      );

      // 非同步執行命令
      exec(analysisCommand, (error, stdout, stderr) => {
        // 更新任務狀態
        const status = error ? "failed" : "completed";
        fs.writeFileSync(
          `/firmware-analysis/logs/job_${jobId}.json`,
          JSON.stringify({
            id: jobId,
            command: analysisCommand,
            status,
            finishTime: new Date().toISOString(),
            error: error ? error.message : null,
            stdout,
            stderr,
          })
        );
      });

      // 返回任務ID給客戶端
      res.status(200).json({
        message: "分析任務已啟動",
        jobId,
      });
    } else {
      return res.status(400).json({ message: "未提供韌體檔案或掃描目錄" });
    }
  } catch (error) {
    console.error("分析錯誤:", error);
    res
      .status(500)
      .json({ message: "分析過程中發生錯誤", error: error.message });
  }
}
