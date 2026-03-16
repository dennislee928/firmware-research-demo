import fs from "fs";
import path from "path";

export default function handler(req, res) {
  const { action, folder, filename } = req.query;
  const BASE_DIR = "/firmware-analysis";
  const ALLOWED_FOLDERS = ["hexdump-analysis", "binwalk-analysis", "yara-rules", "logs", "reports"];

  if (req.method !== "GET") {
    return res.status(405).json({ message: "僅支持GET請求" });
  }

  try {
    if (action === "list") {
      const results = {};
      for (const f of ALLOWED_FOLDERS) {
        const dirPath = path.join(BASE_DIR, f);
        try {
          if (fs.existsSync(dirPath)) {
            const stats = fs.statSync(dirPath);
            if (stats.isDirectory()) {
              results[f] = fs.readdirSync(dirPath)
                .filter(file => !file.startsWith(".") && file !== "empty.yar")
                .map(file => {
                   try {
                     const filePath = path.join(dirPath, file);
                     const fstats = fs.statSync(filePath);
                     return { name: file, size: fstats.size, mtime: fstats.mtime };
                   } catch (e) {
                     console.error(`Error stating file ${file} in ${f}:`, e.message);
                     return null;
                   }
                })
                .filter(item => item !== null)
                .sort((a, b) => b.mtime - a.mtime);
            }
          }
        } catch (e) {
          console.error(`Error processing directory ${f}:`, e.message);
        }
      }
      return res.status(200).json(results);
    }

    if (action === "read") {
      if (!folder || !filename || !ALLOWED_FOLDERS.includes(folder)) {
        return res.status(400).json({ message: "無效的請求參數" });
      }

      // Prevents directory traversal
      const safeFilename = path.basename(filename);
      const filePath = path.join(BASE_DIR, folder, safeFilename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: "找不到檔案" });
      }

      const content = fs.readFileSync(filePath, "utf8");
      return res.status(200).send(content);
    }

    res.status(400).json({ message: "未指定的動作" });
  } catch (error) {
    console.error("Artifact API Error:", error);
    res.status(500).json({ message: "處理請求時發生錯誤", error: error.message });
  }
}
