import { useState, useEffect } from "react";
import axios from "axios";
import Head from "next/head";

export default function Home() {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [error, setError] = useState("");
  const [analysisOptions, setAnalysisOptions] = useState({
    yaraOnly: false,
    binwalkOnly: false,
    extractFilesystem: false,
    recursive: false,
  });
  const [recentReports, setRecentReports] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStatus, setAnalysisStatus] = useState("");
  const [scanDirectory, setScanDirectory] = useState("");
  const [fileExtension, setFileExtension] = useState(".bin");

  // 取得最近的報告
  useEffect(() => {
    fetchRecentReports();
  }, []);

  const fetchRecentReports = async () => {
    try {
      const response = await axios.get("/api/reports");
      setRecentReports(response.data.reports);
    } catch (err) {
      console.error("獲取報告列表失敗:", err);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError("");
    }
  };

  const handleOptionChange = (e) => {
    const { name, checked } = e.target;
    setAnalysisOptions((prev) => ({
      ...prev,
      [name]: checked,
    }));
  };

  const handleUpload = async (e) => {
    e.preventDefault();

    if (!file && !scanDirectory) {
      setError("請選擇要上傳的韌體檔案或指定掃描目錄");
      return;
    }

    setIsUploading(true);
    setError("");

    const formData = new FormData();
    if (file) {
      formData.append("firmware", file);
    }

    formData.append("yaraOnly", analysisOptions.yaraOnly);
    formData.append("binwalkOnly", analysisOptions.binwalkOnly);
    formData.append("extractFilesystem", analysisOptions.extractFilesystem);
    formData.append("recursive", analysisOptions.recursive);

    if (scanDirectory) {
      formData.append("scanDirectory", scanDirectory);
      formData.append("fileExtension", fileExtension);
    }

    try {
      const response = await axios.post("/api/analyze", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      setUploadSuccess(true);
      setIsAnalyzing(true);

      // 輪詢分析狀態
      const intervalId = setInterval(async () => {
        try {
          const statusResponse = await axios.get(
            `/api/status/${response.data.jobId}`
          );
          setAnalysisStatus(statusResponse.data.status);

          if (
            statusResponse.data.status === "completed" ||
            statusResponse.data.status === "failed"
          ) {
            clearInterval(intervalId);
            setIsAnalyzing(false);
            fetchRecentReports();
          }
        } catch (err) {
          console.error("獲取分析狀態失敗:", err);
        }
      }, 2000);
    } catch (err) {
      setError(err.response?.data?.message || "上傳失敗，請重試");
    } finally {
      setIsUploading(false);
    }
  };

  const setupCron = async () => {
    try {
      setIsAnalyzing(true);
      const response = await axios.post("/api/setup-cron");
      setAnalysisStatus("已成功設置定時任務");
      setTimeout(() => {
        setIsAnalyzing(false);
        setAnalysisStatus("");
      }, 3000);
    } catch (err) {
      setError(err.response?.data?.message || "設置定時任務失敗");
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen py-8">
      <Head>
        <title>韌體分析工具</title>
        <meta name="description" content="韌體解包與特徵檢測工具" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className="container mx-auto px-4">
        <h1 className="text-3xl font-bold text-center mb-8">韌體分析工具</h1>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* 上傳表單 */}
          <div className="card">
            <h2 className="text-xl font-semibold mb-4">上傳韌體檔案</h2>

            {error && (
              <div className="alert alert-error">
                <p>{error}</p>
              </div>
            )}

            {uploadSuccess && !isAnalyzing && (
              <div className="alert alert-success">
                <p>檔案上傳成功並完成分析！請查看報告。</p>
              </div>
            )}

            {isAnalyzing && (
              <div className="alert alert-info">
                <p>正在分析中: {analysisStatus || "準備分析..."}</p>
              </div>
            )}

            <form onSubmit={handleUpload}>
              <div className="mb-4">
                <label className="label">上傳韌體檔案</label>
                <input
                  type="file"
                  onChange={handleFileChange}
                  className="input"
                  accept=".bin,.img,.fw"
                />
              </div>

              <div className="mb-4">
                <label className="label">或指定掃描目錄</label>
                <input
                  type="text"
                  value={scanDirectory}
                  onChange={(e) => setScanDirectory(e.target.value)}
                  placeholder="/firmware-analysis/firmware_samples"
                  className="input"
                />
              </div>

              {scanDirectory && (
                <div className="mb-4">
                  <label className="label">檔案副檔名</label>
                  <input
                    type="text"
                    value={fileExtension}
                    onChange={(e) => setFileExtension(e.target.value)}
                    placeholder=".bin"
                    className="input"
                  />
                </div>
              )}

              <div className="mb-6">
                <h3 className="text-lg font-medium mb-2">分析選項</h3>
                <div className="space-y-2">
                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="yaraOnly"
                      name="yaraOnly"
                      checked={analysisOptions.yaraOnly}
                      onChange={handleOptionChange}
                      className="mr-2"
                    />
                    <label htmlFor="yaraOnly">僅執行 YARA 規則檢測</label>
                  </div>

                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="binwalkOnly"
                      name="binwalkOnly"
                      checked={analysisOptions.binwalkOnly}
                      onChange={handleOptionChange}
                      className="mr-2"
                    />
                    <label htmlFor="binwalkOnly">僅執行 binwalk 分析</label>
                  </div>

                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="extractFilesystem"
                      name="extractFilesystem"
                      checked={analysisOptions.extractFilesystem}
                      onChange={handleOptionChange}
                      className="mr-2"
                    />
                    <label htmlFor="extractFilesystem">提取檔案系統</label>
                  </div>

                  {scanDirectory && (
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        id="recursive"
                        name="recursive"
                        checked={analysisOptions.recursive}
                        onChange={handleOptionChange}
                        className="mr-2"
                      />
                      <label htmlFor="recursive">遞迴掃描子目錄</label>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex space-x-4">
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isUploading || isAnalyzing}
                >
                  {isUploading ? "上傳中..." : "上傳並分析"}
                </button>

                <button
                  type="button"
                  onClick={setupCron}
                  className="btn btn-secondary"
                  disabled={isAnalyzing}
                >
                  設置定時分析
                </button>
              </div>
            </form>
          </div>

          {/* 報告列表 */}
          <div className="card">
            <h2 className="text-xl font-semibold mb-4">最近分析報告</h2>

            {recentReports.length === 0 ? (
              <p className="text-gray-500">尚無分析報告</p>
            ) : (
              <ul className="space-y-2">
                {recentReports.map((report, index) => (
                  <li key={index} className="border-b border-gray-200 pb-2">
                    <a
                      href={`/api/reports/${report.filename}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800"
                    >
                      {report.filename}
                    </a>
                    <p className="text-sm text-gray-600">{report.date}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </main>

      <footer className="mt-12 text-center text-gray-500 text-sm">
        <p>韌體分析工具 &copy; 2023 Dennis Lee</p>
      </footer>
    </div>
  );
}
