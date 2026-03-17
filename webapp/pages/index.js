import { useState, useEffect, useRef } from "react";
import axios from "axios";
import Head from "next/head";

export default function Home() {
  const artifactFolders = [
    { id: "hexdump-analysis", label: "Hexdump 分析" },
    { id: "binwalk-analysis", label: "Binwalk 分析" },
    { id: "yara-rules", label: "YARA 規則" },
    { id: "dynamic-analysis", label: "動態分析" },
    { id: "dependency-inventory", label: "依賴盤點" },
  ];

  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState("");
  const [analysisOptions, setAnalysisOptions] = useState({
    yaraOnly: false,
    binwalkOnly: false,
    extractFilesystem: false,
    recursive: false,
  });
  const [recentReports, setRecentReports] = useState([]);
  const [artifacts, setArtifacts] = useState({});
  const [activeJobId, setActiveJobId] = useState(null);
  const [currentJobDetail, setCurrentJobDetail] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [scanDirectory, setScanDirectory] = useState("");
  const [fileExtension, setFileExtension] = useState(".bin");
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [viewingContent, setViewingContent] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);

  const pollingRef = useRef(null);

  useEffect(() => {
    fetchRecentReports();
    fetchArtifacts();
    const interval = setInterval(fetchArtifacts, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchRecentReports = async () => {
    try {
      const response = await axios.get("/api/reports");
      setRecentReports(response.data.reports || []);
    } catch (err) {
      console.error("Fetch reports failed:", err);
    }
  };

  const fetchArtifacts = async () => {
    try {
      const response = await axios.get("/api/artifacts?action=list");
      setArtifacts(response.data || {});
    } catch (err) {
      console.error("Fetch artifacts failed:", err);
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
    setAnalysisOptions((prev) => ({ ...prev, [name]: checked }));
  };

  const startPolling = (jobId) => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    setActiveJobId(jobId);
    setIsAnalyzing(true);

    pollingRef.current = setInterval(async () => {
      try {
        const res = await axios.get(`/api/status/${jobId}`);
        setCurrentJobDetail(res.data);
        if (res.data.status === "completed" || res.data.status === "failed") {
          clearInterval(pollingRef.current);
          setIsAnalyzing(false);
          fetchRecentReports();
          fetchArtifacts();
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    }, 2000);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file && !scanDirectory) {
      setError("請選擇檔案或指定掃描目錄");
      return;
    }

    setIsUploading(true);
    setError("");

    const formData = new FormData();
    if (file) formData.append("firmware", file);
    formData.append("yaraOnly", analysisOptions.yaraOnly);
    formData.append("binwalkOnly", analysisOptions.binwalkOnly);
    formData.append("extractFilesystem", analysisOptions.extractFilesystem);
    formData.append("recursive", analysisOptions.recursive);
    if (scanDirectory) {
      formData.append("scanDirectory", scanDirectory);
      formData.append("fileExtension", fileExtension);
    }

    try {
      const res = await axios.post("/api/analyze", formData);
      startPolling(res.data.jobId);
    } catch (err) {
      setError(err.response?.data?.message || "啟動分析失敗");
    } finally {
      setIsUploading(false);
    }
  };

  const readArtifact = async (folder, filename) => {
    try {
      const res = await axios.get(`/api/artifacts?action=read&folder=${folder}&filename=${filename}`);
      setViewingContent(res.data);
      setSelectedArtifact({ folder, filename });
      setIsModalOpen(true);
    } catch (err) {
      alert("讀取失敗: " + (err.response?.data?.message || err.message));
    }
  };

  const setupCron = async () => {
    try {
      await axios.post("/api/setup-cron");
      alert("定時任務設置成功 (30分鐘一次)");
    } catch (err) {
      setError("設置定時任務失敗");
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 font-sans">
      <Head>
        <title>韌體分析儀 - 高級面板</title>
      </Head>

      <main className="container mx-auto px-4 max-w-7xl">
        <header className="mb-10 text-center">
          <h1 className="text-4xl font-extrabold text-gray-900 mb-2">韌體分析儀</h1>
          <p className="text-gray-600">自動化解包、漏洞掃描與靜態分析工具</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Control Panel */}
          <div className="lg:col-span-4 space-y-6">
            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center">
                <span className="bg-blue-100 text-blue-600 p-2 rounded-lg mr-3">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                </span>
                上傳與分析 （上傳檔案大小限制：2GB）
              </h2>

              {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm border border-red-100">{error}</div>}

              <form onSubmit={handleUpload} className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">韌體檔案 (.bin, .img, .fw, .pkg, .dmg, .iso, .zip, .7z, .tar, .gz, .exe, .msi)</label>
                  <input type="file" onChange={handleFileChange} className="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 cursor-pointer" />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">或 指定容器內路徑</label>
                  <input type="text" value={scanDirectory} onChange={(e) => setScanDirectory(e.target.value)} placeholder="/firmware-analysis/firmware_samples" className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none" />
                </div>

                <div className="pt-2 border-t border-gray-100">
                  <h3 className="text-sm font-bold text-gray-700 mb-3">進階選項</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(analysisOptions).map(([key, value]) => (
                      <label key={key} className="flex items-center text-sm text-gray-600 cursor-pointer hover:text-gray-900">
                        <input type="checkbox" name={key} checked={value} onChange={handleOptionChange} className="rounded text-blue-600 mr-2 focus:ring-blue-500" />
                        {key === 'yaraOnly' ? '僅YARA' : key === 'binwalkOnly' ? '僅Binwalk' : key === 'extractFilesystem' ? '提取文件' : '遞迴掃描'}
                      </label>
                    ))}
                  </div>
                </div>

                <div className="pt-4 flex flex-col space-y-2">
                  <button type="submit" disabled={isUploading || isAnalyzing} className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-bold py-2.5 rounded-lg transition duration-200 shadow-md">
                    {isUploading ? "上傳中..." : isAnalyzing ? "分析中..." : "開始分析"}
                  </button>
                  <button type="button" onClick={setupCron} className="text-gray-500 text-xs hover:text-blue-600 underline">
                    設置每30分鐘自動分析一次
                  </button>
                </div>
              </form>
            </section>

            {/* Active Job Info */}
            {currentJobDetail && (
              <section className="bg-gray-900 rounded-xl shadow-lg p-5 text-white overflow-hidden">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="font-bold text-gray-300 uppercase text-xs tracking-wider">當前任務狀態</h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${currentJobDetail.status === 'completed' ? 'bg-green-500' : currentJobDetail.status === 'failed' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`}>
                    {currentJobDetail.status}
                  </span>
                </div>
                <div className="text-xs space-y-1.5 opacity-90">
                  <p><span className="text-gray-500">ID:</span> {currentJobDetail.id}</p>
                  <p className="truncate"><span className="text-gray-500">Command:</span> {currentJobDetail.command}</p>
                </div>
                {isAnalyzing && (
                  <div className="mt-4 bg-black rounded p-3 text-[10px] font-mono text-green-400 h-32 overflow-y-auto">
                    <pre>{currentJobDetail.stdout?.slice(-500) || "等待輸出..."}</pre>
                  </div>
                )}
              </section>
            )}
          </div>

          {/* Right Column: Artifacts & Results */}
          <div className="lg:col-span-8 space-y-6">
            {/* Reports Section */}
            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">分析報告 (.md)</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {recentReports.length > 0 ? (
                  recentReports.map((report, idx) => (
                    <div key={idx} className="group p-4 bg-gray-50 hover:bg-blue-50 border border-gray-200 hover:border-blue-200 rounded-xl transition duration-200">
                      <div className="flex justify-between items-start">
                        <a href={`/api/reports/${report.filename}`} target="_blank" rel="noreferrer" className="text-sm font-bold text-gray-800 hover:text-blue-700 truncate block mr-2">
                          {report.filename}
                        </a>
                        <span className="text-[10px] text-gray-500 whitespace-nowrap">{new Date(report.date).toLocaleDateString()}</span>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">Size: {(report.size / 1024).toFixed(1)} KB</p>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-400 text-sm col-span-2 py-4 text-center">尚無報告，啟動分析以生成結果。</p>
                )}
              </div>
            </section>

            {/* Artifacts Explorer */}
            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">檔案檢索與結果庫</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-6">
                {artifactFolders.map((folder) => (
                  <div key={folder.id}>
                    <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 border-b border-gray-100 pb-1">{folder.label}</h3>
                    <ul className="space-y-1.5 max-h-60 overflow-y-auto pr-2 custom-scrollbar">
                      {artifacts[folder.id]?.length > 0 ? (
                        artifacts[folder.id].map((art, idx) => (
                          <li key={idx}>
                            <button onClick={() => readArtifact(folder.id, art.name)} className="w-full text-left px-2 py-1.5 text-xs text-gray-600 hover:bg-blue-50 hover:text-blue-700 rounded transition truncate">
                              📄 {art.name}
                            </button>
                          </li>
                        ))
                      ) : (
                        <li className="text-xs text-gray-300 italic">無相關檔案</li>
                      )}
                    </ul>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      </main>

      {/* Artifact Viewer Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-75 backdrop-blur-sm">
          <div className="bg-white w-full max-w-5xl rounded-2xl shadow-2xl flex flex-col max-h-[90vh]">
            <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50 rounded-t-2xl">
              <div>
                <h3 className="font-bold text-gray-900">{selectedArtifact?.filename}</h3>
                <p className="text-[10px] text-gray-500 uppercase tracking-widest">位置: {selectedArtifact?.folder}</p>
              </div>
              <button onClick={() => setIsModalOpen(false)} className="p-2 hover:bg-gray-200 rounded-full transition">
                <svg className="w-6 h-6 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
              </button>
            </div>
            <div className="p-6 overflow-y-auto flex-1 bg-gray-950 font-mono text-sm text-gray-300">
              <pre className="whitespace-pre-wrap">{viewingContent || "讀取中..."}</pre>
            </div>
            <div className="p-4 border-t border-gray-200 text-right bg-gray-50 rounded-b-2xl">
              <button onClick={() => setIsModalOpen(false)} className="px-6 py-2 bg-gray-800 hover:bg-gray-900 text-white rounded-lg font-bold transition">關閉</button>
            </div>
          </div>
        </div>
      )}

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #e2e8f0; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #cbd5e1; }
      `}</style>
    </div>
  );
}
