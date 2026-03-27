/**
 * pages/ScanPage.jsx — Escaneo de archivos.
 */
import { Search, XCircle } from 'lucide-react'
import FileUpload from '../components/FileUpload'
import ScanResultCard from '../components/ScanResultCard'
import LoadingSpinner from '../components/LoadingSpinner'
import { scanFile, explainResult, healthCheck } from '../services/api'
import { DEFAULT_MAX_UPLOAD_BYTES } from '../constants/uploadLimits'

export default function ScanPage() {
  const [maxUploadBytes, setMaxUploadBytes] = useState(DEFAULT_MAX_UPLOAD_BYTES)
  const [scanning, setScanning] = useState(false)
  const [explaining, setExplaining] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [scanHistory, setScanHistory] = useState([])

  useEffect(() => {
    healthCheck()
      .then((body) => {
        const mb = body?.data?.max_upload_mb
        if (typeof mb === 'number' && mb > 0) {
          setMaxUploadBytes(mb * 1024 * 1024)
        }
      })
      .catch(() => {})
  }, [])

  const handleScan = async (file) => {
    setScanning(true); setError(''); setResult(null)
    try {
      const response = await scanFile(file)
      const data = response.data
      setResult(data)
      setScanHistory((prev) => [data, ...prev])
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Scan failed')
    } finally { setScanning(false) }
  }

  const handleExplain = async (scanData) => {
    setExplaining(true)
    try {
      const response = await explainResult(scanData)
      const explanation = response.data?.explanation || ''
      const updated = { ...result, explanation }
      setResult(updated)
      setScanHistory((prev) => prev.map((r, i) => i === 0 ? updated : r))
    } catch (err) { console.error('Explain error:', err) }
    finally { setExplaining(false) }
  }

  return (
    <div style={{ maxWidth: 700, margin: '0 auto' }} className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Search size={24} color="var(--accent)" /> Deep File Scan
        </h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Upload a file to analyze it with ShadowNet's AI engine
        </p>
      </div>

      <div style={{ marginBottom: 20 }}>
        <FileUpload
          onFileSelected={handleScan}
          disabled={scanning}
          maxBytes={maxUploadBytes}
        />
      </div>

      {scanning && (
        <div className="card" style={{ padding: 40, textAlign: 'center', marginBottom: 20 }}>
          <LoadingSpinner size="lg" text="Analyzing file with ML engine..." />
        </div>
      )}

      {error && (
        <div style={{
          background: 'var(--red-bg)', border: '1px solid var(--red-border)',
          borderRadius: 8, padding: 14, marginBottom: 20,
          fontSize: '0.8rem', color: 'var(--red)',
        }} className="animate-fade-in flex items-center gap-2">
          <XCircle size={16} /> {error}
        </div>
      )}

      {result && !scanning && (
        <div style={{ marginBottom: 28 }}>
          <ScanResultCard result={result} onExplain={handleExplain} explaining={explaining} />
        </div>
      )}

      {scanHistory.length > 1 && (
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>
            Session History
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {scanHistory.slice(1).map((r, i) => (
              <ScanResultCard key={`${r.file_name}-${i}`} result={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
