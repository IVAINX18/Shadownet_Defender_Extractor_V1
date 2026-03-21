/**
 * components/FileUpload.jsx — Zona de carga con drag & drop.
 *
 * maxBytes: límite duro (rechaza archivo); debe coincidir con el backend (GET /health → max_upload_mb).
 * warnBytes: solo aviso visual para archivos grandes (subida permitida).
 */
import { useState, useRef, useCallback } from 'react'
import { formatBytes } from '../utils/dashboardStats'
import { LARGE_FILE_WARN_BYTES } from '../constants/uploadLimits'

export default function FileUpload({
  onFileSelected,
  disabled = false,
  maxBytes,
  warnBytes = LARGE_FILE_WARN_BYTES,
}) {
  const [isDragging, setIsDragging] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const [warnLarge, setWarnLarge] = useState(false)
  const inputRef = useRef(null)

  const handleFile = useCallback(
    (file) => {
      setRejectReason('')
      setWarnLarge(false)
      if (!file || !onFileSelected) return
      if (typeof maxBytes === 'number' && file.size > maxBytes) {
        setRejectReason(
          `El archivo supera el máximo permitido (${formatBytes(maxBytes)}).`,
        )
        return
      }
      if (typeof warnBytes === 'number' && file.size >= warnBytes) {
        setWarnLarge(true)
      }
      onFileSelected(file)
    },
    [onFileSelected, maxBytes, warnBytes],
  )

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault()
      setIsDragging(false)
      handleFile(e.dataTransfer.files[0])
    },
    [handleFile],
  )

  const maxLabel =
    typeof maxBytes === 'number' ? formatBytes(maxBytes) : 'configuración del servidor'

  return (
    <div>
      <div
        onClick={() => !disabled && inputRef.current?.click()}
        onDrop={handleDrop}
        onDragOver={(e) => {
          e.preventDefault()
          if (!disabled) setIsDragging(true)
        }}
        onDragLeave={() => setIsDragging(false)}
        style={{
          borderRadius: 12,
          border: `2px dashed ${isDragging ? 'var(--accent)' : 'var(--border)'}`,
          background: isDragging ? 'rgba(139, 92, 246, 0.06)' : 'var(--bg-card)',
          padding: '40px 20px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 16,
          cursor: disabled ? 'not-allowed' : 'pointer',
          opacity: disabled ? 0.5 : 1,
          transition: 'all 0.2s',
        }}
      >
        <div
          style={{
            width: 64,
            height: 64,
            borderRadius: 16,
            background: 'var(--bg-input)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '2rem',
          }}
        >
          {isDragging ? '📥' : '📁'}
        </div>
        <div style={{ textAlign: 'center' }}>
          <p
            style={{
              fontSize: '0.9rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: 4,
            }}
          >
            {isDragging ? 'Drop file here' : 'Drag & drop a file to scan'}
          </p>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            or click to browse — máximo {maxLabel}
          </p>
        </div>
        <input
          ref={inputRef}
          type="file"
          onChange={(e) => {
            handleFile(e.target.files[0])
            e.target.value = ''
          }}
          style={{ display: 'none' }}
          disabled={disabled}
        />
      </div>
      {rejectReason && (
        <p
          style={{
            marginTop: 10,
            fontSize: '0.8rem',
            color: 'var(--red)',
          }}
        >
          {rejectReason}
        </p>
      )}
      {warnLarge && !rejectReason && (
        <p
          style={{
            marginTop: 10,
            fontSize: '0.75rem',
            color: 'var(--yellow)',
          }}
        >
          Archivo grande: la subida y el análisis pueden tardar varios minutos.
        </p>
      )}
    </div>
  )
}
