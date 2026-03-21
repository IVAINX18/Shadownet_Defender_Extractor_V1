/**
 * components/FileUpload.jsx — Zona de carga con drag & drop.
 */
import { useState, useRef, useCallback } from 'react'

export default function FileUpload({ onFileSelected, disabled = false }) {
  const [isDragging, setIsDragging] = useState(false)
  const inputRef = useRef(null)

  const handleFile = useCallback((file) => {
    if (file && onFileSelected) onFileSelected(file)
  }, [onFileSelected])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setIsDragging(false)
    handleFile(e.dataTransfer.files[0])
  }, [handleFile])

  return (
    <div
      onClick={() => !disabled && inputRef.current?.click()}
      onDrop={handleDrop}
      onDragOver={(e) => { e.preventDefault(); if (!disabled) setIsDragging(true) }}
      onDragLeave={() => setIsDragging(false)}
      style={{
        borderRadius: 12,
        border: `2px dashed ${isDragging ? 'var(--accent)' : 'var(--border)'}`,
        background: isDragging ? 'rgba(139, 92, 246, 0.06)' : 'var(--bg-card)',
        padding: '40px 20px',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'all 0.2s',
      }}
    >
      <div style={{
        width: 64, height: 64, borderRadius: 16,
        background: 'var(--bg-input)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '2rem',
      }}>
        {isDragging ? '📥' : '📁'}
      </div>
      <div style={{ textAlign: 'center' }}>
        <p style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          {isDragging ? 'Drop file here' : 'Drag & drop a file to scan'}
        </p>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          or click to browse — any file type supported
        </p>
      </div>
      <input ref={inputRef} type="file" onChange={(e) => { handleFile(e.target.files[0]); e.target.value = '' }} style={{ display: 'none' }} disabled={disabled} />
    </div>
  )
}
