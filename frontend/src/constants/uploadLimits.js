/**
 * Límites de subida en el cliente (deben alinearse con MAX_UPLOAD_MB del backend).
 * VITE_MAX_UPLOAD_MB puede sobreescribir el valor por defecto (200).
 */
const _mb = Number(import.meta.env.VITE_MAX_UPLOAD_MB || 200)
export const DEFAULT_MAX_UPLOAD_MB = Number.isFinite(_mb) && _mb >= 100 ? _mb : 200
export const DEFAULT_MAX_UPLOAD_BYTES = DEFAULT_MAX_UPLOAD_MB * 1024 * 1024

/** Umbral para mostrar advertencia (no bloquea) */
export const LARGE_FILE_WARN_BYTES = 50 * 1024 * 1024
