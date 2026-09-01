# Informe de Auditoría y Evaluación de Viabilidad: Migración de Alertas de Malware de n8n a Supabase Nativo

- **Fecha de Auditoría:** 2026-09-01
- **Proyecto:** ShadowNet Defender Extractor V2
- **Módulo Auditado:** Integración N8N (`core/integrations/n8n_client.py` y orquestación asociada)
- **Estado de Viabilidad:** **100% Viable**

---

## 1. Resumen Ejecutivo

El objetivo de esta auditoría es evaluar la factibilidad técnica de eliminar la dependencia externa de **n8n** para el envío de alertas por correo electrónico ante la detección de malware, migrando dicha funcionalidad a una arquitectura nativa en **Supabase** basada en **Database Webhooks** y **Edge Functions (Deno/TypeScript)**.

### Resultados Principales
- **Viabilidad Técnica:** **100% Viable.**
- **Reducción de Puntos Únicos de Fallo:** Se elimina la dependencia de un servidor n8n en ejecución y de túneles dinámicos (ngrok) requeridos para recibir webhooks en entornos locales o de desarrollo.
- **Costo Operativo:** **$0 / mes** utilizando las capas gratuitas de Supabase (500,000 invocaciones/mes de Edge Functions) y proveedores como Resend (3,000 envíos/mes) o Gmail SMTP.
- **Transparencia en el Backend:** Desacopla el backend de Python de la transmisión de alertas HTTP sincrónicas durante el proceso de escaneo.

---

## 2. Auditoría del Estado Actual (Módulos e Integraciones n8n)

### 2.1. Ubicación y Estructura del Código Actual

1. **Cliente de Integración (`core/integrations/n8n_client.py`)**:
   - **Función Pública:** `send_scan_result(scan_result: Dict[str, Any]) -> bool`
   - **Variables de Entorno:**
     - `N8N_ENABLED` (default: `False`)
     - `N8N_WEBHOOK_TEST` y `N8N_WEBHOOK_PROD`
     - `N8N_TIMEOUT_SECONDS` (default: `8`)
     - `N8N_ALERT_ON_STATUS` (default: `DANGEROUS,SUSPICIOUS`)
     - `N8N_ALERT_ON_LABEL_ONLY` (default: `False`)
   - **Mecanismos de Resiliencia:** Retry exponencial en HTTP 5xx (máx. 2 reintentos con backoff de 1s y 2s) y desinfección de valores float no finitos (`NaN`/`Inf`) mediante `_safe_json()`.

2. **Invocación desde el Pipeline y Servicios**:
   - **`backend/app/services/scan_service.py`**: En `scan_and_explain()`, tras persistir el resultado mediante `save_scan_safe()`, se ejecuta `_notify_n8n(scan_result)`.
   - **`core/scan_pipeline.py`**: En `run_scan_explain_pipeline()`, si `dispatch_n8n=True`, se ejecuta `send_scan_result(scan_result)`.
   - **`tools/cli.py`**: Invoca `send_scan_result()` de forma directa al finalizar el escaneo CLI.

3. **Lógica de Negocio y Reglas de Filtro Actuales**:
   - **Filtro de Disparo:**
     $$\text{Alertar} \iff (\text{result} = \text{"malicious"}) \lor (\text{operational\_status} \in \{\text{"DANGEROUS"}, \text{"SUSPICIOUS"}\})$$
   - **Categorías de Eventos Transmitidas:**
     - `malware_critical`: `result == "malicious"` AND `operational_status == "DANGEROUS"`.
     - `dangerous_detected`: `operational_status == "DANGEROUS"`.
     - `malware_detected`: `result == "malicious"`.

4. **Campos del Payload Enviado a n8n**:
   - Archivo y resultado: `file_name`, `sha256`, `scan_type`, `result`, `risk_level`, `score`, `explanation`.
   - Datos del usuario: `user_id`, `user_email`.
   - Datos del sistema: `system_info` (`os`, `hostname`).
   - Telemetría extendida de auditoría: `operational_status`, `risk_score`, `detection_phases`, `top_family`, `injection_detected`, `persistence_detected`, `credential_theft_detected`, `yara_matches`.

---

## 3. Mapeo a la Arquitectura Nativa de Supabase

```
========================================================================================
                               ARQUITECTURA ACTUAL (n8n)
========================================================================================
[ Escaneo PE / API ] ──► [ backend Python ] ──► [ HTTP POST ] ──► [ n8n ] ──► [ Email ]
                             │
                             └─► [ Supabase `scan_results` ]

========================================================================================
                        ARQUITECTURA PROPUESTA (SUPABASE NATIVO)
========================================================================================
[ Escaneo PE / API ] ──► [ Supabase `scan_results` (INSERT) ]
                                     │
                                     ▼ (Database Webhook Trigger en INSERT)
                        [ Supabase Edge Function (Deno TS) ]
                                     │
                                     ▼ (API HTTP / SMTP)
                        [ Resend API / Gmail SMTP ] ──► [ User Email ]
========================================================================================
```

### Tabla Comparativa de Componentes

| Función | Implementación n8n Actual | Implementación Supabase Nativa | Viabilidad |
| :--- | :--- | :--- | :--- |
| **Event Trigger** | Disparo imperativo HTTP POST desde Python. | **Database Webhook** nativo en PostgreSQL `AFTER INSERT ON scan_results`. | **100% Viable** |
| **Lógica de Filtro** | Código Python en `n8n_client.py`. | Condicional SQL en el Webhook / Validación dentro de la Edge Function. | **100% Viable** |
| **Destinatario Email** | Leído del payload (`user_email`). | Leído del registro `NEW.user_email` o consulta `JOIN` a la tabla `users` mediante `NEW.user_id`. | **100% Viable** |
| **Plantilla y Formato** | Template de n8n. | Template HTML renderizado en la Edge Function (Deno TypeScript). | **100% Viable** |
| **Envío de Correo** | Nodo SMTP/Gmail en n8n. | Servicio Resend API (HTTP) o Nodemailer sobre Gmail SMTP. | **100% Viable** |
| **Reintentos** | Bucle `_send_webhook_with_retry`. | Sistema nativo de reintentos HTTP de Supabase Webhooks. | **100% Viable** |

---

## 4. Diseño Técnico de la Solución Nativa

### 4.1. Configuración del Database Webhook

En la consola de Supabase o mediante migración SQL:

- **Tabla:** `scan_results`
- **Evento:** `INSERT`
- **Condición de Disparo:** `NEW.result = 'malicious' OR NEW.operational_status = 'DANGEROUS'`
- **Target URL:** `https://<SUPABASE_PROJECT_ID>.supabase.co/functions/v1/send-malware-alert`
- **HTTP Method:** `POST`
- **Headers:** `Content-Type: application/json`, `Authorization: Bearer <ANON_OR_SERVICE_KEY>`

### 4.2. Código de la Edge Function (`send-malware-alert/index.ts`)

```typescript
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY");
const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

serve(async (req) => {
  try {
    const payload = await req.json();
    const record = payload.record;

    // 1. Filtrado de seguridad
    const isMalicious = record.result === "malicious";
    const isDangerous = record.operational_status === "DANGEROUS";
    if (!isMalicious && !isDangerous) {
      return new Response(JSON.stringify({ skipped: true, reason: "Non-critical scan" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 2. Obtención del correo del usuario
    let recipientEmail = record.user_email;
    if (!recipientEmail && record.user_id) {
      const supabase = createClient(SUPABASE_URL!, SUPABASE_SERVICE_ROLE_KEY!);
      const { data: user } = await supabase
        .from("users")
        .select("email")
        .eq("id", record.user_id)
        .single();
      recipientEmail = user?.email;
    }

    if (!recipientEmail) {
      return new Response(
        JSON.stringify({ error: "No user email found for scan result" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // 3. Formateo de la plantilla de alerta
    const scorePct = ((record.score || 0) * 100).toFixed(1);
    const htmlBody = `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e1e1e1; border-radius: 8px; padding: 20px;">
        <h2 style="color: #d9534f;">🚨 Alerta de Malware Detectado — ShadowNet Defender</h2>
        <p>Se ha registrado una amenaza en el escaneo de archivo:</p>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Archivo:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${record.file_name}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Resultado:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee; color: #d9534f; font-weight: bold;">${record.result.toUpperCase()}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Estado Operativo:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${record.operational_status}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Nivel de Riesgo:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${record.risk_level}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Probabilidad Malware:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${scorePct}%</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>SHA-256:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px;">${record.sha256 || "N/A"}</td></tr>
        </table>
        ${
          record.explanation
            ? `<div style="background-color: #f9f9f9; padding: 12px; border-left: 4px solid #0275d8; margin-top: 15px;">
                <h4 style="margin-top:0;">Análisis del Asistente LLM:</h4>
                <p style="white-space: pre-line; font-size: 14px;">${record.explanation}</p>
              </div>`
            : ""
        }
        <p style="font-size: 12px; color: #777; margin-top: 30px;">Notificación automática enviada por ShadowNet Defender SOC Agent.</p>
      </div>
    `;

    // 4. Envío vía Resend API
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: "ShadowNet Alerts <onboarding@resend.dev>",
        to: [recipientEmail],
        subject: `🚨 Alerta Crítica: Malware Detectado en ${record.file_name}`,
        html: htmlBody,
      }),
    });

    const resendData = await resendRes.json();
    return new Response(JSON.stringify({ success: true, resendData }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
```

---

## 5. Plan de Ejecución para la Migración

1. **Paso 1: Configurar Cuenta de Envío de Correos**
   - Registrar una cuenta en **Resend** (o servicio equivalente como SendGrid/Mailgun) y obtener la API Key.
2. **Paso 2: Desarrollar y Desplegar la Edge Function**
   - Crear el directorio de la función en la CLI de Supabase.
   - Guardar el secreto: `supabase secrets set RESEND_API_KEY=re_123456...`.
   - Desplegar la función a producción: `supabase functions deploy send-malware-alert`.
3. **Paso 3: Activar el Database Webhook**
   - Configurar el Webhook en la tabla `scan_results` con los filtros indicados.
4. **Paso 4: Desactivación Gradual de n8n**
   - Cambiar `N8N_ENABLED=false` en el archivo `.env`.
   - Realizar escaneos de prueba en el entorno de desarrollo/staging.
   - Confirmar la recepción del correo enviado por la Edge Function.
5. **Paso 5: Limpieza de Código Backend (Post-Verificación)**
   - Marcar `core/integrations/n8n_client.py` como obsoleto/deprecated o remover las llamadas en `scan_service.py`.

---

## 6. Riesgos y Consideraciones Finales

- **Límites de Uso Gratuito (Resend):** La capa gratuita ofrece hasta 3,000 emails/mes. Dado que solo se envían correos para `malicious` / `DANGEROUS`, la cuota es más que suficiente para operación estándar.
- **Monitoreo:** El estado de los envíos se puede revisar directamente desde el panel de Supabase en **Logs -> Edge Functions** y en el panel de control de Resend.
- **Reintentos:** Supabase reintenta automáticamente la invocación del Webhook si la Edge Function responde con un error HTTP o timeout.
