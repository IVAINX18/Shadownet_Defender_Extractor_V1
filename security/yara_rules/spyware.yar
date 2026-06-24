/*
    spyware.yar — Firmas YARA para Spyware, Keyloggers y Stealers

    El spyware busca robar información del usuario:
        - Credenciales de navegadores (passwords, cookies)
        - Capturas de pantalla y keylogging
        - Wallets de criptomonedas
        - Tokens de Discord/Steam/etc.
*/

rule AgentTesla_Spyware {
    meta:
        description = "Detecta Agent Tesla — spyware y keylogger muy común en campañas de phishing"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "spyware"
        severity    = "high"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"

    strings:
        $str_at1    = "AgentTesla" ascii nocase wide
        $str_at2    = "Agent Tesla" ascii nocase wide

        // Strings de robo de credenciales de navegadores
        $str_chrome = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase
        $str_ff     = "\\Mozilla\\Firefox\\Profiles" ascii nocase
        $str_edge   = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii nocase

        // Strings de exfiltración por SMTP/FTP/Telegram
        $str_smtp   = "smtp.gmail.com" ascii nocase
        $str_mail   = "@gmail.com" ascii nocase
        $str_ftp    = "ftp.uploadserver" ascii nocase

        // Strings de keylogging — bajo wildcard $str_at*
        $str_at6 = "keylog" ascii nocase wide
        $str_at7 = "GetKeyboardLayout" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            any of ($str_at*) or
            (2 of ($str_chrome, $str_ff, $str_edge) and 1 of ($str_smtp, $str_ftp, $str_mail))
        )
}


rule RedLine_Stealer {
    meta:
        description = "Detecta RedLine Stealer — ladrón de credenciales y datos de navegadores"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "spyware"
        severity    = "high"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"

    strings:
        $str_rl1    = "RedLine" ascii nocase wide
        $str_rl2    = "red-line" ascii nocase

        // Robo de wallets de criptomonedas
        $str_w1     = "\\Exodus\\exodus.wallet" ascii nocase
        $str_w2     = "\\Electrum\\wallets" ascii nocase
        $str_w3     = "\\Ethereum\\keystore" ascii nocase
        $str_w4     = "wallet.dat" ascii nocase

        // Robo de tokens de Discord
        $str_discord = "\\Discord\\Local Storage\\leveldb" ascii nocase

        // Steam session stealing
        $str_steam  = "\\Steam\\config\\loginusers.vdf" ascii nocase

    condition:
        (uint16(0) == 0x5A4D) and
        (
            any of ($str_rl*) or
            (2 of ($str_w*) and 1 of ($str_discord, $str_steam)) or
            (3 of ($str_w*))
        )
}


rule Generic_Credential_Stealer {
    meta:
        description = "Detecta stealers genéricos de credenciales por patrones de acceso a datos sensibles"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "spyware"
        severity    = "medium"

    strings:
        // Acceso a SQLite de navegadores (almacén de contraseñas)
        $str_sql1   = "SELECT origin_url, username_value, password_value FROM logins" ascii nocase
        $str_sql2   = "SELECT host_key, name, encrypted_value FROM cookies" ascii nocase

        // Desencriptado de credenciales de Windows DPAPI
        $str_dpapi  = "CryptUnprotectData" ascii

        // Exfiltración HTTP
        $str_exfil1 = "multipart/form-data" ascii nocase

        // Acceso a archivos de contraseñas maestras
        $str_pass1  = "key3.db" ascii
        $str_pass2  = "logins.json" ascii
        $str_pass3  = "signons.sqlite" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            1 of ($str_sql*) or
            ($str_dpapi and 2 of ($str_pass*)) or
            (1 of ($str_sql*) and $str_exfil1)
        )
}


rule Keylogger_Generic {
    meta:
        description = "Detecta keyloggers genéricos por uso de hooks de teclado de Windows"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "spyware"
        severity    = "medium"

    strings:
        // APIs de hooking de teclado
        $api_hook1  = "SetWindowsHookExA" ascii
        $api_hook2  = "SetWindowsHookExW" ascii
        $api_key1   = "GetKeyState" ascii
        $api_key2   = "GetAsyncKeyState" ascii

        // Escritura de log de teclas en archivo
        $str_log1   = "keystrokes.txt" ascii nocase
        $str_log2   = "keylog.txt" ascii nocase
        $str_log3   = "[ENTER]" ascii
        $str_log4   = "[SPACE]" ascii
        $str_log5   = "[BACKSPACE]" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            (1 of ($api_hook*) and 1 of ($api_key*)) or
            (2 of ($str_log*) and 1 of ($api_key*))
        )
}
