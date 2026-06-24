/*
    worms.yar — Firmas YARA para Gusanos de Red (Worms)

    Los gusanos se distinguen por su capacidad de auto-propagación.
    Regla de oro en YARA: TODOS los strings declarados deben estar
    referenciados en la condition (directamente o mediante wildcard).
*/

rule WannaCry_Ransomworm {
    meta:
        description = "Detecta WannaCry — gusano ransomware EternalBlue (MS17-010)"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "worm"
        severity    = "critical"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wannacryptor"

    strings:
        // Todos bajo wildcard $str_wc* para evitar unreferenced errors
        $str_wc1 = ".WNCRY" ascii nocase
        $str_wc2 = ".WNCRYT" ascii
        $str_wc3 = "@Please_Read_Me@.txt" ascii
        $str_wc4 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii  // BTC Wallet
        $str_wc5 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii nocase
        $str_wc6 = "\\\\ADMIN$\\__" ascii
        $str_wc7 = "\\IPC$" ascii

        // Firma UTF-16 del nombre "Wncry"
        $hex_eblue = { 57 00 6E 00 63 00 72 00 79 00 }

    condition:
        (uint16(0) == 0x5A4D) and
        (2 of ($str_wc*) or $hex_eblue)
}


rule Mirai_Botnet_Worm {
    meta:
        description = "Detecta variantes del gusano botnet Mirai (IoT DDoS)"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "worm"
        severity    = "high"

    strings:
        // Strings únicos de Mirai — todos bajo wildcard $str_mirai*
        $str_mirai1 = "mirai" ascii nocase
        $str_mirai2 = "MIRAI" ascii
        $str_mirai3 = "report.intervals" ascii
        $str_mirai4 = "bot.killdisk" ascii nocase
        $str_mirai5 = "scanner.init" ascii
        $str_mirai6 = "DEFAULT_USERNAME" ascii
        $str_mirai7 = "TELNET" ascii wide

        // Credenciales por defecto para brute force en dispositivos IoT
        $str_cred1 = "root:xc3511" ascii
        $str_cred2 = "admin:admin" ascii
        $str_cred3 = "root:vizxv" ascii

    condition:
        (
            2 of ($str_mirai*) or
            (1 of ($str_mirai*) and 1 of ($str_cred*))
        )
}


rule Generic_Worm_Propagation {
    meta:
        description = "Detecta comportamiento genérico de propagación de gusanos de red"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "worm"
        severity    = "medium"

    strings:
        // APIs de red (propagación) — wildcard $api_net*
        $api_net1 = "WSAStartup" ascii
        $api_net2 = "connect" ascii
        $api_net3 = "send" ascii
        $api_net4 = "recv" ascii

        // APIs para copia en recursos compartidos SMB — wildcard $api_smb*
        $api_smb1 = "NetShareEnum" ascii
        $api_smb2 = "NetUseAdd" ascii
        $api_smb3 = "WNetAddConnection" ascii

        // Persistencia en registro — wildcard $api_reg*
        $api_reg1 = "RegSetValueEx" ascii
        $api_reg2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

        // Strings de rutas SMB — wildcard $str_smb*
        $str_smb1 = "\\\\%s\\ADMIN$" ascii
        $str_smb2 = "\\\\%s\\IPC$" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            (2 of ($api_smb*) and 1 of ($api_reg*)) or
            (1 of ($str_smb*) and 2 of ($api_net*))
        )
}
