/*
    ransomware.yar — Firmas YARA para Ransomware

    El ransomware se detecta por:
        1. Funciones criptográficas combinadas con modificación masiva de archivos
        2. Strings de notas de rescate
        3. Direcciones de wallets de criptomonedas
        4. Eliminación de copias de seguridad (Shadow Copies)
*/

rule Ransomware_Generic_Shadow_Deletion {
    meta:
        description = "Detecta eliminación de Shadow Copies — comportamiento universal del ransomware"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "ransomware"
        severity    = "critical"

    strings:
        // Comandos de eliminación de copias de seguridad de Windows
        $str_shadow1 = "vssadmin delete shadows" ascii nocase wide
        $str_shadow2 = "wbadmin delete catalog" ascii nocase wide
        $str_shadow3 = "bcdedit /set {default} recoveryenabled No" ascii nocase wide
        $str_shadow4 = "wmic shadowcopy delete" ascii nocase wide

        // Deshabilitar Windows Defender y restauración del sistema
        $str_def1 = "Set-MpPreference -DisableRealtimeMonitoring" ascii nocase wide
        $str_def2 = "DisableAntiSpyware" ascii nocase
        $str_restore = "DisableSystemRestore" ascii nocase

    condition:
        (uint16(0) == 0x5A4D) and
        (
            1 of ($str_shadow*) or
            (1 of ($str_def*) and $str_restore)
        )
}


rule LockBit_Ransomware {
    meta:
        description = "Detecta LockBit — ransomware RaaS (Ransomware as a Service)"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "ransomware"
        severity    = "critical"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"

    strings:
        $str_lb1 = "LockBit" ascii nocase wide
        $str_lb2 = "lockbit" ascii nocase
        $str_lb3 = "Restore-My-Files.txt" ascii nocase
        $str_lb4 = ".lockbit" ascii nocase
        $str_lb5 = "LockBit_Ransomware.hta" ascii nocase

        // Wallet y web onion del panel
        $str_onion1 = "lockbitsupport" ascii nocase
        $str_onion2 = ".onion" ascii nocase

    condition:
        (uint16(0) == 0x5A4D) and
        (2 of ($str_lb*) or ($str_onion1 and $str_onion2))
}


rule Ryuk_Ransomware {
    meta:
        description = "Detecta Ryuk — ransomware dirigido a empresas"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "ransomware"
        severity    = "critical"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"

    strings:
        $str_ryuk1 = "RyukReadMe.txt" ascii nocase
        $str_ryuk2 = "RYUK" ascii
        $str_ryuk3 = "ryuk" ascii nocase
        $str_ryuk4 = "No system is safe" ascii

        // API de cifrado que Ryuk usa
        $api_crypt1 = "CryptAcquireContext" ascii
        $api_crypt2 = "CryptGenKey" ascii
        $api_crypt3 = "CryptEncrypt" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (1 of ($str_ryuk*) or (3 of ($api_crypt*)))
}


rule Generic_File_Encryptor {
    meta:
        description = "Detecta comportamiento genérico de cifrado masivo de archivos"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "ransomware"
        severity    = "high"

    strings:
        // APIs de enumeración de archivos
        $api_find1 = "FindFirstFileW" ascii
        $api_find2 = "FindNextFileW" ascii
        $api_write = "WriteFile" ascii

        // APIs criptográficas de Windows (CryptoAPI)
        $api_crypt1 = "CryptAcquireContextW" ascii
        $api_crypt2 = "CryptEncrypt" ascii
        $api_crypt3 = "BCryptEncrypt" ascii

        // Extensiones comunes que el ransomware añade a los archivos
        $str_ext1 = ".encrypted" ascii nocase
        $str_ext2 = ".locked" ascii nocase
        $str_ext3 = ".crypted" ascii nocase
        $str_ext4 = ".enc" ascii nocase

        // Notas de rescate genéricas
        $str_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase wide
        $str_note2 = "To recover your files" ascii nocase wide
        $str_note3 = "Bitcoin" ascii nocase wide

    condition:
        (uint16(0) == 0x5A4D) and
        (
            (2 of ($api_crypt*) and 2 of ($api_find*) and $api_write) or
            (1 of ($str_note*) and 2 of ($api_crypt*)) or
            (2 of ($str_ext*) and $str_note3)
        )
}
