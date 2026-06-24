/*
    trojans.yar — Firmas YARA para Troyanos de Acceso Remoto (RATs)

    Regla de oro en YARA: TODOS los strings declarados deben estar
    referenciados en la condition (directamente o mediante wildcard $prefix*).
*/

rule njRAT_Generic {
    meta:
        description = "Detecta variantes del troyano de acceso remoto njRAT (Bladabindi)"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "trojan"
        severity    = "high"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"

    strings:
        // Identificadores únicos de njRAT — wildcard $str_njrat*
        $str_njrat1 = "njRAT" ascii nocase wide
        $str_njrat2 = "Bladabindi" ascii nocase wide
        $str_njrat3 = "houdini" ascii nocase wide

        // APIs de funcionalidad de njRAT — wildcard $str_func*
        $str_func1 = "GetKeyboardState" ascii wide
        $str_func2 = "keylog" ascii nocase wide
        $str_func3 = "CAM" ascii wide

        // Mutex de njRAT — wildcard $str_mutex*
        $str_mutex1 = "njq8" ascii
        $str_mutex2 = "Microsoft Corporation" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            any of ($str_njrat*) or
            (2 of ($str_func*) and 1 of ($str_mutex*))
        )
}


rule AsyncRAT_Generic {
    meta:
        description = "Detecta AsyncRAT — RAT de código abierto con .NET"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "trojan"
        severity    = "high"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"

    strings:
        // Identificadores de AsyncRAT — wildcard $str_async*
        $str_async1 = "AsyncRAT" ascii nocase wide
        $str_async2 = "AsyncClient" ascii wide
        $str_async3 = "ServerCertificate" ascii wide
        $str_async4 = "KeyboardHook" ascii wide
        $str_async5 = "pastebin.com" ascii nocase

        // Comunicación SSL — wildcard $str_ssl*
        $str_ssl1 = "SslStream" ascii wide
        $str_ssl2 = "RemoteCertificateValidationCallback" ascii wide

    condition:
        (uint16(0) == 0x5A4D) and
        (2 of ($str_async*) or (1 of ($str_async*) and 1 of ($str_ssl*)))
}


rule DarkComet_RAT {
    meta:
        description = "Detecta DarkComet RAT — uno de los troyanos más usados"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "trojan"
        severity    = "high"

    strings:
        // Identificadores de DarkComet — wildcard $str_dc*
        $str_dc1 = "DARKCOMET" ascii nocase wide
        $str_dc2 = "DarkComet-RAT" ascii nocase
        $str_dc3 = "DC4.2" ascii
        $str_dc4 = "#CRYPTO#" ascii
        $str_dc5 = "DC_MUTEX" ascii

    condition:
        (uint16(0) == 0x5A4D) and 2 of ($str_dc*)
}


rule Generic_RAT_Behavior {
    meta:
        description = "Detecta comportamiento genérico de RATs por combinación de APIs sospechosas"
        author      = "ShadowNet Defender"
        date        = "2024-01-01"
        category    = "trojan"
        severity    = "medium"

    strings:
        // APIs de inyección de procesos — wildcard $api_inject*
        $api_inject1 = "VirtualAllocEx" ascii
        $api_inject2 = "WriteProcessMemory" ascii
        $api_inject3 = "CreateRemoteThread" ascii
        $api_inject4 = "NtCreateThreadEx" ascii

        // APIs de detección de análisis (evasión) — wildcard $api_evasion*
        $api_evasion1 = "IsDebuggerPresent" ascii
        $api_evasion2 = "CheckRemoteDebuggerPresent" ascii

        // APIs de keylogging — wildcard $api_keylog*
        $api_keylog1 = "SetWindowsHookEx" ascii
        $api_keylog2 = "GetAsyncKeyState" ascii

        // APIs de captura de pantalla — wildcard $api_screen*
        $api_screen1 = "BitBlt" ascii
        $api_screen2 = "GetDC" ascii
        $api_screen3 = "CreateCompatibleDC" ascii

    condition:
        (uint16(0) == 0x5A4D) and
        (
            (2 of ($api_inject*) and 1 of ($api_evasion*)) or
            (2 of ($api_keylog*) and 2 of ($api_screen*))
        )
}
