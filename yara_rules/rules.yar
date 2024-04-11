rule asyncrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_async = "AsyncClient" wide ascii nocase
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_schtasks = "schtasks /create /f /sc onlogon /rl highest" wide ascii
        $dcrat_1 = "dcrat" wide ascii nocase
        $dcrat_2 = "qwqdan" wide ascii
        $dcrat_3 = "YW1zaS5kbGw=" wide ascii
        $dcrat_4 = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $dcrat_5 = "save_Plugin" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }
        $patt_config = { 72 [3] 70 80 [3] 04 }

    condition:
        (not any of ($dcrat*)) and 6 of them and #patt_config >= 10
 }

rule dcrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $venom_1 = "VenomRAT" wide ascii nocase
        $venom_2 = "HVNC_REPLY_MESSAGE" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_b64_amsi = "YW1zaS5kbGw=" wide ascii
        $str_b64_virtual_protect = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $str_dcrat = "dcrat" wide ascii nocase
        $str_plugin = "save_Plugin" wide ascii
        $str_qwqdan = "qwqdan" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        (not any of ($venom*)) and 5 of them and #patt_config >= 10
 }

rule quasarrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_quasar = "Quasar." wide ascii
        $str_hidden = "set_Hidden" wide ascii
        $str_shell = "DoShellExecuteResponse" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 25 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $byte_special_folder = { 7e 73 [4] 28 [4] 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        6 of them and #patt_config >= 10
 }

rule venomrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_id_venomrat = "venomrat" wide ascii nocase
        $str_hvnc = "HVNC_REPLY_MESSAGE" wide ascii
        $str_offline_keylogger = "OfflineKeylog sending...." wide ascii
        $str_videocontroller = "select * from Win32_VideoController" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_keylog = {73 [3] 06 80 [3] 04}
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        5 of them and #patt_config >= 10
 }
