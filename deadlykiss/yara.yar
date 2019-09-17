rule APT_DeadlyKiss_DLL_v1 : UNKNOWN ORIGIN THREAT ACTOR {
        meta:
            description = "Detects DeadlyKiss APT dlls"
            author      = "Emanuele De Lucia"
            date        = "2019-09-17"
			tlp         = "white"
        strings:
		    /* Common exports in dataset */
			$export1 = "DllRegisterServer" ascii                          
			$export2 = "DllCanUnloadNow" ascii         
			$export3 = "DllGetClassObject" ascii
			/* SHELL */
			$shell = "SHELL32.dll" ascii
			/* Extracted matched common functions */
            $func1 = { 55 8B EC 8B 55 0C 8B 45 08 83 65 0C 00 D1 EA 85 C0 74 14 81 fA }
			$func2 = { 55 8B EC 83 EC 4C 83 65 FC 00 EB 07 8B 45 FC 40 89 45 FC 83 7D } 
			
        condition:
            uint16(0) == 0x5a4d and filesize < 700KB and (all of ($export*) and $shell or all of ($func*))
}
