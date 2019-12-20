rule APT3_Filensfer_89834_73 : CHINESE THREAT ACTOR {
   meta:
          author = "Emanuele De Lucia"
		  description = "Detects C/C++ version of Filensfer (aka XServer)"
   strings:
      $cmd = "%s\\cmd.exe /c %s" fullword ascii
      $ = "Execute system commands." fullword ascii
      $ = "[+] Takes %ld seconds, an average speed of %s/s, Download the complete!" fullword ascii
      $ = "[-] Connected to [%s:%d] failed!" fullword ascii
      $ = "[-] Connected to proxy [%s:%d] failed!" fullword ascii
      $ = "[*] File download %0.2f%%,Speed:%s/s%10s" fullword ascii
      $ = "-ftp -s <port> [path] [-t<minute>] " fullword ascii
      $ = "[+] Get list complete,total %d objects." fullword ascii
      $ = "exec \"command\"" fullword ascii
      $ = "'%s' is not recognized as an internal or external command." fullword ascii
      $ = "From the remote host download files" fullword ascii
      $ = "[+] %s:%d Successfully connected services." fullword ascii
      $ = "title Transfer File Client - %s:%d" fullword ascii
      $ = "[*] File upload %0.2f%%,Speed:%s/s%10s" fullword ascii
      $ = "[*] Not complete the task,whether to continue the transmission? (y/n) " fullword ascii
      $ = "[+] Successfully connected to [%s:%d]" fullword ascii
      $ = "[-] Delete file '%s' failed." fullword ascii
   condition:
      (uint16(0) == 0x5a4d and filesize < 200KB and ($cmd  and 5 of them))
}
