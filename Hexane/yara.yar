rule Hexane_CMDHandlerDLL_v19 : IRAN THREAT ACTOR {
   meta:
      description = "Detects Lyceum-Hexane command handler DLL based on internal strings"
      author = "Emanuele De Lucia"
      date = "2019-08-03"
	  tlp = "white"
   strings:
      $s1 = "Set shell=CreateObject(\"WScript.Shell\")" fullword wide
      $s2 = " 2>&1  & echo ------------------------- >>" fullword wide
      $s3 = "shell.CurrentDirectory=\"" fullword wide
      $s4 = " Set fl = CreateObject(\"Scripting.FileSystemObject\")" fullword wide
      $s5 = "rmdir /s /q {0}" fullword wide
      $s6 = "Wscript.Quit 1" fullword wide
      $s7 = "Downloads Dir" fullword wide
      $s8 = "DownloadsPath" fullword ascii
      $s9 = "Dim shell" fullword wide
      $s10 = "On Error Resume Next" fullword wide
      $s11 = "Proxy Saved" fullword wide
	  $s12 = "Copied File By Name " fullword wide
      $s13 = "Copied File" fullword wide
      $s14 = "File Moved" fullword wide
      $s15 = " =>Uploads" fullword wide
      $s16 = "File Copied" fullword wide
      $s17 = "Uploads Dir" fullword wide
      $s18 = "UploadsPath" fullword ascii
      $s19 = "\"*DLL@\"" fullword wide
      $s20 = "fl.DeleteFile \"" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and ( 10 of them ))
}
