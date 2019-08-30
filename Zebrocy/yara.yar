rule Zebrocy_NIMDownloader_v61 : RUSSIAN THREAT ACTOR {
   meta:
      description = "Detects Zebrocy nim downloader"
      author = "Emanuele De Lucia"
	  date = "2019-08-22"
      tlp = "white"
   strings:
      $x1 = "(Attempt to read from nil?)" fullword ascii
      $x2 = "libgcj-16.dll" fullword ascii
      $s1 = "@Ws2_32.dll" fullword ascii
      $s2 = "@user-agent" fullword ascii
      $s3 = "_tempFrames_7nBYIr2UsDREpYylZK4fug" fullword ascii
      $s4 = "@User-Agent" fullword ascii
      $s5 = "PROCESSOR_SKYLAKE_AVX512" fullword ascii
      $s6 = "PROCESSOR_GENERIC" fullword ascii
      $s7 = "PROCESSOR_PENTIUM" fullword ascii
      $s8 = "PROCESSOR_PENTIUM4" fullword ascii
      $s9 = "@Connection was closed before full request has been made" fullword ascii
      $s10 = "PROCESSOR_BDVER1" fullword ascii
      $s11 = "PROCESSOR_BDVER3" fullword ascii
      $s12 = "PROCESSOR_BDVER4" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and ( 2 of ($x*) and 6 of ($s*) )
}
