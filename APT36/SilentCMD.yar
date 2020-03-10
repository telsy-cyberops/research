rule APT36_SilentCMD_54333_44 : APT  {
   meta:
      description = "Detects APT36 SilentCMD"
      author = "Emanuele De Lucia"
      hash1 = "b0dfb366cc63b4051bd100e5f8d132c400f4c0845d142c723d9c83efd1c52c1f"
   strings:
      $pdb = "SilentCMD.pdb" fullword ascii
	  $frm = ".NET Framework 4.5" fullword ascii
	  $exec = "SilentCMD.exe" fullword wide
      $log1 = "SilentCMD c:\\MyBatch.cmd /LOG+:c:\\MyLog.txt" fullword ascii
      $log2 = "SilentCMD c:\\MyBatch.cmd MyParam1 /LOG:c:\\MyLog.txt" fullword ascii
      $log3 = "SilentCMD c:\\MyBatch.cmd /DELAY:3600 /LOG+:c:\\MyLog.txt" fullword ascii
	  $log4 = "%temp%\\SilentCMD.log" fullword wide
   condition:
      uint16(0) == 0x5a4d and 
	  filesize < 40KB and
      ($pdb and 
	    $frm and 
		$exec and 
		4 of ($log*)
	  )
}
