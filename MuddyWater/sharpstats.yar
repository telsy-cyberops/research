rule MuddyWater_SharpStats_v93 : MIDDLE EAST APT {
   meta:
      description = "Detects MuddyWater - SHARPSTATS"
      author = "Emanuele De Lucia"
	  tlp = "white"
   strings:
      $x1 = "GoogleUpdate.pdb" fullword ascii
	  $x2 = "System.Management.Automation.dll" fullword wide
      $x3 = "loaderx86.dll" fullword ascii
      $s1 = "chkdsk.exe" fullword wide
      $s2 = "temp_gh_12.dat" fullword wide
      $s3 = "GoogleUpdate.exe.config" fullword wide
      $s4 = "virtualboximportunit" fullword ascii
      $s5 = "DyYfJxxhakdWCg1UDzBkfiVnETEgLgB8NicALxIBfy8SDhwtN3BHAF1QcmwAEzsEBwEGDw8BBQ0oBXIHZXE6PgUrFz5aWW0OaANsBwAJEAAVHg8YAxpkDxstO1hRZgJ5" wide
      $s6 = "&path=Users" fullword wide
      $s7 = "TMapTemporaryFile" fullword ascii
      $s8 = "virtualboximportunit" fullword ascii
      $s9 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s10 = "attrib.exe" fullword wide
      $s11 = "tcpsvcs.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 1 of ($x*) and 8 of ($s*))) or ( all of them )
}
