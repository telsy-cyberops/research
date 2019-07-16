rule SIDEWINDER_DOWNLOADER_ST1_v9 : SIDEWINDER APT {
   meta:
      description = "Detects Sidewinder APT 1st Stage Downloader"
      author = "Emanuele De Lucia"
      hash = "cb1831f4900824faef3a05a4df4b3a845a643da2f7190268de8f4dbed0539e40"
	  tlp = "white"
   strings:
      $s1 = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.56)" fullword wide
	  $s2 = "LinkZip.dll" fullword wide
      $s3 = "'System.Reflection.Assembly Load(Byte[])" fullword ascii
      $s4 = "$Example Assembly for DotNetToJScript" fullword ascii
	  $s5 = "bd.hta" fullword wide
      $s6 = "Example Assembly for DotNetToJScript" fullword wide
      $s7 = " James Forshaw 2017" fullword wide
      $s8 = "James Forshaw 2017" fullword ascii
	  $s9 = "File-not-Written" fullword wide
      $s10 = "$56598f1c-6d88-4994-a392-af337abe5777" fullword ascii
      $s11 = "finalName" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and 10 of them
}

rule SIDEWINDER_DOWNLOADER_ST2_v5 : SIDEWINDER APT {
   meta:
      description = "Detects Sidewinder APT 2nd Stage Downloader"
      author = "Emanuele De Lucia"
      hash = "913890af43c13a099b52700c1c699b5880a5cf488b177097667d87b0503fe590"
	  tlp = "white"
   strings: 
      $s1 = "PROPSYS.dll" fullword wide
      $s2 = "<supportedRuntime version=\"v2.0.50727\"/>" fullword wide
	  $s3 = "StInstaller.dll" fullword wide
      $s4 = "<startup useLegacyV2RuntimeActivationPolicy=\"true\">" fullword wide
      $s5 = "manifestContent" fullword ascii
	  $s6 = "<supportedRuntime version =\"v4.0\"/>" fullword wide
      $s7 = "hijackdllname" fullword ascii
      $s8 = "Already installed" fullword wide
      $s9 = "instfolder" fullword ascii
      $s10 = "'System.Reflection.Assembly Load(Byte[])" fullword ascii
      $s11 = "ReplaceBytes" fullword ascii
      $s12 = "StInstaller" fullword wide
      $s13 = "FindBytes" fullword ascii
	  $s14 = "UrlCombine" fullword ascii
      $s15 = "instpath" fullword ascii
      $s16 = "copyexe" fullword ascii
      $s17 = "</startup>" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and 10 of them
}


rule SIDEWINDER_LOADER_v11 : SIDEWINDER APT {
   meta:
      description = "Detects Sidewinder APT Implant Loader"
      author = "Emanuele De Lucia"
      date = "2019-07-16"
      hash = "0021247704d4d5cf6ae8ed245a19a840c00613d30ac082c367e21ce835095844"
	  tlp = "white"
   strings:
      $s1 = "PROPSYS.dll" fullword wide
      $s2 = "\\PROPSYS.dll" fullword ascii
      $s3 = "get_SettingsDoFileUpload" fullword ascii
      $s4 = "2MwNX8.tmp          " fullword wide
      $s5 = "get_SettingsSelectFileExtensions" fullword ascii
	  $s6 = "PluginLoader" fullword ascii
      $s7 = "get_SettingsServerUri" fullword ascii
	  $s8 = "get_SettingsMaxSelectFileSize" fullword ascii
      $s9 = "set_SettingsSelectFileExtensions" fullword ascii
	  $s10 = "set_SettingsDoFileUpload" fullword ascii
      $s11 = "SettingsDoFileUpload" fullword ascii
      $s12 = "set_SettingsMaxSelectFileSize" fullword ascii
      $s13 = "SettingsMaxSelectFileSize" fullword ascii
      $s14 = "SettingsSelectFileExtensions" fullword ascii
      $s15 = "PROPSYS" fullword ascii
      $s16 = "set_SettingsServerUri" fullword ascii
      $s17 = "SendSelectedFiles" fullword ascii
      $s18 = "SettingsServerUri" fullword ascii
      $s19 = "AddSelectedFile" fullword ascii
      $s20 = "SendFileListing" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and 10 of them
}
