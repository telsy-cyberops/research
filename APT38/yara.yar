rule APT38_DLLImplant_v14 : DPRK THREAT ACTOR {
   meta:
      author = "Emanuele De Lucia"
	  description = "Detects Lazarus DLL implanter"
	  tlp = "white"
   strings:
      /* params handling #1 */
      $fcode1 = { 83 BD DC F8 FF FF 05 0F 85 94 01 00 00 }
	  /* Dec  */
	  $fcode2 = { 0F B6 79 FE 0F B6 59 FF C1 E7 08 0B FB 0F B6 19 C1 E7 08 0B }
	  /* Strings */
	  $pack1 = "SetupWorkStation" fullword ascii
	  $pack2 = "SetupWorkStationW" fullword ascii
      $pack3 = "ShowState" fullword ascii
      $pack4 = "DnDll.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (2 of ($fcode*) and 4 of ($pack*))
}
