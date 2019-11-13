rule APT41_MESSAGETAP_18721_v33 : CHINESE THREAT ACTOR {
   meta:
      description = "Detects APT41-MESSAGETAP"
      author = "Emanuele De Lucia"
      date = "2019-11-13"
	    tlp = "white"
   strings:
      $x1 = "%04d%02d%02d_%d.dump" fullword ascii
      $x2 = "%s_%04d%02d%02d.csv" fullword ascii
      $x3 = "%04d%02d%02d.csv" fullword ascii
      $s1 = "get message type fail" fullword ascii
      $s2 = "GetLen fail" fullword ascii
      $s3 = "GetType fail" fullword ascii
      $s4 = "Operation_Global_Code_tag TODO" fullword ascii
      $s5 = "mem alloc failed" fullword ascii
      $s6 = "tcap parse begin component fail" fullword ascii
      $s7 = "GCC: (SUSE Linux) 4.3.4 [gcc-4_3-branch revision 152973]" fullword ascii
      $s8 = "tcap parse begin Dialogue fail" fullword ascii
   condition:
      (uint16(0) == 0x457f and filesize < 200KB and (1 of ($x*) and 4 of ($s*) ) )
}
