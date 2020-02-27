rule APT38_ARTFULPIE_87763_87 : NK THREAT ACTOR {
   meta:
      description = "Detects APT38 ARTFULPIE"
      author = "Emanuele De Lucia"
	  tlp = "white"
	  malfamily = "ARTFULPIE"
	  actor = "Lazarus Group / Hidden Cobra"
   strings:
      $ = "PPPh @A" fullword ascii
      $ = "3>3D3M3X3h3" fullword ascii
      $ = "2`2d2h2p8t8x8|8" fullword ascii
      $ = {C7 43 (1C|20) (60|70) 1E 40 00}
   condition:
      filesize < 200KB and 
	  uint16(0) == 0x5a4d and 
	  all of them
}
