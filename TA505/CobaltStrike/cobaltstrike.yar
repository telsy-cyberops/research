import "pe"
rule CobaltStrike_Implant_43223_21 : TA505 THREAT ACTOR {
   meta:
      description = "Detects CobalStrike variant used by TA505"
      author = "Emanuele De Lucia"
      hash1 = "341189f31b39ab16aa7454d683c46b5e3f2a8b693b842fcb0d129502d8e5fe5b"
	  reference = "https://github.com/StrangerealIntel/DailyIOC/blob/master/2020-02-25/TA505.csv"
	  tlp = "white"
   strings:
      $ = "mo_prov.dll" fullword ascii
	  $ = "P<T<X<\\<" fullword ascii
      $ = "H}J'A\\" fullword ascii
	  $ = "-$Mv5J" fullword ascii
      $ = "7d8K9S9" fullword ascii
   condition:
      (uint16(0) == 0x5a4d and filesize < 800KB and (pe.exports("getProv") and all of them ))
}
