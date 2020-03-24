rule Corona_Implanter_54343_56 : CRIMEWARE {
   meta:
      score = "100"
	  author = "Emanuele De Lucia"
      hash1 = "dfbcce38214fdde0b8c80771cfdec499fc086735c8e7e25293e7292fc7993b4c"
      hash2 = "f632b6e822d69fb54b41f83a357ff65d8bfc67bc3e304e88bf4d9f0c4aedc224"
   strings:
      $ = "kfftopk" fullword ascii
      $ = "%BU!T%M%b'q8'" fullword ascii
      $ = "tzsgho" fullword ascii
      $ = "q1cqdYB B" fullword ascii
      $ = "NhREG!$" fullword ascii
      $ = "mrjLG,," fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and 
			filesize < 1000KB and 
				( all of them ) ) 
}
