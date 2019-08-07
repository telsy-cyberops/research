import "pe"

rule Evora_Loader_v23 : LOTUS PANDA CHINA THREAT ACTOR {
   meta:
      description = "Detects Lotus Panda Evora Loader"
      author = "Emanuele De Lucia"
      tlp = "white"
   strings:
      $s1 = "LoaderDLL.dll" fullword ascii
      $s2 = "444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii
      $s3 = "http://cyberproxy.pccw.com:8080" fullword ascii
      $s4 = "tttttttttttttttttttttttt99II::__--[[22QQ444444444444444444444444444444444444444444444444444444444444444444444444444444444444rr" fullword ascii
      $s5 = "http://10.87.10.206:8080" fullword ascii
      $s6 = "vYYYYYYYYYYYYYYYYYYYYYYYYY.G)N%R=S4" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and ( pe.imphash() == "f4d9c353dfa3971ec4e9f0ac7ed04f6e" or ( 4 of them ))
}
