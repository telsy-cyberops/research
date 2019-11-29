rule APT_DustSquad_95765_v21 : APT Malware {
meta:
description = "Detects DustSquad Octopus"
reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
author = "Emanuele De Lucia"
date = "2019-11-29"
tlp = "white"
strings:
$string1 = "Address type not supported.\"%s:" fullword wide
$string2 = "Error reading %s%s%s: %s\"Character index out of bounds (%d)" fullword wide
$string3 = "The logon attempt failed;The credentials supplied to the package were not recognized" wide
$code1 = { B2 01 A1 28 D2 48 00 E8 52 D9 ED FF A3 BC DB 5D 00 8D 45 DC 50 33 C9 BA B0 F7 5C  }
$code2 = { 68 68 F8 5C 00 FF 35 B0 DB 5D 00 68 84 F8 5C 00 8D 45 A4 BA 03 00 00 00 E8 3C C3  }
$code3 = { 89 45 EC 8B 45 F8 BA 88 40 5C 00 E8 1D 73 E4 FF 75 0F BA A4 40 5C 00  8B 45 EC    }
condition:
uint16(0) == 0x5a4d and filesize < 6000KB and (all of them)
}
