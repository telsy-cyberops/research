rule APT32_KerrDown_IID952948 : OceanLotus {
   meta:
      description = "Detects KerrDown APT32 Malware - Hunter Rule - 31 samples - 1 Golden - 1923 base instructions set"
	  author = "Emanuele De Lucia"
	  tlp = "white"
   strings:
    $h1 = {55 8bec 83???? ff750c 8d???? e8 40 ff ff }
	  $h2 = {55 8bec e8???????? 8b???? 85c0 740e 8b   }
	  $h3 = {55 8bec 807d0800 56 57 8b7d0c 8bf1 7447  }
	  $h4 = {55 8bec ff???? e8???????? 59 b001 5d c3  }
	  $h5 = {55 8bec 807d0800 7512 e8???????? e8 4f   }
   condition:
      (uint16(0) == 0x5a4d) and all of them
   }
