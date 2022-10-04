/*
   YARA Rule Set
   Author: WCS-SND Security Researcher
   Date: 2021-06-28   
  
*/

/* Rule Set ----------------------------------------------------------------- */

rule main_setup_x86x64 {
   meta:
      description = "tmpDJcr6g - file main_setup_x86x64.exe"
      hash1 = "6a91a4affa1ec1e4e06492a200ed0365f21a2576f065852944fd7fb362ed1370"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii
      $s3 = "ExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xm" ascii
      $s4 = "%s%S.dll" fullword wide
      $s5 = "Nullsoft Install System v3.06.1</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
      $s6 = "CRYPTBASE" fullword ascii
      $s7 = "t4|Z:\\" fullword ascii
      $s8 = "FE:\\:C" fullword ascii
      $s9 = " Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{3" ascii
      $s10 = "L:\"Y8u" fullword ascii
      $s11 = "-DX:\"2" fullword ascii
      $s12 = "tw2.kCY" fullword ascii
      $s13 = "PROPSYS" fullword ascii
      $s14 = "NTMARTA" fullword ascii
      $s15 = "UXTHEME" fullword ascii
      $s16 = "APPHELP" fullword ascii
      $s17 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s18 = "n}RAT\"'P" fullword ascii
      $s19 = "\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><support" ascii
      $s20 = "]TsiRCn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      1 of ($x*) and 4 of them
}

