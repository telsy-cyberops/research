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

rule APT38_LDACLS_78736_45 : DPRK THREAT ACTOR  {
   meta:
      description = "Detects APT38-Lazarus Linux DACLS"
      author = "Emanuele De Lucia"
      reference = "https://blog.netlab.360.com/dacls-the-dual-platform-rat/"
      hash = "ba5b781ebacac07c4b14f9430a23ca0442e294236bd8dd14d1f69c6661551db8"
   strings:
      $pt = "INTERNAL_SYSCALL_ERRNO (e, __err) != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s2 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s3 = "TLS generation counter wrapped!  Please report as described in <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>." fullword ascii
      $s4 = "Bad mutex, operation failed" fullword ascii
      $s5 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s6 = "int_no <= (uintmax_t) (exponent < 0 ? (INTMAX_MAX - bits + 1) / 4 : (INTMAX_MAX - exponent - bits + 1) / 4)" fullword ascii
      $s7 = "Unable to decode an indefinite length encoded message" fullword ascii
      $s8 = "Unexpected error %d on netlink descriptor %d (address family %d)" fullword ascii
      $s9 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s10 = "dig_no > int_no && exponent <= 0 && exponent >= MIN_10_EXP - (DIG + 2)" fullword ascii
      $s11 = "previous_prio == -1 || (previous_prio >= fifo_min_prio && previous_prio <= fifo_max_prio)" fullword ascii
      $s12 = "The Key Share data contains group that wasn't in Client Hello" fullword ascii
      $s13 = "Unexpected netlink response of size %zd on descriptor %d (address family %d)" fullword ascii
      $s14 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s15 = "relocation processing: %s%s" fullword ascii
      $s16 = "Initialize ctx mutex error" fullword ascii
      $s17 = "ELF load command address/offset not properly aligned" fullword ascii
      $s18 = "!victim || chunk_is_mmapped (mem2chunk (victim)) || ar_ptr == arena_for_chunk (mem2chunk (victim))" fullword ascii
      $s19 = "!victim || chunk_is_mmapped (mem2chunk (victim)) || &main_arena == arena_for_chunk (mem2chunk (victim))" fullword ascii
      $s20 = "__pthread_mutex_lock_full" fullword ascii
   condition:
      (uint16(0) == 0x457f and filesize < 6000KB and ($pt and 10 of them))
}
import "pe"
rule APT38_WDACLS_78736_46 : DPRK THREAT ACTOR  {
   meta:
      description = "Detects APT38-Lazarus Win DACLS"
      author = "Emanuele De Lucia"
      reference = "https://blog.netlab.360.com/dacls-the-dual-platform-rat/"
      hash1 = "d29bc522d23513cfbb5ff4542382e1b4f0df2fa6bced5fb479cd63b6f902c0eb"
   strings:
      $s1 = "assertion failed: s->d1->w_msg_hdr.msg_len + DTLS1_HM_HEADER_LENGTH == (unsigned int)s->init_num" fullword ascii
      $s2 = "assertion failed: s->init_num == (int)s->d1->w_msg_hdr.msg_len + DTLS1_HM_HEADER_LENGTH" fullword ascii
      $s3 = "tls_post_process_client_key_exchange" fullword ascii
      $s4 = "D:\\opensource\\openssl-dist-1.1.0f-vs2015\\openssl-x64-static-release-vs2015\\ssl/cert.pem" fullword ascii
      $s5 = "WindowsNT.dll" fullword ascii
      $s6 = "tls_post_process_client_hello" fullword ascii
      $s7 = "assertion failed: strlen(objstr) + 23 + 2 * EVP_CIPHER_iv_length(enc) + 13 <= sizeof buf" fullword ascii
      $s8 = "assertion failed: EVP_CIPHER_key_length(cipher) <= (int)sizeof(md_tmp)" fullword ascii
      $s9 = "tls_process_new_session_ticket" fullword ascii
      $s10 = "You need to read the OpenSSL FAQ, https://www.openssl.org/docs/faq.html" fullword ascii
      $s11 = "D:\\opensource\\openssl-dist-1.1.0f-vs2015\\openssl-x64-static-release-vs2015\\ssl/certs" fullword ascii
      $s12 = "D:\\opensource\\openssl-dist-1.1.0f-vs2015\\openssl-x64-static-release-vs2015\\lib\\engines-1_1" fullword ascii
      $s13 = "assertion failed: ctx->cipher->block_size == 1 || ctx->cipher->block_size == 8 || ctx->cipher->block_size == 16" fullword ascii
      $s14 = "D:\\opensource\\openssl-dist-1.1.0f-vs2015\\openssl-x64-static-release-vs2015\\ssl" fullword ascii
      $s15 = "dtls1_process_buffered_records" fullword ascii
      $s16 = "dtls_process_hello_verify" fullword ascii
      $s17 = "ssl_cipher_process_rulestr" fullword ascii
      $s18 = "tls_process_ske_psk_preamble" fullword ascii
      $s19 = "tls_process_cke_psk_preamble" fullword ascii
      $s20 = "assertion failed: data_plus_mac_plus_padding_size < 1024 * 1024" fullword ascii
   condition:
     (uint16(0) == 0x5a4d and filesize < 5000KB and ( pe.imphash() == "e399f5195df03e805c8a0b9cf73add01" and 15 of them ))
}
