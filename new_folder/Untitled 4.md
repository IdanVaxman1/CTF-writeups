## Incident Overview

A high-value system has been compromised. Security analysts detected suspicious activity within the kernel, but the attacker’s presence remained hidden. Traditional detection tools failed, and the intruder established deep persistence. The investigation focuses on a suspected kernel-level backdoor.

The first step is to check what is currently running inside the kernel modules using:

```bash
	cat /proc/modules
```

The following output was received:

```text 
	spatch 12288 0 - Live 0x0000000000000000 (OE)  
	btrfs 2035712 0 - Live 0x0000000000000000  
	blake2b_generic 24576 0 - Live 0x0000000000000000  
	xor 20480 1 btrfs, Live 0x0000000000000000  
	raid6_pq 126976 1 btrfs, Live 0x0000000000000000  
	ufs 126976 0 - Live 0x0000000000000000  
	msdos 16384 0 - Live 0x0000000000000000  
	xfs 2351104 0 - Live 0x0000000000000000  
	libcrc32c 12288 2 btrfs,xfs, Live 0x0000000000000000  
	8021q 45056 0 - Live 0x0000000000000000  
	garp 20480 1 8021q, Live 0x0000000000000000  
	mrp 20480 1 8021q, Live 0x0000000000000000  
	stp 12288 1 garp, Live 0x0000000000000000  
	llc 16384 2 garp,stp, Live 0x0000000000000000  
	ena 151552 0 - Live 0x0000000000000000  
	psmouse 217088 0 - Live 0x0000000000000000  
	input_leds 12288 0 - Live 0x0000000000000000  
	serio_raw 20480 0 - Live 0x0000000000000000  
	crct10dif_pclmul 12288 1 - Live 0x0000000000000000  
	crc32_pclmul 12288 0 - Live 0x0000000000000000  
	polyval_clmulni 12288 0 - Live 0x0000000000000000  
	polyval_generic 12288 1 polyval_clmulni, Live 0x0000000000000000  
	ghash_clmulni_intel 16384 0 - Live 0x0000000000000000  
	sha256_ssse3 32768 0 - Live 0x0000000000000000  
	sha1_ssse3 32768 0 - Live 0x0000000000000000  
	aesni_intel 356352 0 - Live 0x0000000000000000  
	crypto_simd 16384 1 aesni_intel, Live 0x0000000000000000  
	cryptd 24576 2 ghash_clmulni_intel,crypto_simd, Live 0x0000000000000000  
	binfmt_misc 24576 1 - Live 0x0000000000000000  
	sch_fq_codel 24576 3 - Live 0x0000000000000000  
	msr 12288 0 - Live 0x0000000000000000  
	parport_pc 53248 0 - Live 0x0000000000000000  
	ppdev 24576 0 - Live 0x0000000000000000  
	lp 32768 0 - Live 0x0000000000000000  
	dm_multipath 45056 0 - Live 0x0000000000000000  
	parport 73728 3 parport_pc,ppdev,lp, Live 0x0000000000000000  
	efi_pstore 12288 0 - Live 0x0000000000000000  
	nfnetlink 20480 2 - Live 0x0000000000000000  
	ip_tables 32768 0 - Live 0x0000000000000000  
	x_tables 65536 1 ip_tables, Live 0x0000000000000000  
	autofs4 57344 2 - Live 0x0000000000000000
```


The module spatch stands out because it is not a standard kernel module and is marked as (OE), which indicates it is an out-of-tree / external module.

Next step is to investigate the module using modinfo:

```bash
	/sbin/modinfo spatch
```

Output:
```text
	
	filename: /lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko  
	description: Cipher is always root  
	author: Cipher  
	license: GPL  
	srcversion: 81BE8A2753A1D8A9F28E91E  
	depends:  
	retpoline: Y  
	name: spatch  
	vermagic: 6.8.0-1016-aws SMP mod_unload modversions

```


The description and author are suspicious and suggest the module is not part of a standard trusted vendor.

Further analysis was performed using strings:

```bash
strings /lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko
```

Key output:

```text
	Linux
	Linux
	AUATL
	[A\A]]1
	AUATL
	get_flagH9
	[A\A]]1
	cipher_bd
	/tmp/cipher_output.txt
	/bin/sh
	%s > %s 2>&1
	get_flag
	/root/src/spatch.c
	HOME=/root
	3[CIPHER BACKDOOR] Failed to create /proc entry
	6[CIPHER BACKDOOR] Module loaded. Write data to /proc/%s
	6[CIPHER BACKDOOR] Module unloaded.
	3[CIPHER BACKDOOR] Failed to read output file
	6[CIPHER BACKDOOR] Command Output: %s
	3[CIPHER BACKDOOR] No output captured.
	6[CIPHER BACKDOOR] Executing command: %s
	3[CIPHER BACKDOOR] Failed to setup usermode helper.
	6[CIPHER BACKDOOR] Format: echo "COMMAND" > /proc/cipher_bd
	6[CIPHER BACKDOOR] Try: echo "%s" > /proc/cipher_bd
	6[CIPHER BACKDOOR] Here's the secret:  
	54484d7b73757033725f736e33346b795f643030727d0a
	PATH=/sbin:/bin:/usr/sbin:/usr/bin
	description=Cipher is always root

```

It was decoded using:

```bash
echo "4484d7b73757033725f736e33346b795f643030727d0a" | xxd -r -p
```

The final flag was retrieved.