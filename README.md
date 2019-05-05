# Ghostbusters

This was a part of my undergraduate project. The files are MAMBO plugins.

## Dependencies:

- [MAMBO](https://github.com/beehive-lab/mambo)
- AArch64 device

## Files:

> source.c

This contains a proof of concept code for Spectre variant 1 (Bounds Check Bypass). It has been modified to support ARMv8 rather than x86.  
Also, it was only using Flush+Reload, so I attempted to develop the other cache attacks Prime+Probe, Evict+Time, and Flush+Flush, of which only the last worked.  
Compile with: `aarch64-linux-gnu-gcc -o spectre source.c -pie -std=gnu99 -lpthread -fPIC`

> stop_spectre_cache_attacks.c, stop_spectre_csdb.c, stop_spectre_full.c, stop_spectre_v4.c

These are the MAMBO plugins that I developed. Each have their ups and downs, they're commented.
