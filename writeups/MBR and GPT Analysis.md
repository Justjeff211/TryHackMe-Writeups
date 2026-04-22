
# TryHackMe Write-up: MBR and GPT Analysis

## Room Information

Platform: TryHackMe

Room Name: MBR and GPT Analysis

Difficulty: Medium

Date Completed: 22/04/2026

https://github.com/user-attachments/assets/bd3e439a-56fe-4235-971b-e9aaa371a38b


----------

## Objective

Analyse disk structures and the boot process to identify tampering and understand how attackers target MBR and GPT systems.

----------

## Summary

In this room, I analysed how disks are structured using **MBR and GPT**, and how the boot process works at a low level.

I performed manual analysis using a hex editor to:

-   Identify partition structures
-   Calculate partition sizes
-   Repair a corrupted MBR
-   Analyse GPT partition entries
-   Detect indicators of bootkit activity

I also identified encoded data inside a bootloader, which demonstrates how attackers hide malicious content at the firmware level.

> The VM was unstable throughout the room and crashed multiple times. This forced me to repeatedly reload everything and re-verify steps, which slowed progress but reinforced a more methodical workflow.

----------

## Tools Used

-   HxD (Hex Editor)
-   FTK Imager
-   CyberChef

----------

## Boot Process

### Summary

I reviewed how a system boots and which components are involved before the operating system loads.

### Key Points

-   The boot process begins with **Power-On Self-Test (POST)**
-   Firmware (BIOS/UEFI) initialises hardware
-   A **bootable device** is selected
-   The **bootloader** loads the operating system

### Key Insight

-   UEFI supports GPT
-   BIOS typically uses MBR

----------

## MBR Analysis

### Summary

I analysed the structure of the MBR to understand how partition data is stored and interpreted.

### Analysis

-   MBR size: **512 bytes**
-   Partition table starts at **byte 446**
-   Each partition entry is **16 bytes**
-   Maximum of **4 partitions** supported
-   Magic number: `55 AA`

----------

### Partition Size Calculation

To determine partition size manually, I:

1.  Navigated to the partition table
2.  Located the correct partition entry
3.  Extracted the sector count (last 4 bytes)
4.  Converted from little-endian to big-endian
5.  Converted hex to decimal
6.  Multiplied by 512 (sector size)
7.  Converted bytes to GB (decimal format)

This process is critical when analysing raw disk data without relying on automated tools.

----------

## MBR Tampering Case

### Summary

I was provided with a corrupted disk image and had to identify and fix issues in the MBR.

----------

### Analysis

Using HxD:

-   The **magic number was corrupted**
-   The **LBA value of the partition was incorrect**
-   Only one partition entry contained valid data

----------

### Fix

-   Restored magic number to `55 AA`
-   Corrected LBA to the proper starting sector

----------

### Findings

-   Total partitions: **1**
-   Starting sector: **2048**
-   First byte at partition start: `EB`
-   File system: **NTFS**

----------

### Validation

I verified results by:

-   Calculating partition size manually
-   Cross-checking with FTK Imager

This ensured the integrity of the recovery process.

----------

### Evidence Discovery

After fixing the MBR:

-   I navigated the file system
-   Located the Administrator directory
-   Identified a file containing a hidden artefact

This demonstrates post-recovery forensic validation.

----------

## GPT Analysis

### Summary

I analysed GPT structure and extracted partition metadata manually.

----------

### Analysis

-   GPT supports up to **128 partitions**
-   Partition entries are stored in the **partition array**
-   Each entry is **128 bytes**

----------

### Process

1.  Calculated offset for the 3rd sector
2.  Located partition array
3.  Navigated to the 2nd partition entry
4.  Extracted the first 16 bytes
5.  Converted to GUID format

----------

### Key Insight

GPT improves on MBR by:

-   Providing redundancy
-   Supporting more partitions
-   Using structured metadata

----------

## UEFI Bootkit Analysis

### Summary

I analysed a bootloader to identify potential malicious indicators.

----------

### Analysis

While reviewing the bootloader file, I identified an encoded string:

SGVsbG8sIEVGSSBCb290a2l0IQ==

Indicators:

-   Ends with `==` > Base64 encoding
-   Located in bootloader > suspicious

----------

### Decoding

Using CyberChef:

-   Decoded the Base64 string
-   Revealed a hidden message

----------

### Key Insight

Bootkits:

-   Modify bootloaders
-   Execute before OS-level defences
-   Hide payloads using encoding

This makes them difficult to detect and highly persistent.

----------

## Conclusion

In this room, I:

-   Analysed MBR and GPT structures
-   Recovered a corrupted MBR
-   Calculated partition data manually
-   Navigated raw disk structures
-   Identified encoded content in a bootloader

The instability of the VM added friction, but also reinforced disciplined analysis and verification at each step.

This room strengthened my understanding of **disk forensics and pre-OS attack vectors**, which are critical in advanced incident response scenarios.
