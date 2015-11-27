/* radare - LGPL - 2015 - maijin */

// https://github.com/devkitPro/buildscripts/blob/master/dkarm-eabi/crtls/3dsx.ld

#ifndef _3DSX_H
#define _3DSX_H

#define _3DSX_MAGIC								 "3DSX"
#define _3DSX_HDR_SIZE						sizeof (_3DSX_hdr)

#define CODE_START_ADDRESS        0x00100000


typedef struct __attribute__((__packed__)) {
	ut32 magic;
	ut16 header_size;
	ut16 reloc_hdr_size;
	ut32 format_ver;
	ut32 flags;
	ut32 code_seg_size;
	ut32 rodata_seg_size;
	ut32 data_seg_size;
	ut32 bss_size;
} _3DSX_hdr;

typedef struct __attribute__((__packed__)) {
	ut32 smdh_hdr_offset;
	ut32 smdh_hdr_size;
	ut32 romfs_hdr_offset;
} _3DSX_extended_hdr;

typedef struct __attribute__((__packed__)) {
	ut32 num_absolute_reloc;
	ut32 num_relative_reloc;
} _3DSX_relocation_hdr;

typedef struct __attribute__((__packed__)) {
	ut16 number_words_skip;
	ut16 number_words_patch;
} _3DSX_relocation;

#endif // _3DSX_H
