/* radare - LGPL - 2015 - maijin */

#include <r_bin.h>
#include "3DSX_specs.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 4) return false;
	return (!memcmp (buf, _3DSX_MAGIC, 4));
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	_3DSX_hdr _3dsxhdr;
	memset (&_3dsxhdr, 0, _3DSX_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&_3dsxhdr, _3DSX_HDR_SIZE);
	if (reat != _3DSX_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = strdup ("Sound File Data");
	ret->machine = strdup ("3DSX");
	ret->os = strdup ("3DS");
	ret->arch = strdup ("arm");
	ret->bits = 32;
  ret->has_va = 1;
		return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	_3DSX_hdr _3dsxhdr;
	memset (&_3dsxhdr, 0, _3DSX_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&_3dsxhdr, _3DSX_HDR_SIZE);
	if (reat != _3DSX_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = r_list_new ()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, ".text");
	ptr->paddr = _3dsxhdr.header_size + 3 * _3DSX_RELOC_HDR_SIZE;
	ptr->size = _3dsxhdr.code_seg_size;
	ptr->vaddr = CODE_START_ADDRESS;
	ptr->vsize = _3dsxhdr.code_seg_size;
	ptr->srwx = R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;;
	r_list_append (ret, ptr);
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, ".rodata");
	ptr->paddr = _3dsxhdr.header_size + 3 * _3DSX_RELOC_HDR_SIZE + _3dsxhdr.code_seg_size;
	ptr->size = _3dsxhdr.rodata_seg_size;
	ptr->vaddr = CODE_START_ADDRESS + 3 * _3DSX_RELOC_HDR_SIZE + _3dsxhdr.code_seg_size;
	ptr->vsize = _3dsxhdr.rodata_seg_size;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	r_list_append (ret, ptr);
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, ".data");
	ptr->paddr = _3dsxhdr.header_size + 3 * _3DSX_RELOC_HDR_SIZE + _3dsxhdr.code_seg_size + _3dsxhdr.rodata_seg_size;
	ptr->size = _3dsxhdr.data_seg_size - _3dsxhdr.bss_seg_size;
	ptr->vaddr = CODE_START_ADDRESS + 3 * _3DSX_RELOC_HDR_SIZE + _3dsxhdr.code_seg_size + _3dsxhdr.rodata_seg_size;
	ptr->vsize = _3dsxhdr.data_seg_size - _3dsxhdr.bss_seg_size;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_MAP;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	_3DSX_hdr _3dsxhdr;

	memset (&_3dsxhdr, 0, _3DSX_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&_3dsxhdr, _3DSX_HDR_SIZE);
	if (reat != _3DSX_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = r_list_new ()))
			return NULL;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = _3dsxhdr.header_size + 3 * _3DSX_RELOC_HDR_SIZE;
	ptr->vaddr = CODE_START_ADDRESS;
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_3DSX = {
	.name = "3DSX",
	.desc = "3DSX - homebrew applications on the 3DS",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_3DSX,
	.version = R2_VERSION
};
#endif
