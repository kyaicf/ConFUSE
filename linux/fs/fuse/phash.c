#include "fuse_i.h"

#include <linux/err.h>
#include <linux/gfp_types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/file.h>

/**
 * Metadata File
| Section      | Size(bytes) | Description                |
| ------------ | ----------- | -------------------------- |
| graphOffset  | uint32      | 记录图数据在文件中的偏移量 |
| inodesOffset | uint32      | 记录inodes在文件中的偏移量 |
| namesOffset  | uint32      | 记录inode文件名的偏移量    |
| salt1        | variable    | 包含salt1信息的数组        |
| salt2        | variable    | 包含salt2信息的数组        |
| graph        | variable    | 包含图信息的数组           |
| inodes       | variable    | 包含所有inodes信息的数组   |
| names        | variable    | 包含所有inodes的文件名     |
 */

static ssize_t fuse_phash_read_file(void *buf, struct file *metadata_file, loff_t pos, size_t count)
{
	pr_debug("%s: buf=0x%p, metadata_file=0x%p, pos=%lld, count=%ld\n", __func__, buf, metadata_file, pos, count);

	struct kvec iov;
	struct iov_iter iter;
	struct kiocb iocb;

	iov.iov_base = buf;
	iov.iov_len = count;
	iov_iter_kvec(&iter, ITER_DEST, &iov, 1, count);
	init_sync_kiocb(&iocb, metadata_file);
	iocb.ki_pos = pos;
	return vfs_iocb_iter_read(metadata_file, &iocb, &iter);
}

int fuse_phash_init(struct fuse_conn *fc, unsigned int metadata_fd)
{
	pr_debug("%s: fc=0x%p, metadata_fd=%d\n", __func__, fc, metadata_fd);

	struct cred *cred = prepare_creds();
	const struct cred *old_cred;
	struct file *file, *metadata_file;
	struct fuse_phash *fph, *old_fph;
	uint32_t *salt, *graph;
	ssize_t ret;
	int err = 0;

	file = fget(metadata_fd);

	char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
	char *path;
	if (buf) {
		path = d_path(&file->f_path, buf, PATH_MAX);
		if (IS_ERR(path)) {
			pr_debug("%s: fc=0x%p, metadata_fd=%d failed to get path to metadata file\n", __func__, fc, metadata_fd);
		} else {
			pr_debug("%s: fc=0x%p, metadata_fd=%d, path=%s\n", __func__, fc, metadata_fd, path);
		}
		kfree(buf);
	}

	metadata_file = dentry_open(&file->f_path, O_RDONLY, cred);
	if (IS_ERR(metadata_file)) {
		err = PTR_ERR(metadata_file);
		goto err;
	}

	fph = kmalloc(sizeof(struct fuse_phash), GFP_KERNEL);
	if (!fph) {
		err = -ENOMEM;
		goto err_put_metadata_file;
	}

	old_cred = override_creds(cred);

	ret = fuse_phash_read_file(&fph->md, metadata_file, 0, sizeof(fph->md));
	if (ret < 0) {
		err = ret;
		goto err_free_fph;
	}

	fph->salt_size = (fph->md.graph_offset - sizeof(fph->md)) / sizeof(uint32_t) / 2;
	fph->graph_size = (fph->md.inodes_offset - fph->md.graph_offset) / sizeof(uint32_t);
	fph->inodes_count = (fph->md.names_offset - fph->md.inodes_offset) / sizeof(struct fuse_attr);

	salt = kcalloc(2 * fph->salt_size, sizeof(uint32_t), GFP_KERNEL);
	if (!salt) {
		err = -ENOMEM;
		goto err_free_fph;
	}

	ret = fuse_phash_read_file(salt, metadata_file, sizeof(fph->md), 2 * fph->salt_size * sizeof(uint32_t));
	if (ret < 0) {
		err = ret;
		goto err_free_salt;
	}

	fph->salt1 = salt;
	fph->salt2 = salt + fph->salt_size;

	// May exceed KMALLOC_MAX_SIZE(4M)
	graph = vzalloc(fph->graph_size * sizeof(uint32_t));
	if (!salt) {
		err = -ENOMEM;
		goto err_free_salt;
	}

	ret = fuse_phash_read_file(graph, metadata_file, fph->md.graph_offset, fph->graph_size * sizeof(uint32_t));
	if (ret < 0) {
		err = ret;
		goto err_free_graph;
	}

	fph->graph = graph;
	fph->metadata_file = metadata_file;
	fph->cred = cred;
	refcount_set(&fph->count, 1);

	spin_lock(&fc->lock);
	old_fph = xchg(&fc->fph, fph);
	spin_unlock(&fc->lock);
	if (old_fph) {
		fuse_phash_put(old_fph);
	} else {
		wake_up_all(&fc->fph_waitq);
	}

	pr_debug("%s: fc=0x%p, metadata_fd=%d fuse perfect hash init success: fph=0x%p, metadata_file=0x%p, salt_size=%d, graph_size=%d, inodes_count=%d, graph_offset=%d, inodes_offset=%d, names_offset=%d, salt1=0x%p, salt2=0x%p, graph=0x%p\n", __func__, fc, metadata_fd, fph, fph->metadata_file, fph->salt_size, fph->graph_size, fph->inodes_count, fph->md.graph_offset, fph->md.inodes_offset, fph->md.names_offset, fph->salt1, fph->salt2, fph->graph);

	revert_creds(old_cred);
	fput(file);
	return 0;

err_free_graph:
	vfree(graph);
err_free_salt:
	kfree(salt);
err_free_fph:
	kfree(fph);
	revert_creds(old_cred);
err_put_metadata_file:
	fput(metadata_file);
err:
	fput(file);
	put_cred(cred);

	pr_debug("%s: fc=0x%p, metadata_fd=%d perfect hash init failure: err=%d\n", __func__, fc, metadata_fd, err);

	return err;
}

void fuse_phash_put(struct fuse_phash *fph)
{
	if (fph && refcount_dec_and_test(&fph->count)) {
		fput(fph->metadata_file);
		put_cred(fph->cred);
		kfree(fph->salt1);
		vfree(fph->graph);
		kfree(fph);
	}
}

struct fuse_phash *fuse_phash_get(struct fuse_phash *fph)
{
	if (fph && refcount_inc_not_zero(&fph->count))
		return fph;
	return NULL;
}

static uint32_t fuse_phash_get_index(struct fuse_phash *fph, u64 nodeid, const unsigned char *name, u32 len)
{
	pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d\n", __func__, fph, nodeid, name, len);

	uint32_t f1 = 0, f2 = 0;
	const unsigned char *nic = (const unsigned char *)&nodeid;

	for (u32 i = 0; i < 8 && i < fph->salt_size; i++) {
		f1 += fph->salt1[i] * nic[i];
		f2 += fph->salt2[i] * nic[i];
	}

	for (u32 j = 0; j < len && j + 8 < fph->salt_size ; j++) {
		f1 += fph->salt1[j+8] * name[j];
		f2 += fph->salt2[j+8] * name[j];
	}

	return (fph->graph[f1 % fph->graph_size] + fph->graph[f2 % fph->graph_size]) % fph->graph_size;
}

static int get_error(const unsigned char *name, u32 len)
{
	// go-fuse在mount结束前会open该文件并poll，需要由go-fuse处理
	if (len == 19 && !strncmp(name, ".go-fuse-epoll-hack", len)) {
		return -EPERM;
	}
	return -ENOENT;
}

int fuse_phash_get_entry_out(struct fuse_conn *fc, u64 nodeid, const unsigned char *name, u32 len, struct fuse_entry_out *outarg)
{
	struct fuse_phash *fph;
	uint32_t index;
	ssize_t ret;
	const struct cred *old_cred;
	unsigned char *inode_name;
	int err = 0;

	pr_debug("%s: fc=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p\n", __func__, fc, nodeid, name, len, outarg);

	// TODO(djx): 暂时共用passthrough的flag，后续更换
	if (fc->passthrough) {
		err = wait_event_interruptible(fc->fph_waitq, (fuse_conn_phash(fc) || (len == 19 && !strncmp(name, ".go-fuse-epoll-hack", len))));
		if (err) {
			return err;
		}
	}

	fph = fuse_phash_get(fuse_conn_phash(fc));
	if (!fph) {
		return -EINVAL;
	}

	pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p\n", __func__, fph, nodeid, name, len, outarg);

	memset(outarg, 0, sizeof(struct fuse_entry_out));

	index = fuse_phash_get_index(fph, nodeid, name, len);
	if (index >= fph->inodes_count) {

		pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p index out of range: index=%d\n", __func__, fph, nodeid, name, len, outarg, index);

		err = get_error(name, len);
		goto out_put_phash;
	}

	pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d\n", __func__, fph, nodeid, name, len, outarg, index);

	old_cred = override_creds(fph->cred);
	ret = fuse_phash_read_file(&outarg->attr, fph->metadata_file,
				   fph->md.inodes_offset + index * sizeof(struct fuse_attr), sizeof(struct fuse_attr));
	if (ret < 0) {

		pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d failed to read fuse attr: ret=%ld\n", __func__, fph, nodeid, name, len, outarg, index, ret);

		err = ret;
		goto out_revert_creds;
	}

	// index conflict
	if (outarg->attr.parent_ino != nodeid) {

		pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d parent nodeid does not match: outarg.attr.parent_ino=%lld\n", __func__, fph, nodeid, name, len, outarg, index, outarg->attr.parent_ino);

		err = get_error(name, len);
		goto out_revert_creds;
	} else if (outarg->attr.flags & FUSE_ATTR_NAME) {
		if ( len > 8 || strncmp(name, outarg->attr.name, len) || (len < 8 && outarg->attr.name[len])) {

			pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d name does not match: outarg.attr.name=%.8s\n", __func__, fph, nodeid, name, len, outarg, index, outarg->attr.name);

			err = get_error(name, len);
			goto out_revert_creds;
		}
	} else if (outarg->attr.n.length != len) {

		pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d name length does not match: outarg.attr.length=%d\n", __func__, fph, nodeid, name, len, outarg, index, outarg->attr.n.length);

		err = get_error(name, len);
		goto out_revert_creds;
	} else {
		inode_name = kzalloc((len + 1) * sizeof(char), GFP_KERNEL);
		if (!inode_name) {
			err = -ENOMEM;
			goto out_revert_creds;
		}

		ret = fuse_phash_read_file(inode_name, fph->metadata_file, fph->md.names_offset + outarg->attr.n.offset, outarg->attr.n.length);
		if (ret < 0) {

			pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d failed to read inode name: ret=%ld\n", __func__, fph, nodeid, name, len, outarg, index, ret);

			kfree(inode_name);
			err = ret;
			goto out_revert_creds;
		}

		if (strncmp(name, inode_name, len)) {

			pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d name does not match: outarg.attr.length=%d, outarg.attr.offset=%d, inode_name=%s\n", __func__, fph, nodeid, name, len, outarg, index, outarg->attr.n.length, outarg->attr.n.offset, inode_name);

			kfree(inode_name);
			err = get_error(name, len);
			goto out_revert_creds;
		}
		kfree(inode_name);
	}

	outarg->nodeid = outarg->attr.ino;
	outarg->generation = 0;
	outarg->entry_valid = 300;
	outarg->entry_valid_nsec = 0;
	outarg->attr_valid = MAX_SEC_IN_JIFFIES;
	outarg->attr_valid_nsec = 0;

	pr_debug("%s: fph=0x%p, nodeid=%lld, name=%s, len=%d, outarg=0x%p, index=%d, outarg.nodeid=%lld, outarg.entry_valid=%lld, outarg.entry_valid_nsec=%d, outarg.attr_valid=%lld, outarg.attr_valid_nsec=%d, outarg.attr.length=%d, outarg.attr.offset=%d, outarg.attr.name=%.8s, outarg.attr.ino=%lld, outarg.attr.parent_ino=%lld, outarg.attr.size=%lld, outarg.attr.mode=%d\n", __func__, fph, nodeid, name, len, outarg, index, outarg->nodeid, outarg->entry_valid, outarg->entry_valid_nsec, outarg->attr_valid, outarg->attr_valid_nsec, outarg->attr.n.length, outarg->attr.n.offset, (outarg->attr.flags & FUSE_ATTR_NAME) ? outarg->attr.name : "", outarg->attr.ino, outarg->attr.parent_ino, outarg->attr.size, outarg->attr.mode);

out_revert_creds:
	revert_creds(old_cred);
out_put_phash:
	fuse_phash_put(fph);
	return err;
}
