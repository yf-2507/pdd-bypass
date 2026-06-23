/*
 * pdd_bypass.c -- K40 (alioth) ????
 * ARM64 syscall hook??? PDD ??
 *
 * ??: make (?? Makefile)
 * ??: insmod pdd_bypass.ko
 * ??: rmmod pdd_bypass
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pdd-bypass");
MODULE_DESCRIPTION("K40 PDD anti-detection - ARM64 syscall hooks");

/* ---- ARM64 syscall numbers (hardcoded, no header dependency) ---- */

#define NR_read          63
#define NR_openat        56
#define NR_connect      203
#define NR_faccessat     48
#define NR_newfstatat    79

/* ---- Syscall table pointer ---- */

static unsigned long *sys_call_table = NULL;

/* ---- Original handlers (stored as void* to avoid typeof on ARM64) ---- */

typedef long (*read_fn_t)(unsigned int, char __user *, size_t);
typedef long (*openat_fn_t)(int, const char __user *, int, umode_t);
typedef long (*connect_fn_t)(int, struct sockaddr __user *, int);
typedef long (*faccessat_fn_t)(int, const char __user *, int);
typedef long (*newfstatat_fn_t)(int, const char __user *, struct kstat __user *, int);

static read_fn_t        orig_read        = NULL;
static openat_fn_t      orig_openat      = NULL;
static connect_fn_t     orig_connect     = NULL;
static faccessat_fn_t   orig_faccessat   = NULL;
static newfstatat_fn_t  orig_newfstatat  = NULL;

/* ---- FD-to-path cache for /proc filtering ---- */

#define CACHE_SIZE 64

struct fd_path {
    int fd;
    char path[256];
};
static struct fd_path fd_cache[CACHE_SIZE];
static int cache_pos = 0;

static void cache_add(int fd, const char *path)
{
    if (fd < 0 || !path) return;
    fd_cache[cache_pos].fd = fd;
    strncpy(fd_cache[cache_pos].path, path, 255);
    fd_cache[cache_pos].path[255] = '\0';
    cache_pos = (cache_pos + 1) % CACHE_SIZE;
}

static const char *cache_lookup(int fd)
{
    int i;
    for (i = 0; i < CACHE_SIZE; i++)
        if (fd_cache[i].fd == fd)
            return fd_cache[i].path;
    return NULL;
}

/* ---- Path checking helpers ---- */

static int is_status(const char *p)  { return p && strstr(p, "/proc/self/status"); }
static int is_maps(const char *p)    { return p && (strstr(p, "/proc/self/maps")   || strstr(p, "/proc/self/smaps")); }

static int has_bad_kw(const char *s)
{
    static const char *kw[] = {"frida","gadget","apatch","magisk","xposed","lsposed","riru","zygisk","substrate","linjector",NULL};
    int i;
    if (!s) return 0;
    for (i = 0; kw[i]; i++)
        if (strstr(s, kw[i])) return 1;
    return 0;
}

/* ---- 1. sys_read hook ---- */

static long hooked_read(unsigned int fd, char __user *buf, size_t count)
{
    const char *path = cache_lookup((int)fd);
    long ret;
    char *kbuf;

    if (!is_status(path) && !is_maps(path))
        return orig_read(fd, buf, count);

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) return orig_read(fd, buf, count);

    ret = orig_read(fd, kbuf, count);
    if (ret <= 0) { kfree(kbuf); return ret; }

    if (is_status(path)) {
        /* Zero out TracerPid */
        char *tp = strstr(kbuf, "TracerPid:");
        if (tp) {
            char *v = tp + 10;
            while (*v == ' ' || *v == '\t') v++;
            while (*v >= '0' && *v <= '9') *v++ = '0';
        }
    } else {
        /* Remove lines with bad keywords from maps */
        char *line, *end;
        for (line = kbuf; line < kbuf + ret; line = end + 1) {
            end = strchr(line, '\n');
            if (!end) break;
            *end = '\0';
            if (has_bad_kw(line)) memset(line, ' ', end - line);
            *end = '\n';
        }
    }

    if (copy_to_user(buf, kbuf, ret)) ret = -EFAULT;
    kfree(kbuf);
    return ret;
}

/* ---- 2. sys_openat hook ---- */

static long hooked_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    long fd = orig_openat(dfd, filename, flags, mode);
    if (fd >= 0 && filename) {
        char kname[256];
        if (strncpy_from_user(kname, filename, 255) > 0)
            cache_add((int)fd, kname);
    }
    return fd;
}

/* ---- 3. sys_connect hook ---- */

static long hooked_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    struct sockaddr_in sin;
    if (uservaddr && addrlen >= (int)sizeof(sin)) {
        if (copy_from_user(&sin, uservaddr, sizeof(sin)) == 0 && sin.sin_family == AF_INET) {
            unsigned short port = ntohs(sin.sin_port);
            if (port == 27042 || port == 27043 || port == 23946)
                return -ECONNREFUSED;
        }
    }
    return orig_connect(fd, uservaddr, addrlen);
}

/* ---- 4 & 5. faccessat + newfstatat hooks ---- */

static const char *hidden[] = {
    "/sbin/su","/system/xbin/su","/data/local/su",
    "/sbin/magisk","/data/adb/magisk","/data/adb/ap","/data/adb/modules",
    "frida-server","frida-agent", NULL
};

static int is_hidden(const char *p)
{
    int i;
    if (!p) return 0;
    for (i = 0; hidden[i]; i++)
        if (strstr(p, hidden[i])) return 1;
    return 0;
}

static long hooked_faccessat(int dfd, const char __user *filename, int mode)
{
    char kname[256];
    if (!filename) return orig_faccessat(dfd, filename, mode);
    if (strncpy_from_user(kname, filename, 255) > 0 && is_hidden(kname))
        return -ENOENT;
    return orig_faccessat(dfd, filename, mode);
}

static long hooked_newfstatat(int dfd, const char __user *filename,
                               struct kstat __user *statbuf, int flag)
{
    char kname[256];
    if (!filename) return orig_newfstatat(dfd, filename, statbuf, flag);
    if (strncpy_from_user(kname, filename, 255) > 0 && is_hidden(kname))
        return -ENOENT;
    return orig_newfstatat(dfd, filename, statbuf, flag);
}

/* ---- Init / Exit ---- */

static int __init pdd_bypass_init(void)
{
    unsigned long *tbl;

    tbl = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!tbl) {
        printk(KERN_ERR "[pdd_bypass] sys_call_table not found\n");
        return -ENODEV;
    }
    sys_call_table = tbl;
    printk(KERN_INFO "[pdd_bypass] sys_call_table at %px\n", tbl);

    /* Save originals */
    orig_read       = (read_fn_t)       sys_call_table[NR_read];
    orig_openat     = (openat_fn_t)     sys_call_table[NR_openat];
    orig_connect    = (connect_fn_t)    sys_call_table[NR_connect];
    orig_faccessat  = (faccessat_fn_t)  sys_call_table[NR_faccessat];
    orig_newfstatat = (newfstatat_fn_t) sys_call_table[NR_newfstatat];

    /* Install hooks */
    sys_call_table[NR_read]       = (unsigned long)hooked_read;
    sys_call_table[NR_openat]     = (unsigned long)hooked_openat;
    sys_call_table[NR_connect]    = (unsigned long)hooked_connect;
    sys_call_table[NR_faccessat]  = (unsigned long)hooked_faccessat;
    sys_call_table[NR_newfstatat] = (unsigned long)hooked_newfstatat;

    printk(KERN_INFO "[pdd_bypass] 5 syscall hooks installed\n");
    return 0;
}

static void __exit pdd_bypass_exit(void)
{
    if (!sys_call_table) return;
    sys_call_table[NR_read]       = (unsigned long)orig_read;
    sys_call_table[NR_openat]     = (unsigned long)orig_openat;
    sys_call_table[NR_connect]    = (unsigned long)orig_connect;
    sys_call_table[NR_faccessat]  = (unsigned long)orig_faccessat;
    sys_call_table[NR_newfstatat] = (unsigned long)orig_newfstatat;
    printk(KERN_INFO "[pdd_bypass] hooks removed\n");
}

module_init(pdd_bypass_init);
module_exit(pdd_bypass_exit);
