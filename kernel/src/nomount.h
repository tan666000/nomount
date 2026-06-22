#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#ifndef CONFIG_DYNAMIC_FTRACE
#error "This LKM only works with Ftrace, please enable CONFIG_FUNCTION_TRACE and CONFIG_DYNAMIC_FTRACE in your kernel"
#endif

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

#define NOMOUNT_VERSION    10
#define NOMOUNT_HASH_BITS  12
#define NOMOUNT_UID_HASH_BITS 4
#define NM_FLAG_IS_DIR (1 << 1)

static DEFINE_HASHTABLE(nomount_dirs_ht,           NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_vpath,    NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_real_ino, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_v_ino,    NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_basenames_ht,      NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_uid_ht,            NOMOUNT_UID_HASH_BITS);
static LIST_HEAD(nomount_rules_list);
static LIST_HEAD(nomount_private_dirs_list);
static DEFINE_MUTEX(nomount_write_mutex);

/* logs */
#define nm_debug(fmt, ...) printk(KERN_DEBUG "NoMount: [DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...) printk(KERN_INFO "NoMount: " fmt, ##__VA_ARGS__)
#define nm_warn(fmt, ...) printk(KERN_WARNING "NoMount: [WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR "NoMount: [ERROR] " fmt, ##__VA_ARGS__)

struct nomount_rule {
    struct list_head list;
    struct hlist_node v_ino_node;
    struct hlist_node real_ino_node;
    struct hlist_node vpath_node;
    struct hlist_node basename_node;
    char *virtual_path;
    char *real_path;
    const char *basename;
    unsigned long v_ino;
    unsigned long real_ino;
    unsigned long parent_ino;
    u32 v_fs_type;
    u32 v_hash;
    u32 b_hash;
    dev_t v_dev;
    dev_t real_dev;
    dev_t parent_dev;
    u16 vp_len;
    u16 rp_len;
    u16 b_len;
    u8  flags;
};

struct nomount_child_name {
    unsigned long fake_ino;
    u16 name_len;
    u8 d_type;
    char name[256];
};

struct nm_child_array {
    atomic_t refcnt;
    u32 num_children;
    struct rcu_head rcu;
    struct nomount_child_name entries[]; /* Flexible array member */
};

struct nomount_dir_node {
    struct hlist_node node;
    struct list_head private_list;
    struct nm_child_array __rcu *child_array; 
    char *dir_path;
    unsigned long dir_ino;
    dev_t dir_dev;
    u16 dir_path_len;
    bool is_private;
};

struct nomount_uid_node {
    struct hlist_node node;
    uid_t uid;
};

/* ========================================================================= */
/* NETLINK GENERIC PROTOCOL DEFINITIONS */
/* ========================================================================= */

#define NOMOUNT_GENL_NAME "nomount"
#define NOMOUNT_GENL_VERSION 1

/* Commands */
enum {
    NOMOUNT_CMD_UNSPEC = 0,
    NOMOUNT_CMD_GET_VERSION,
    NOMOUNT_CMD_ADD_RULE,
    NOMOUNT_CMD_DEL_RULE,
    NOMOUNT_CMD_CLEAR_ALL,
    NOMOUNT_CMD_ADD_UID,
    NOMOUNT_CMD_DEL_UID,
    NOMOUNT_CMD_GET_LIST,
    __NOMOUNT_CMD_MAX,
};
#define NOMOUNT_CMD_MAX (__NOMOUNT_CMD_MAX - 1)

/* Attributes */
enum {
    NOMOUNT_ATTR_UNSPEC = 0,
    NOMOUNT_ATTR_VIRTUAL_PATH,  /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_REAL_PATH,     /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_FLAGS,         /* u32 (NLA_U32) */
    NOMOUNT_ATTR_UID,           /* u32 (NLA_U32) */
    NOMOUNT_ATTR_VERSION,       /* u32 (NLA_U32) */
    NOMOUNT_ATTR_PAYLOAD,       /* Binary payload for GET_LIST (NLA_BINARY) */
    __NOMOUNT_ATTR_MAX,
};

#define NOMOUNT_ATTR_MAX (__NOMOUNT_ATTR_MAX - 1)

/* * Compat macros for Generic Netlink Policy API changes.
 * Linux 4.20 moved the policy pointer from genl_ops to genl_family.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define NM_OPS_POLICY(p)    .policy = (p),
#define NM_FAMILY_POLICY(p)
#else
#define NM_OPS_POLICY(p)
#define NM_FAMILY_POLICY(p) .policy = (p),
#endif

/* Application UID start */
#define AID_APP_START 10000

/* ================================ */
/* Ftrace definitions and helpers   */
/* ================================ */

// LKM-specific includes
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t nm_kallsyms;

static int nm_resolve_kallsyms(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    nm_kallsyms = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}
#else
#define nm_kallsyms(name) kallsyms_lookup_name(name)
#endif

struct ftrace_ops;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#ifdef __x86_64__
    #define PT_REGS_IP(regs) ((regs)->ip)
#else
    #define PT_REGS_IP(regs) ((regs)->pc)
#endif

struct nm_hook {
    const char *name;
    void *hook_fn;
    void *orig_fn;
    unsigned long address;
    struct ftrace_ops ops;
};

static int nm_resolve_hook_address(struct nm_hook *hook)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    if (!nm_kallsyms) {
        if (nm_resolve_kallsyms()) return -ENOENT;
    }
#endif

    hook->address = nm_kallsyms(hook->name);
    if (!hook->address) {
        nm_debug("Unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->orig_fn) = hook->address;
    return 0;
}

static void notrace nm_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct nm_hook *hook = container_of(ops, struct nm_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE)) {
        PT_REGS_IP(regs) = (unsigned long)hook->hook_fn;
    }
}

static int nm_install_hook(struct nm_hook *hook) {
    int ret;

    ret = nm_resolve_hook_address(hook);
    if (ret) return ret;

    hook->ops.func = nm_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&hook->ops);
    if (ret) ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  
    return ret;
}

static void nm_remove_hook(struct nm_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

#endif /* _LINUX_NOMOUNT_H */
