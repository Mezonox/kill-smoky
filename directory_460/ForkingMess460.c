 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 *  linux/kernel/fork.c * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 *  Copyright (C) 1991, 1992  Linus Torvalds * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 *  'fork.c' contains the help-routines for the 'fork' system call * MX2 has one interrupt *for all* gpio ports. The list is used
 * (see also entry.S and others). * MX2 has one interrupt *for all* gpio ports. The list is used
 * Fork is rather simple, once you get the hang of it, but the memory * MX2 has one interrupt *for all* gpio ports. The list is used
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()' * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/slab.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/init.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/unistd.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/module.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/vmalloc.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/completion.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/personality.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/mempolicy.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/sem.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/file.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/fdtable.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/iocontext.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/key.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/binfmts.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/mman.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/mmu_notifier.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/fs.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/nsproxy.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/capability.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/cpu.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/cgroup.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/security.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/hugetlb.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/seccomp.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/swap.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/syscalls.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/jiffies.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/futex.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/compat.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/kthread.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/task_io_accounting_ops.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/rcupdate.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/ptrace.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/mount.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/audit.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/memcontrol.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/ftrace.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/proc_fs.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/profile.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/rmap.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/ksm.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/acct.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/tsacct_kern.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/cn_proc.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/freezer.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/delayacct.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/taskstats_kern.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/random.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/tty.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/blkdev.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/fs_struct.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/magic.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/perf_event.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/posix-timers.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/user-return-notifier.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/oom.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/khugepaged.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/signalfd.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/uprobes.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/aio.h> * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/pgtable.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/pgalloc.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/uaccess.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/mmu_context.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/cacheflush.h> * MX2 has one interrupt *for all* gpio ports. The list is used
#include <asm/tlbflush.h> * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#include <trace/events/sched.h> * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#define CREATE_TRACE_POINTS * MX2 has one interrupt *for all* gpio ports. The list is used
#include <trace/events/task.h> * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Protected counters by write_lock_irq(&tasklist_lock) * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
unsigned long total_forks;	/* Handle normal Linux uptimes. */ * MX2 has one interrupt *for all* gpio ports. The list is used
int nr_threads;			/* The idle threads do not count.. */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
int max_threads;		/* tunable limit on nr_threads */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
DEFINE_PER_CPU(unsigned long, process_counts) = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_PROVE_RCU * MX2 has one interrupt *for all* gpio ports. The list is used
int lockdep_tasklist_lock_is_held(void) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return lockdep_is_held(&tasklist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL_GPL(lockdep_tasklist_lock_is_held); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif /* #ifdef CONFIG_PROVE_RCU */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
int nr_processes(void) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	int cpu; * MX2 has one interrupt *for all* gpio ports. The list is used
	int total = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	for_each_possible_cpu(cpu) * MX2 has one interrupt *for all* gpio ports. The list is used
		total += per_cpu(process_counts, cpu); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return total; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __weak arch_release_task_struct(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR * MX2 has one interrupt *for all* gpio ports. The list is used
static struct kmem_cache *task_struct_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline struct task_struct *alloc_task_struct_node(int node) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void free_task_struct(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	kmem_cache_free(task_struct_cachep, tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __weak arch_release_thread_info(struct thread_info *ti) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef CONFIG_ARCH_THREAD_INFO_ALLOCATOR * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a * MX2 has one interrupt *for all* gpio ports. The list is used
 * kmemcache based allocator. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
# if THREAD_SIZE >= PAGE_SIZE * MX2 has one interrupt *for all* gpio ports. The list is used
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk, * MX2 has one interrupt *for all* gpio ports. The list is used
						  int node) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct page *page = alloc_pages_node(node, THREADINFO_GFP_ACCOUNTED, * MX2 has one interrupt *for all* gpio ports. The list is used
					     THREAD_SIZE_ORDER); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return page ? page_address(page) : NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void free_thread_info(struct thread_info *ti) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	free_memcg_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
# else * MX2 has one interrupt *for all* gpio ports. The list is used
static struct kmem_cache *thread_info_cache; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk, * MX2 has one interrupt *for all* gpio ports. The list is used
						  int node) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return kmem_cache_alloc_node(thread_info_cache, THREADINFO_GFP, node); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void free_thread_info(struct thread_info *ti) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	kmem_cache_free(thread_info_cache, ti); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void thread_info_cache_init(void) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	thread_info_cache = kmem_cache_create("thread_info", THREAD_SIZE, * MX2 has one interrupt *for all* gpio ports. The list is used
					      THREAD_SIZE, 0, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
	BUG_ON(thread_info_cache == NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
# endif * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for signal_struct structures (tsk->signal) */ * MX2 has one interrupt *for all* gpio ports. The list is used
static struct kmem_cache *signal_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for sighand_struct structures (tsk->sighand) */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct kmem_cache *sighand_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for files_struct structures (tsk->files) */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct kmem_cache *files_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for fs_struct structures (tsk->fs) */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct kmem_cache *fs_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for vm_area_struct structures */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct kmem_cache *vm_area_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* SLAB cache for mm_struct structures (tsk->mm) */ * MX2 has one interrupt *for all* gpio ports. The list is used
static struct kmem_cache *mm_cachep; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void account_kernel_stack(struct thread_info *ti, int account) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct zone *zone = page_zone(virt_to_page(ti)); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mod_zone_page_state(zone, NR_KERNEL_STACK, account); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void free_task(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	account_kernel_stack(tsk->stack, -1); * MX2 has one interrupt *for all* gpio ports. The list is used
	arch_release_thread_info(tsk->stack); * MX2 has one interrupt *for all* gpio ports. The list is used
	free_thread_info(tsk->stack); * MX2 has one interrupt *for all* gpio ports. The list is used
	rt_mutex_debug_task_free(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	ftrace_graph_exit_task(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	put_seccomp_filter(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	arch_release_task_struct(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	free_task_struct(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL(free_task); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void free_signal_struct(struct signal_struct *sig) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	taskstats_tgid_free(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
	sched_autogroup_exit(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
	kmem_cache_free(signal_cachep, sig); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void put_signal_struct(struct signal_struct *sig) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (atomic_dec_and_test(&sig->sigcnt)) * MX2 has one interrupt *for all* gpio ports. The list is used
		free_signal_struct(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __put_task_struct(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	WARN_ON(!tsk->exit_state); * MX2 has one interrupt *for all* gpio ports. The list is used
	WARN_ON(atomic_read(&tsk->usage)); * MX2 has one interrupt *for all* gpio ports. The list is used
	WARN_ON(tsk == current); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	task_numa_free(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	security_task_free(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_creds(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	delayacct_tsk_free(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	put_signal_struct(tsk->signal); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!profile_handoff_task(tsk)) * MX2 has one interrupt *for all* gpio ports. The list is used
		free_task(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL_GPL(__put_task_struct); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __init __weak arch_task_cache_init(void) { } * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __init fork_init(unsigned long mempages) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef ARCH_MIN_TASKALIGN * MX2 has one interrupt *for all* gpio ports. The list is used
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	/* create a slab on which task_structs can be allocated */ * MX2 has one interrupt *for all* gpio ports. The list is used
	task_struct_cachep = * MX2 has one interrupt *for all* gpio ports. The list is used
		kmem_cache_create("task_struct", sizeof(struct task_struct), * MX2 has one interrupt *for all* gpio ports. The list is used
			ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* do the arch specific task caches init */ * MX2 has one interrupt *for all* gpio ports. The list is used
	arch_task_cache_init(); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * The default maximum number of threads is set to a safe * MX2 has one interrupt *for all* gpio ports. The list is used
	 * value: the thread structures can take up at most half * MX2 has one interrupt *for all* gpio ports. The list is used
	 * of memory. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * we need to allow at least 20 threads to boot a system * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (max_threads < 20) * MX2 has one interrupt *for all* gpio ports. The list is used
		max_threads = 20; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2; * MX2 has one interrupt *for all* gpio ports. The list is used
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2; * MX2 has one interrupt *for all* gpio ports. The list is used
	init_task.signal->rlim[RLIMIT_SIGPENDING] = * MX2 has one interrupt *for all* gpio ports. The list is used
		init_task.signal->rlim[RLIMIT_NPROC]; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
int __attribute__((weak)) arch_dup_task_struct(struct task_struct *dst, * MX2 has one interrupt *for all* gpio ports. The list is used
					       struct task_struct *src) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	*dst = *src; * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static struct task_struct *dup_task_struct(struct task_struct *orig) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct task_struct *tsk; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct thread_info *ti; * MX2 has one interrupt *for all* gpio ports. The list is used
	unsigned long *stackend; * MX2 has one interrupt *for all* gpio ports. The list is used
	int node = tsk_fork_get_node(orig); * MX2 has one interrupt *for all* gpio ports. The list is used
	int err; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk = alloc_task_struct_node(node); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
		return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	ti = alloc_thread_info_node(tsk, node); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!ti) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto free_tsk; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	err = arch_dup_task_struct(tsk, orig); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto free_ti; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->stack = ti; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	setup_thread_stack(tsk, orig); * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_user_return_notifier(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_tsk_need_resched(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	stackend = end_of_stack(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	*stackend = STACK_END_MAGIC;	/* for overflow detection */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_CC_STACKPROTECTOR * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->stack_canary = get_random_int(); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * One for us, one for whoever does the "release_task()" (usually * MX2 has one interrupt *for all* gpio ports. The list is used
	 * parent) * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&tsk->usage, 2); * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_BLK_DEV_IO_TRACE * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->btrace_seq = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->splice_pipe = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->task_frag.page = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	account_kernel_stack(ti, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return tsk; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
free_ti: * MX2 has one interrupt *for all* gpio ports. The list is used
	free_thread_info(ti); * MX2 has one interrupt *for all* gpio ports. The list is used
free_tsk: * MX2 has one interrupt *for all* gpio ports. The list is used
	free_task_struct(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_MMU * MX2 has one interrupt *for all* gpio ports. The list is used
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct rb_node **rb_link, *rb_parent; * MX2 has one interrupt *for all* gpio ports. The list is used
	int retval; * MX2 has one interrupt *for all* gpio ports. The list is used
	unsigned long charge; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	uprobe_start_dup_mmap(); * MX2 has one interrupt *for all* gpio ports. The list is used
	down_write(&oldmm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	flush_cache_dup_mm(oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
	uprobe_dup_mmap(oldmm, mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Not linked in yet - no deadlock potential: * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->locked_vm = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->mmap = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->mmap_cache = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->map_count = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	cpumask_clear(mm_cpumask(mm)); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->mm_rb = RB_ROOT; * MX2 has one interrupt *for all* gpio ports. The list is used
	rb_link = &mm->mm_rb.rb_node; * MX2 has one interrupt *for all* gpio ports. The list is used
	rb_parent = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	pprev = &mm->mmap; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = ksm_fork(mm, oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = khugepaged_fork(mm, oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	prev = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) { * MX2 has one interrupt *for all* gpio ports. The list is used
		struct file *file; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (mpnt->vm_flags & VM_DONTCOPY) { * MX2 has one interrupt *for all* gpio ports. The list is used
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file, * MX2 has one interrupt *for all* gpio ports. The list is used
							-vma_pages(mpnt)); * MX2 has one interrupt *for all* gpio ports. The list is used
			continue; * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		charge = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
		if (mpnt->vm_flags & VM_ACCOUNT) { * MX2 has one interrupt *for all* gpio ports. The list is used
			unsigned long len = vma_pages(mpnt); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */ * MX2 has one interrupt *for all* gpio ports. The list is used
				goto fail_nomem; * MX2 has one interrupt *for all* gpio ports. The list is used
			charge = len; * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (!tmp) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto fail_nomem; * MX2 has one interrupt *for all* gpio ports. The list is used
		*tmp = *mpnt; * MX2 has one interrupt *for all* gpio ports. The list is used
		INIT_LIST_HEAD(&tmp->anon_vma_chain); * MX2 has one interrupt *for all* gpio ports. The list is used
		retval = vma_dup_policy(mpnt, tmp); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto fail_nomem_policy; * MX2 has one interrupt *for all* gpio ports. The list is used
		tmp->vm_mm = mm; * MX2 has one interrupt *for all* gpio ports. The list is used
		if (anon_vma_fork(tmp, mpnt)) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto fail_nomem_anon_vma_fork; * MX2 has one interrupt *for all* gpio ports. The list is used
		tmp->vm_flags &= ~VM_LOCKED; * MX2 has one interrupt *for all* gpio ports. The list is used
		tmp->vm_next = tmp->vm_prev = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		file = tmp->vm_file; * MX2 has one interrupt *for all* gpio ports. The list is used
		if (file) { * MX2 has one interrupt *for all* gpio ports. The list is used
			struct inode *inode = file_inode(file); * MX2 has one interrupt *for all* gpio ports. The list is used
			struct address_space *mapping = file->f_mapping; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
			get_file(file); * MX2 has one interrupt *for all* gpio ports. The list is used
			if (tmp->vm_flags & VM_DENYWRITE) * MX2 has one interrupt *for all* gpio ports. The list is used
				atomic_dec(&inode->i_writecount); * MX2 has one interrupt *for all* gpio ports. The list is used
			mutex_lock(&mapping->i_mmap_mutex); * MX2 has one interrupt *for all* gpio ports. The list is used
			if (tmp->vm_flags & VM_SHARED) * MX2 has one interrupt *for all* gpio ports. The list is used
				mapping->i_mmap_writable++; * MX2 has one interrupt *for all* gpio ports. The list is used
			flush_dcache_mmap_lock(mapping); * MX2 has one interrupt *for all* gpio ports. The list is used
			/* insert tmp into the share list, just after mpnt */ * MX2 has one interrupt *for all* gpio ports. The list is used
			if (unlikely(tmp->vm_flags & VM_NONLINEAR)) * MX2 has one interrupt *for all* gpio ports. The list is used
				vma_nonlinear_insert(tmp, * MX2 has one interrupt *for all* gpio ports. The list is used
						&mapping->i_mmap_nonlinear); * MX2 has one interrupt *for all* gpio ports. The list is used
			else * MX2 has one interrupt *for all* gpio ports. The list is used
				vma_interval_tree_insert_after(tmp, mpnt, * MX2 has one interrupt *for all* gpio ports. The list is used
							&mapping->i_mmap); * MX2 has one interrupt *for all* gpio ports. The list is used
			flush_dcache_mmap_unlock(mapping); * MX2 has one interrupt *for all* gpio ports. The list is used
			mutex_unlock(&mapping->i_mmap_mutex); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		/* * MX2 has one interrupt *for all* gpio ports. The list is used
		 * Clear hugetlb-related page reserves for children. This only * MX2 has one interrupt *for all* gpio ports. The list is used
		 * affects MAP_PRIVATE mappings. Faults generated by the child * MX2 has one interrupt *for all* gpio ports. The list is used
		 * are not guaranteed to succeed, even if read-only * MX2 has one interrupt *for all* gpio ports. The list is used
		 */ * MX2 has one interrupt *for all* gpio ports. The list is used
		if (is_vm_hugetlb_page(tmp)) * MX2 has one interrupt *for all* gpio ports. The list is used
			reset_vma_resv_huge_pages(tmp); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		/* * MX2 has one interrupt *for all* gpio ports. The list is used
		 * Link in the new vma and copy the page table entries. * MX2 has one interrupt *for all* gpio ports. The list is used
		 */ * MX2 has one interrupt *for all* gpio ports. The list is used
		*pprev = tmp; * MX2 has one interrupt *for all* gpio ports. The list is used
		pprev = &tmp->vm_next; * MX2 has one interrupt *for all* gpio ports. The list is used
		tmp->vm_prev = prev; * MX2 has one interrupt *for all* gpio ports. The list is used
		prev = tmp; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		__vma_link_rb(mm, tmp, rb_link, rb_parent); * MX2 has one interrupt *for all* gpio ports. The list is used
		rb_link = &tmp->vm_rb.rb_right; * MX2 has one interrupt *for all* gpio ports. The list is used
		rb_parent = &tmp->vm_rb; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		mm->map_count++; * MX2 has one interrupt *for all* gpio ports. The list is used
		retval = copy_page_range(mm, oldmm, mpnt); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (tmp->vm_ops && tmp->vm_ops->open) * MX2 has one interrupt *for all* gpio ports. The list is used
			tmp->vm_ops->open(tmp); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	/* a new mm has just been created */ * MX2 has one interrupt *for all* gpio ports. The list is used
	arch_dup_mmap(oldmm, mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
out: * MX2 has one interrupt *for all* gpio ports. The list is used
	up_write(&mm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	flush_tlb_mm(oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
	up_write(&oldmm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	uprobe_end_dup_mmap(); * MX2 has one interrupt *for all* gpio ports. The list is used
	return retval; * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nomem_anon_vma_fork: * MX2 has one interrupt *for all* gpio ports. The list is used
	mpol_put(vma_policy(tmp)); * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nomem_policy: * MX2 has one interrupt *for all* gpio ports. The list is used
	kmem_cache_free(vm_area_cachep, tmp); * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nomem: * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	vm_unacct_memory(charge); * MX2 has one interrupt *for all* gpio ports. The list is used
	goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline int mm_alloc_pgd(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->pgd = pgd_alloc(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unlikely(!mm->pgd)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void mm_free_pgd(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	pgd_free(mm, mm->pgd); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#else * MX2 has one interrupt *for all* gpio ports. The list is used
#define dup_mmap(mm, oldmm)	(0) * MX2 has one interrupt *for all* gpio ports. The list is used
#define mm_alloc_pgd(mm)	(0) * MX2 has one interrupt *for all* gpio ports. The list is used
#define mm_free_pgd(mm) * MX2 has one interrupt *for all* gpio ports. The list is used
#endif /* CONFIG_MMU */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL)) * MX2 has one interrupt *for all* gpio ports. The list is used
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm))) * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int __init coredump_filter_setup(char *s) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	default_dump_filter = * MX2 has one interrupt *for all* gpio ports. The list is used
		(simple_strtoul(s, NULL, 0) << MMF_DUMP_FILTER_SHIFT) & * MX2 has one interrupt *for all* gpio ports. The list is used
		MMF_DUMP_FILTER_MASK; * MX2 has one interrupt *for all* gpio ports. The list is used
	return 1; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
__setup("coredump_filter=", coredump_filter_setup); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#include <linux/init_task.h> * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void mm_init_aio(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_AIO * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_lock_init(&mm->ioctx_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->ioctx_table = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&mm->mm_users, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&mm->mm_count, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
	init_rwsem(&mm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&mm->mmlist); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->flags = (current->mm) ? * MX2 has one interrupt *for all* gpio ports. The list is used
		(current->mm->flags & MMF_INIT_MASK) : default_dump_filter; * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->core_state = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_long_set(&mm->nr_ptes, 0); * MX2 has one interrupt *for all* gpio ports. The list is used
	memset(&mm->rss_stat, 0, sizeof(mm->rss_stat)); * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_lock_init(&mm->page_table_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_init_aio(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_init_owner(mm, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_tlb_flush_pending(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (likely(!mm_alloc_pgd(mm))) { * MX2 has one interrupt *for all* gpio ports. The list is used
		mm->def_flags = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
		mmu_notifier_mm_init(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		return mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	free_mm(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void check_mm(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	int i; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	for (i = 0; i < NR_MM_COUNTERS; i++) { * MX2 has one interrupt *for all* gpio ports. The list is used
		long x = atomic_long_read(&mm->rss_stat.count[i]); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (unlikely(x)) * MX2 has one interrupt *for all* gpio ports. The list is used
			printk(KERN_ALERT "BUG: Bad rss-counter state " * MX2 has one interrupt *for all* gpio ports. The list is used
					  "mm:%p idx:%d val:%ld\n", mm, i, x); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS * MX2 has one interrupt *for all* gpio ports. The list is used
	VM_BUG_ON(mm->pmd_huge_pte); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Allocate and initialize an mm_struct. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct mm_struct *mm_alloc(void) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct mm_struct *mm; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mm = allocate_mm(); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!mm) * MX2 has one interrupt *for all* gpio ports. The list is used
		return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	memset(mm, 0, sizeof(*mm)); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_init_cpumask(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	return mm_init(mm, current); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Called when the last reference to the mm * MX2 has one interrupt *for all* gpio ports. The list is used
 * is dropped: either by a lazy thread or by * MX2 has one interrupt *for all* gpio ports. The list is used
 * mmput. Free the page directory and the mm. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
void __mmdrop(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	BUG_ON(mm == &init_mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_free_pgd(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	destroy_context(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	mmu_notifier_mm_destroy(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	check_mm(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	free_mm(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL_GPL(__mmdrop); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Decrement the use count and release all resources for an mm. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
void mmput(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	might_sleep(); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (atomic_dec_and_test(&mm->mm_users)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		uprobe_clear_state(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		exit_aio(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		ksm_exit(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		khugepaged_exit(mm); /* must run before exit_mmap */ * MX2 has one interrupt *for all* gpio ports. The list is used
		exit_mmap(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		set_mm_exe_file(mm, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (!list_empty(&mm->mmlist)) { * MX2 has one interrupt *for all* gpio ports. The list is used
			spin_lock(&mmlist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
			list_del(&mm->mmlist); * MX2 has one interrupt *for all* gpio ports. The list is used
			spin_unlock(&mmlist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		if (mm->binfmt) * MX2 has one interrupt *for all* gpio ports. The list is used
			module_put(mm->binfmt->module); * MX2 has one interrupt *for all* gpio ports. The list is used
		mmdrop(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL_GPL(mmput); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (new_exe_file) * MX2 has one interrupt *for all* gpio ports. The list is used
		get_file(new_exe_file); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (mm->exe_file) * MX2 has one interrupt *for all* gpio ports. The list is used
		fput(mm->exe_file); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->exe_file = new_exe_file; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
struct file *get_mm_exe_file(struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct file *exe_file; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* We need mmap_sem to protect against races with removal of exe_file */ * MX2 has one interrupt *for all* gpio ports. The list is used
	down_read(&mm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	exe_file = mm->exe_file; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (exe_file) * MX2 has one interrupt *for all* gpio ports. The list is used
		get_file(exe_file); * MX2 has one interrupt *for all* gpio ports. The list is used
	up_read(&mm->mmap_sem); * MX2 has one interrupt *for all* gpio ports. The list is used
	return exe_file; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	/* It's safe to write the exe_file pointer without exe_file_lock because * MX2 has one interrupt *for all* gpio ports. The list is used
	 * this is called during fork when the task is not yet in /proc */ * MX2 has one interrupt *for all* gpio ports. The list is used
	newmm->exe_file = get_mm_exe_file(oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/** * MX2 has one interrupt *for all* gpio ports. The list is used
 * get_task_mm - acquire a reference to the task's mm * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 * Returns %NULL if the task has no mm.  Checks PF_KTHREAD (meaning * MX2 has one interrupt *for all* gpio ports. The list is used
 * this kernel workthread has transiently adopted a user mm with use_mm, * MX2 has one interrupt *for all* gpio ports. The list is used
 * to do its AIO) is not set and if so returns a reference to it, after * MX2 has one interrupt *for all* gpio ports. The list is used
 * bumping up the use count.  User must release the mm via mmput() * MX2 has one interrupt *for all* gpio ports. The list is used
 * after use.  Typically used by /proc and ptrace. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
struct mm_struct *get_task_mm(struct task_struct *task) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct mm_struct *mm; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	task_lock(task); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm = task->mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (mm) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (task->flags & PF_KTHREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
			mm = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		else * MX2 has one interrupt *for all* gpio ports. The list is used
			atomic_inc(&mm->mm_users); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	task_unlock(task); * MX2 has one interrupt *for all* gpio ports. The list is used
	return mm; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
EXPORT_SYMBOL_GPL(get_task_mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
struct mm_struct *mm_access(struct task_struct *task, unsigned int mode) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct mm_struct *mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	int err; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	err =  mutex_lock_killable(&task->signal->cred_guard_mutex); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(err); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mm = get_task_mm(task); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (mm && mm != current->mm && * MX2 has one interrupt *for all* gpio ports. The list is used
			!ptrace_may_access(task, mode)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		mmput(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
		mm = ERR_PTR(-EACCES); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	mutex_unlock(&task->signal->cred_guard_mutex); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return mm; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void complete_vfork_done(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct completion *vfork; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	task_lock(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	vfork = tsk->vfork_done; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (likely(vfork)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		tsk->vfork_done = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		complete(vfork); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	task_unlock(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int wait_for_vfork_done(struct task_struct *child, * MX2 has one interrupt *for all* gpio ports. The list is used
				struct completion *vfork) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	int killed; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	freezer_do_not_count(); * MX2 has one interrupt *for all* gpio ports. The list is used
	killed = wait_for_completion_killable(vfork); * MX2 has one interrupt *for all* gpio ports. The list is used
	freezer_count(); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (killed) { * MX2 has one interrupt *for all* gpio ports. The list is used
		task_lock(child); * MX2 has one interrupt *for all* gpio ports. The list is used
		child->vfork_done = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		task_unlock(child); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	put_task_struct(child); * MX2 has one interrupt *for all* gpio ports. The list is used
	return killed; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* Please note the differences between mmput and mm_release. * MX2 has one interrupt *for all* gpio ports. The list is used
 * mmput is called whenever we stop holding onto a mm_struct, * MX2 has one interrupt *for all* gpio ports. The list is used
 * error success whatever. * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 * mm_release is called after a mm_struct has been removed * MX2 has one interrupt *for all* gpio ports. The list is used
 * from the current process. * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 * This difference is important for error handling, when we * MX2 has one interrupt *for all* gpio ports. The list is used
 * only half set up a mm_struct for a new process and need to restore * MX2 has one interrupt *for all* gpio ports. The list is used
 * the old one.  Because we mmput the new mm_struct before * MX2 has one interrupt *for all* gpio ports. The list is used
 * restoring the old one. . . * MX2 has one interrupt *for all* gpio ports. The list is used
 * Eric Biederman 10 January 1998 * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
void mm_release(struct task_struct *tsk, struct mm_struct *mm) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	/* Get rid of any futexes when releasing the mm */ * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_FUTEX * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unlikely(tsk->robust_list)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		exit_robust_list(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
		tsk->robust_list = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_COMPAT * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unlikely(tsk->compat_robust_list)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		compat_exit_robust_list(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
		tsk->compat_robust_list = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unlikely(!list_empty(&tsk->pi_state_list))) * MX2 has one interrupt *for all* gpio ports. The list is used
		exit_pi_state_list(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	uprobe_free_utask(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* Get rid of any cached register state */ * MX2 has one interrupt *for all* gpio ports. The list is used
	deactivate_mm(tsk, mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If we're exiting normally, clear a user-space tid field if * MX2 has one interrupt *for all* gpio ports. The list is used
	 * requested.  We leave this alone when dying by signal, to leave * MX2 has one interrupt *for all* gpio ports. The list is used
	 * the value intact in a core dump, and to save the unnecessary * MX2 has one interrupt *for all* gpio ports. The list is used
	 * trouble, say, a killed vfork parent shouldn't touch this mm. * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Userland only wants this done for a sys_exit. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (tsk->clear_child_tid) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (!(tsk->flags & PF_SIGNALED) && * MX2 has one interrupt *for all* gpio ports. The list is used
		    atomic_read(&mm->mm_users) > 1) { * MX2 has one interrupt *for all* gpio ports. The list is used
			/* * MX2 has one interrupt *for all* gpio ports. The list is used
			 * We don't check the error code - if userspace has * MX2 has one interrupt *for all* gpio ports. The list is used
			 * not set up a proper pointer then tough luck. * MX2 has one interrupt *for all* gpio ports. The list is used
			 */ * MX2 has one interrupt *for all* gpio ports. The list is used
			put_user(0, tsk->clear_child_tid); * MX2 has one interrupt *for all* gpio ports. The list is used
			sys_futex(tsk->clear_child_tid, FUTEX_WAKE, * MX2 has one interrupt *for all* gpio ports. The list is used
					1, NULL, NULL, 0); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		tsk->clear_child_tid = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * All done, finally we can wake up parent and return this mm to him. * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Also kthread_stop() uses this completion for synchronization. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (tsk->vfork_done) * MX2 has one interrupt *for all* gpio ports. The list is used
		complete_vfork_done(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Allocate a new mm structure and copy contents from the * MX2 has one interrupt *for all* gpio ports. The list is used
 * mm structure of the passed in task structure. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static struct mm_struct *dup_mm(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct mm_struct *mm, *oldmm = current->mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	int err; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mm = allocate_mm(); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!mm) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fail_nomem; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	memcpy(mm, oldmm, sizeof(*mm)); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_init_cpumask(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->pmd_huge_pte = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!mm_init(mm, tsk)) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fail_nomem; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (init_new_context(tsk, mm)) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fail_nocontext; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	dup_mm_exe_file(oldmm, mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	err = dup_mmap(mm, oldmm); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto free_pt; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->hiwater_rss = get_mm_rss(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->hiwater_vm = mm->total_vm; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (mm->binfmt && !try_module_get(mm->binfmt->module)) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto free_pt; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return mm; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
free_pt: * MX2 has one interrupt *for all* gpio ports. The list is used
	/* don't put binfmt in mmput, we haven't got module yet */ * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->binfmt = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	mmput(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nomem: * MX2 has one interrupt *for all* gpio ports. The list is used
	return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nocontext: * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If init_new_context() failed, we cannot use mmput() to free the mm * MX2 has one interrupt *for all* gpio ports. The list is used
	 * because it calls destroy_context() * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_free_pgd(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	free_mm(mm); * MX2 has one interrupt *for all* gpio ports. The list is used
	return NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct mm_struct *mm, *oldmm; * MX2 has one interrupt *for all* gpio ports. The list is used
	int retval; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->min_flt = tsk->maj_flt = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->nvcsw = tsk->nivcsw = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_DETECT_HUNG_TASK * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->mm = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->active_mm = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Are we cloning a kernel thread? * MX2 has one interrupt *for all* gpio ports. The list is used
	 * * MX2 has one interrupt *for all* gpio ports. The list is used
	 * We need to steal a active VM for that.. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	oldmm = current->mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!oldmm) * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_VM) { * MX2 has one interrupt *for all* gpio ports. The list is used
		atomic_inc(&oldmm->mm_users); * MX2 has one interrupt *for all* gpio ports. The list is used
		mm = oldmm; * MX2 has one interrupt *for all* gpio ports. The list is used
		goto good_mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	mm = dup_mm(tsk); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!mm) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fail_nomem; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
good_mm: * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->mm = mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->active_mm = mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
fail_nomem: * MX2 has one interrupt *for all* gpio ports. The list is used
	return retval; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct fs_struct *fs = current->fs; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_FS) { * MX2 has one interrupt *for all* gpio ports. The list is used
		/* tsk->fs is already what we want */ * MX2 has one interrupt *for all* gpio ports. The list is used
		spin_lock(&fs->lock); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (fs->in_exec) { * MX2 has one interrupt *for all* gpio ports. The list is used
			spin_unlock(&fs->lock); * MX2 has one interrupt *for all* gpio ports. The list is used
			return -EAGAIN; * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		fs->users++; * MX2 has one interrupt *for all* gpio ports. The list is used
		spin_unlock(&fs->lock); * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->fs = copy_fs_struct(fs); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!tsk->fs) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_files(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct files_struct *oldf, *newf; * MX2 has one interrupt *for all* gpio ports. The list is used
	int error = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * A background process may not have any files ... * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	oldf = current->files; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!oldf) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_FILES) { * MX2 has one interrupt *for all* gpio ports. The list is used
		atomic_inc(&oldf->count); * MX2 has one interrupt *for all* gpio ports. The list is used
		goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	newf = dup_fd(oldf, &error); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!newf) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto out; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->files = newf; * MX2 has one interrupt *for all* gpio ports. The list is used
	error = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
out: * MX2 has one interrupt *for all* gpio ports. The list is used
	return error; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_io(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_BLOCK * MX2 has one interrupt *for all* gpio ports. The list is used
	struct io_context *ioc = current->io_context; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct io_context *new_ioc; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!ioc) * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Share io context with parent, if CLONE_IO is set * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_IO) { * MX2 has one interrupt *for all* gpio ports. The list is used
		ioc_task_link(ioc); * MX2 has one interrupt *for all* gpio ports. The list is used
		tsk->io_context = ioc; * MX2 has one interrupt *for all* gpio ports. The list is used
	} else if (ioprio_valid(ioc->ioprio)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (unlikely(!new_ioc)) * MX2 has one interrupt *for all* gpio ports. The list is used
			return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		new_ioc->ioprio = ioc->ioprio; * MX2 has one interrupt *for all* gpio ports. The list is used
		put_io_context(new_ioc); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct sighand_struct *sig; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_SIGHAND) { * MX2 has one interrupt *for all* gpio ports. The list is used
		atomic_inc(&current->sighand->count); * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL); * MX2 has one interrupt *for all* gpio ports. The list is used
	rcu_assign_pointer(tsk->sighand, sig); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!sig) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&sig->count, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
	memcpy(sig->action, current->sighand->action, sizeof(sig->action)); * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __cleanup_sighand(struct sighand_struct *sighand) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (atomic_dec_and_test(&sighand->count)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		signalfd_cleanup(sighand); * MX2 has one interrupt *for all* gpio ports. The list is used
		kmem_cache_free(sighand_cachep, sighand); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Initialize POSIX timer handling for a thread group. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static void posix_cpu_timers_init_group(struct signal_struct *sig) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	unsigned long cpu_limit; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* Thread group counters. */ * MX2 has one interrupt *for all* gpio ports. The list is used
	thread_group_cputime_init(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	cpu_limit = ACCESS_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (cpu_limit != RLIM_INFINITY) { * MX2 has one interrupt *for all* gpio ports. The list is used
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit); * MX2 has one interrupt *for all* gpio ports. The list is used
		sig->cputimer.running = 1; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* The timer lists. */ * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&sig->cpu_timers[0]); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&sig->cpu_timers[1]); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&sig->cpu_timers[2]); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct signal_struct *sig; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_THREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL); * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->signal = sig; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!sig) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->nr_threads = 1; * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&sig->live, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_set(&sig->sigcnt, 1); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */ * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node); * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	init_waitqueue_head(&sig->wait_chldexit); * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->curr_target = tsk; * MX2 has one interrupt *for all* gpio ports. The list is used
	init_sigpending(&sig->shared_pending); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&sig->posix_timers); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL); * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->real_timer.function = it_real_fn; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	task_lock(current->group_leader); * MX2 has one interrupt *for all* gpio ports. The list is used
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim); * MX2 has one interrupt *for all* gpio ports. The list is used
	task_unlock(current->group_leader); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	posix_cpu_timers_init_group(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	tty_audit_fork(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
	sched_autogroup_fork(sig); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_CGROUPS * MX2 has one interrupt *for all* gpio ports. The list is used
	init_rwsem(&sig->group_rwsem); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->oom_score_adj = current->signal->oom_score_adj; * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->oom_score_adj_min = current->signal->oom_score_adj_min; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	sig->has_child_subreaper = current->signal->has_child_subreaper || * MX2 has one interrupt *for all* gpio ports. The list is used
				   current->signal->is_child_subreaper; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	mutex_init(&sig->cred_guard_mutex); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void copy_flags(unsigned long clone_flags, struct task_struct *p) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	unsigned long new_flags = p->flags; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	new_flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER); * MX2 has one interrupt *for all* gpio ports. The list is used
	new_flags |= PF_FORKNOEXEC; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->flags = new_flags; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	current->clear_child_tid = tidptr; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return task_pid_vnr(current); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void rt_mutex_init_task(struct task_struct *p) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	raw_spin_lock_init(&p->pi_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_RT_MUTEXES * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pi_waiters = RB_ROOT; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pi_waiters_leftmost = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pi_blocked_on = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pi_top_task = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_MM_OWNER * MX2 has one interrupt *for all* gpio ports. The list is used
void mm_init_owner(struct mm_struct *mm, struct task_struct *p) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	mm->owner = p; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif /* CONFIG_MM_OWNER */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Initialize POSIX timer handling for a single task. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static void posix_cpu_timers_init(struct task_struct *tsk) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->cputime_expires.prof_exp = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->cputime_expires.virt_exp = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	tsk->cputime_expires.sched_exp = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&tsk->cpu_timers[0]); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&tsk->cpu_timers[1]); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&tsk->cpu_timers[2]); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void * MX2 has one interrupt *for all* gpio ports. The list is used
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	 task->pids[type].pid = pid; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * This creates a new process as a copy of the old one, * MX2 has one interrupt *for all* gpio ports. The list is used
 * but does not actually start it yet. * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 * It copies the registers, and all the appropriate * MX2 has one interrupt *for all* gpio ports. The list is used
 * parts of the process environment (as per the clone * MX2 has one interrupt *for all* gpio ports. The list is used
 * flags). The actual kick-off is left to the caller. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static struct task_struct *copy_process(unsigned long clone_flags, * MX2 has one interrupt *for all* gpio ports. The list is used
					unsigned long stack_start, * MX2 has one interrupt *for all* gpio ports. The list is used
					unsigned long stack_size, * MX2 has one interrupt *for all* gpio ports. The list is used
					int __user *child_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
					struct pid *pid, * MX2 has one interrupt *for all* gpio ports. The list is used
					int trace) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	int retval; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct task_struct *p; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Thread groups must share signals as well, and detached threads * MX2 has one interrupt *for all* gpio ports. The list is used
	 * can only be started up within the thread group. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Shared signal handlers imply shared VM. By way of the above, * MX2 has one interrupt *for all* gpio ports. The list is used
	 * thread groups also imply shared VM. Blocking this case allows * MX2 has one interrupt *for all* gpio ports. The list is used
	 * for various simplifications in other code. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Siblings of global init remain as zombies on exit since they are * MX2 has one interrupt *for all* gpio ports. The list is used
	 * not reaped by their parent (swapper). To solve this and to avoid * MX2 has one interrupt *for all* gpio ports. The list is used
	 * multi-rooted process trees, prevent global and container-inits * MX2 has one interrupt *for all* gpio ports. The list is used
	 * from creating siblings. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & CLONE_PARENT) && * MX2 has one interrupt *for all* gpio ports. The list is used
				current->signal->flags & SIGNAL_UNKILLABLE) * MX2 has one interrupt *for all* gpio ports. The list is used
		return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If the new process will be in a different pid or user namespace * MX2 has one interrupt *for all* gpio ports. The list is used
	 * do not allow it to share a thread group or signal handlers or * MX2 has one interrupt *for all* gpio ports. The list is used
	 * parent with the forking task. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_SIGHAND) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) || * MX2 has one interrupt *for all* gpio ports. The list is used
		    (task_active_pid_ns(current) != * MX2 has one interrupt *for all* gpio ports. The list is used
				current->nsproxy->pid_ns_for_children)) * MX2 has one interrupt *for all* gpio ports. The list is used
			return ERR_PTR(-EINVAL); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = security_task_create(clone_flags); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fork_out; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
	p = dup_task_struct(current); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!p) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto fork_out; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	ftrace_graph_init_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	get_seccomp_filter(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	rt_mutex_init_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_PROVE_LOCKING * MX2 has one interrupt *for all* gpio ports. The list is used
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled); * MX2 has one interrupt *for all* gpio ports. The list is used
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = -EAGAIN; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (atomic_read(&p->real_cred->user->processes) >= * MX2 has one interrupt *for all* gpio ports. The list is used
			task_rlimit(p, RLIMIT_NPROC)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (p->real_cred->user != INIT_USER && * MX2 has one interrupt *for all* gpio ports. The list is used
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN)) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto bad_fork_free; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	current->flags &= ~PF_NPROC_EXCEEDED; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_creds(p, clone_flags); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval < 0) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_free; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If multiple threads are within copy_process(), then this check * MX2 has one interrupt *for all* gpio ports. The list is used
	 * triggers too late. This doesn't hurt, the check is only there * MX2 has one interrupt *for all* gpio ports. The list is used
	 * to stop root fork bombs. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = -EAGAIN; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (nr_threads >= max_threads) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_count; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!try_module_get(task_thread_info(p)->exec_domain->module)) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_count; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */ * MX2 has one interrupt *for all* gpio ports. The list is used
	copy_flags(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&p->children); * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&p->sibling); * MX2 has one interrupt *for all* gpio ports. The list is used
	rcu_copy_process(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->vfork_done = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_lock_init(&p->alloc_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	init_sigpending(&p->pending); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p->utime = p->stime = p->gtime = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->utimescaled = p->stimescaled = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE * MX2 has one interrupt *for all* gpio ports. The list is used
	p->prev_cputime.utime = p->prev_cputime.stime = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN * MX2 has one interrupt *for all* gpio ports. The list is used
	seqlock_init(&p->vtime_seqlock); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->vtime_snap = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->vtime_snap_whence = VTIME_SLEEPING; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#if defined(SPLIT_RSS_COUNTING) * MX2 has one interrupt *for all* gpio ports. The list is used
	memset(&p->rss_stat, 0, sizeof(p->rss_stat)); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p->default_timer_slack_ns = current->timer_slack_ns; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	task_io_accounting_init(&p->ioac); * MX2 has one interrupt *for all* gpio ports. The list is used
	acct_clear_integrals(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	posix_cpu_timers_init(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	do_posix_clock_monotonic_gettime(&p->start_time); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->real_start_time = p->start_time; * MX2 has one interrupt *for all* gpio ports. The list is used
	monotonic_to_bootbased(&p->real_start_time); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->io_context = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->audit_context = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_THREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
		threadgroup_change_begin(current); * MX2 has one interrupt *for all* gpio ports. The list is used
	cgroup_fork(p); * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_NUMA * MX2 has one interrupt *for all* gpio ports. The list is used
	p->mempolicy = mpol_dup(p->mempolicy); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (IS_ERR(p->mempolicy)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		retval = PTR_ERR(p->mempolicy); * MX2 has one interrupt *for all* gpio ports. The list is used
		p->mempolicy = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_cgroup; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	mpol_fix_fork_child_flag(p); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_CPUSETS * MX2 has one interrupt *for all* gpio ports. The list is used
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE; * MX2 has one interrupt *for all* gpio ports. The list is used
	seqcount_init(&p->mems_allowed_seq); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_TRACE_IRQFLAGS * MX2 has one interrupt *for all* gpio ports. The list is used
	p->irq_events = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirqs_enabled = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirq_enable_ip = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirq_enable_event = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirq_disable_ip = _THIS_IP_; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirq_disable_event = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirqs_enabled = 1; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirq_enable_ip = _THIS_IP_; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirq_enable_event = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirq_disable_ip = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirq_disable_event = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->hardirq_context = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->softirq_context = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_LOCKDEP * MX2 has one interrupt *for all* gpio ports. The list is used
	p->lockdep_depth = 0; /* no locks held yet */ * MX2 has one interrupt *for all* gpio ports. The list is used
	p->curr_chain_key = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->lockdep_recursion = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_DEBUG_MUTEXES * MX2 has one interrupt *for all* gpio ports. The list is used
	p->blocked_on = NULL; /* not blocked yet */ * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_MEMCG * MX2 has one interrupt *for all* gpio ports. The list is used
	p->memcg_batch.do_batch = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->memcg_batch.memcg = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_BCACHE * MX2 has one interrupt *for all* gpio ports. The list is used
	p->sequential_io	= 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->sequential_io_avg	= 0; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* Perform scheduler related setup. Assign this task to a CPU. */ * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = sched_fork(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_policy; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = perf_event_init_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_policy; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = audit_alloc(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_policy; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* copy all the process information */ * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_semundo(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_audit; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_files(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_semundo; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_fs(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_files; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_sighand(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_fs; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_signal(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_sighand; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_mm(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_signal; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_namespaces(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_mm; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_io(clone_flags, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_namespaces; * MX2 has one interrupt *for all* gpio ports. The list is used
	retval = copy_thread(clone_flags, stack_start, stack_size, p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (retval) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_cleanup_io; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (pid != &init_struct_pid) { * MX2 has one interrupt *for all* gpio ports. The list is used
		retval = -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
		pid = alloc_pid(p->nsproxy->pid_ns_for_children); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (!pid) * MX2 has one interrupt *for all* gpio ports. The list is used
			goto bad_fork_cleanup_io; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Clear TID on mm_release()? * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_BLOCK * MX2 has one interrupt *for all* gpio ports. The list is used
	p->plug = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_FUTEX * MX2 has one interrupt *for all* gpio ports. The list is used
	p->robust_list = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_COMPAT * MX2 has one interrupt *for all* gpio ports. The list is used
	p->compat_robust_list = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&p->pi_state_list); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pi_state_cache = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * sigaltstack should be cleared when sharing the same VM * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM) * MX2 has one interrupt *for all* gpio ports. The list is used
		p->sas_ss_sp = p->sas_ss_size = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Syscall tracing and stepping should be turned off in the * MX2 has one interrupt *for all* gpio ports. The list is used
	 * child regardless of CLONE_PTRACE. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	user_disable_single_step(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE); * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef TIF_SYSCALL_EMU * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU); * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	clear_all_latency_tracing(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* ok, now we should be set up.. */ * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pid = pid_nr(pid); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_THREAD) { * MX2 has one interrupt *for all* gpio ports. The list is used
		p->exit_signal = -1; * MX2 has one interrupt *for all* gpio ports. The list is used
		p->group_leader = current->group_leader; * MX2 has one interrupt *for all* gpio ports. The list is used
		p->tgid = current->tgid; * MX2 has one interrupt *for all* gpio ports. The list is used
	} else { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (clone_flags & CLONE_PARENT) * MX2 has one interrupt *for all* gpio ports. The list is used
			p->exit_signal = current->group_leader->exit_signal; * MX2 has one interrupt *for all* gpio ports. The list is used
		else * MX2 has one interrupt *for all* gpio ports. The list is used
			p->exit_signal = (clone_flags & CSIGNAL); * MX2 has one interrupt *for all* gpio ports. The list is used
		p->group_leader = p; * MX2 has one interrupt *for all* gpio ports. The list is used
		p->tgid = p->pid; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p->nr_dirtied = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->dirty_paused_when = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p->pdeath_signal = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	INIT_LIST_HEAD(&p->thread_group); * MX2 has one interrupt *for all* gpio ports. The list is used
	p->task_works = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Make it visible to the rest of the system, but dont wake it up yet. * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Need tasklist lock for parent etc handling! * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	write_lock_irq(&tasklist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* CLONE_PARENT re-uses the old parent */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		p->real_parent = current->real_parent; * MX2 has one interrupt *for all* gpio ports. The list is used
		p->parent_exec_id = current->parent_exec_id; * MX2 has one interrupt *for all* gpio ports. The list is used
	} else { * MX2 has one interrupt *for all* gpio ports. The list is used
		p->real_parent = current; * MX2 has one interrupt *for all* gpio ports. The list is used
		p->parent_exec_id = current->self_exec_id; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_lock(&current->sighand->siglock); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Process group and session signals need to be delivered to just the * MX2 has one interrupt *for all* gpio ports. The list is used
	 * parent before the fork or both the parent and the child after the * MX2 has one interrupt *for all* gpio ports. The list is used
	 * fork. Restart if a signal comes in before we add the new process to * MX2 has one interrupt *for all* gpio ports. The list is used
	 * it's process group. * MX2 has one interrupt *for all* gpio ports. The list is used
	 * A fatal signal pending means that current will exit, so the new * MX2 has one interrupt *for all* gpio ports. The list is used
	 * thread can't slip out of an OOM kill (or normal SIGKILL). * MX2 has one interrupt *for all* gpio ports. The list is used
	*/ * MX2 has one interrupt *for all* gpio ports. The list is used
	recalc_sigpending(); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (signal_pending(current)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		spin_unlock(&current->sighand->siglock); * MX2 has one interrupt *for all* gpio ports. The list is used
		write_unlock_irq(&tasklist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
		retval = -ERESTARTNOINTR; * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_fork_free_pid; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (likely(p->pid)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		init_task_pid(p, PIDTYPE_PID, pid); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (thread_group_leader(p)) { * MX2 has one interrupt *for all* gpio ports. The list is used
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current)); * MX2 has one interrupt *for all* gpio ports. The list is used
			init_task_pid(p, PIDTYPE_SID, task_session(current)); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
			if (is_child_reaper(pid)) { * MX2 has one interrupt *for all* gpio ports. The list is used
				ns_of_pid(pid)->child_reaper = p; * MX2 has one interrupt *for all* gpio ports. The list is used
				p->signal->flags |= SIGNAL_UNKILLABLE; * MX2 has one interrupt *for all* gpio ports. The list is used
			} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
			p->signal->leader_pid = pid; * MX2 has one interrupt *for all* gpio ports. The list is used
			p->signal->tty = tty_kref_get(current->signal->tty); * MX2 has one interrupt *for all* gpio ports. The list is used
			list_add_tail(&p->sibling, &p->real_parent->children); * MX2 has one interrupt *for all* gpio ports. The list is used
			list_add_tail_rcu(&p->tasks, &init_task.tasks); * MX2 has one interrupt *for all* gpio ports. The list is used
			attach_pid(p, PIDTYPE_PGID); * MX2 has one interrupt *for all* gpio ports. The list is used
			attach_pid(p, PIDTYPE_SID); * MX2 has one interrupt *for all* gpio ports. The list is used
			__this_cpu_inc(process_counts); * MX2 has one interrupt *for all* gpio ports. The list is used
		} else { * MX2 has one interrupt *for all* gpio ports. The list is used
			current->signal->nr_threads++; * MX2 has one interrupt *for all* gpio ports. The list is used
			atomic_inc(&current->signal->live); * MX2 has one interrupt *for all* gpio ports. The list is used
			atomic_inc(&current->signal->sigcnt); * MX2 has one interrupt *for all* gpio ports. The list is used
			list_add_tail_rcu(&p->thread_group, * MX2 has one interrupt *for all* gpio ports. The list is used
					  &p->group_leader->thread_group); * MX2 has one interrupt *for all* gpio ports. The list is used
			list_add_tail_rcu(&p->thread_node, * MX2 has one interrupt *for all* gpio ports. The list is used
					  &p->signal->thread_head); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
		attach_pid(p, PIDTYPE_PID); * MX2 has one interrupt *for all* gpio ports. The list is used
		nr_threads++; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	total_forks++; * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_unlock(&current->sighand->siglock); * MX2 has one interrupt *for all* gpio ports. The list is used
	write_unlock_irq(&tasklist_lock); * MX2 has one interrupt *for all* gpio ports. The list is used
	proc_fork_connector(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	cgroup_post_fork(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_THREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
		threadgroup_change_end(current); * MX2 has one interrupt *for all* gpio ports. The list is used
	perf_event_fork(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	trace_task_newtask(p, clone_flags); * MX2 has one interrupt *for all* gpio ports. The list is used
	uprobe_copy_process(p, clone_flags); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return p; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_free_pid: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (pid != &init_struct_pid) * MX2 has one interrupt *for all* gpio ports. The list is used
		free_pid(pid); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_io: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (p->io_context) * MX2 has one interrupt *for all* gpio ports. The list is used
		exit_io_context(p); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_namespaces: * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_task_namespaces(p); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_mm: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (p->mm) * MX2 has one interrupt *for all* gpio ports. The list is used
		mmput(p->mm); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_signal: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!(clone_flags & CLONE_THREAD)) * MX2 has one interrupt *for all* gpio ports. The list is used
		free_signal_struct(p->signal); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_sighand: * MX2 has one interrupt *for all* gpio ports. The list is used
	__cleanup_sighand(p->sighand); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_fs: * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_fs(p); /* blocking */ * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_files: * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_files(p); /* blocking */ * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_semundo: * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_sem(p); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_audit: * MX2 has one interrupt *for all* gpio ports. The list is used
	audit_free(p); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_policy: * MX2 has one interrupt *for all* gpio ports. The list is used
	perf_event_free_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_NUMA * MX2 has one interrupt *for all* gpio ports. The list is used
	mpol_put(p->mempolicy); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_cgroup: * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
	if (clone_flags & CLONE_THREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
		threadgroup_change_end(current); * MX2 has one interrupt *for all* gpio ports. The list is used
	cgroup_exit(p, 0); * MX2 has one interrupt *for all* gpio ports. The list is used
	delayacct_tsk_free(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	module_put(task_thread_info(p)->exec_domain->module); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_cleanup_count: * MX2 has one interrupt *for all* gpio ports. The list is used
	atomic_dec(&p->cred->user->processes); * MX2 has one interrupt *for all* gpio ports. The list is used
	exit_creds(p); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_fork_free: * MX2 has one interrupt *for all* gpio ports. The list is used
	free_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
fork_out: * MX2 has one interrupt *for all* gpio ports. The list is used
	return ERR_PTR(retval); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static inline void init_idle_pids(struct pid_link *links) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	enum pid_type type; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) { * MX2 has one interrupt *for all* gpio ports. The list is used
		INIT_HLIST_NODE(&links[type].node); /* not really needed */ * MX2 has one interrupt *for all* gpio ports. The list is used
		links[type].pid = &init_struct_pid; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
struct task_struct *fork_idle(int cpu) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct task_struct *task; * MX2 has one interrupt *for all* gpio ports. The list is used
	task = copy_process(CLONE_VM, 0, 0, NULL, &init_struct_pid, 0); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!IS_ERR(task)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		init_idle_pids(task->pids); * MX2 has one interrupt *for all* gpio ports. The list is used
		init_idle(task, cpu); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return task; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 *  Ok, this is the main fork-routine. * MX2 has one interrupt *for all* gpio ports. The list is used
 * * MX2 has one interrupt *for all* gpio ports. The list is used
 * It copies the process, and if successful kick-starts * MX2 has one interrupt *for all* gpio ports. The list is used
 * it and waits for it to finish using the VM if required. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
long do_fork(unsigned long clone_flags, * MX2 has one interrupt *for all* gpio ports. The list is used
	      unsigned long stack_start, * MX2 has one interrupt *for all* gpio ports. The list is used
	      unsigned long stack_size, * MX2 has one interrupt *for all* gpio ports. The list is used
	      int __user *parent_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
	      int __user *child_tidptr) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct task_struct *p; * MX2 has one interrupt *for all* gpio ports. The list is used
	int trace = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	long nr; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Determine whether and which event to report to ptracer.  When * MX2 has one interrupt *for all* gpio ports. The list is used
	 * called from kernel_thread or CLONE_UNTRACED is explicitly * MX2 has one interrupt *for all* gpio ports. The list is used
	 * requested, no event is reported; otherwise, report if the event * MX2 has one interrupt *for all* gpio ports. The list is used
	 * for the type of forking is enabled. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!(clone_flags & CLONE_UNTRACED)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (clone_flags & CLONE_VFORK) * MX2 has one interrupt *for all* gpio ports. The list is used
			trace = PTRACE_EVENT_VFORK; * MX2 has one interrupt *for all* gpio ports. The list is used
		else if ((clone_flags & CSIGNAL) != SIGCHLD) * MX2 has one interrupt *for all* gpio ports. The list is used
			trace = PTRACE_EVENT_CLONE; * MX2 has one interrupt *for all* gpio ports. The list is used
		else * MX2 has one interrupt *for all* gpio ports. The list is used
			trace = PTRACE_EVENT_FORK; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (likely(!ptrace_event_enabled(current, trace))) * MX2 has one interrupt *for all* gpio ports. The list is used
			trace = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	p = copy_process(clone_flags, stack_start, stack_size, * MX2 has one interrupt *for all* gpio ports. The list is used
			 child_tidptr, NULL, trace); * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Do this prior waking up the new thread - the thread pointer * MX2 has one interrupt *for all* gpio ports. The list is used
	 * might get invalid after that point, if the thread exits quickly. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!IS_ERR(p)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		struct completion vfork; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		trace_sched_process_fork(current, p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		nr = task_pid_vnr(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (clone_flags & CLONE_PARENT_SETTID) * MX2 has one interrupt *for all* gpio ports. The list is used
			put_user(nr, parent_tidptr); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (clone_flags & CLONE_VFORK) { * MX2 has one interrupt *for all* gpio ports. The list is used
			p->vfork_done = &vfork; * MX2 has one interrupt *for all* gpio ports. The list is used
			init_completion(&vfork); * MX2 has one interrupt *for all* gpio ports. The list is used
			get_task_struct(p); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		wake_up_new_task(p); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		/* forking complete and child started to run, tell ptracer */ * MX2 has one interrupt *for all* gpio ports. The list is used
		if (unlikely(trace)) * MX2 has one interrupt *for all* gpio ports. The list is used
			ptrace_event(trace, nr); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (clone_flags & CLONE_VFORK) { * MX2 has one interrupt *for all* gpio ports. The list is used
			if (!wait_for_vfork_done(p, &vfork)) * MX2 has one interrupt *for all* gpio ports. The list is used
				ptrace_event(PTRACE_EVENT_VFORK_DONE, nr); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
	} else { * MX2 has one interrupt *for all* gpio ports. The list is used
		nr = PTR_ERR(p); * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	return nr; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Create a kernel thread. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn, * MX2 has one interrupt *for all* gpio ports. The list is used
		(unsigned long)arg, NULL, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef __ARCH_WANT_SYS_FORK * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE0(fork) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_MMU * MX2 has one interrupt *for all* gpio ports. The list is used
	return do_fork(SIGCHLD, 0, 0, NULL, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
#else * MX2 has one interrupt *for all* gpio ports. The list is used
	/* can not support in nommu mode */ * MX2 has one interrupt *for all* gpio ports. The list is used
	return -EINVAL; * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef __ARCH_WANT_SYS_VFORK * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE0(vfork) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, * MX2 has one interrupt *for all* gpio ports. The list is used
			0, NULL, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef __ARCH_WANT_SYS_CLONE * MX2 has one interrupt *for all* gpio ports. The list is used
#ifdef CONFIG_CLONE_BACKWARDS * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, parent_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int, tls_val, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, child_tidptr) * MX2 has one interrupt *for all* gpio ports. The list is used
#elif defined(CONFIG_CLONE_BACKWARDS2) * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, parent_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, child_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int, tls_val) * MX2 has one interrupt *for all* gpio ports. The list is used
#elif defined(CONFIG_CLONE_BACKWARDS3) * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp, * MX2 has one interrupt *for all* gpio ports. The list is used
		int, stack_size, * MX2 has one interrupt *for all* gpio ports. The list is used
		int __user *, parent_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		int __user *, child_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		int, tls_val) * MX2 has one interrupt *for all* gpio ports. The list is used
#else * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, parent_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int __user *, child_tidptr, * MX2 has one interrupt *for all* gpio ports. The list is used
		 int, tls_val) * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
#ifndef ARCH_MIN_MMSTRUCT_ALIGN * MX2 has one interrupt *for all* gpio ports. The list is used
#define ARCH_MIN_MMSTRUCT_ALIGN 0 * MX2 has one interrupt *for all* gpio ports. The list is used
#endif * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
static void sighand_ctor(void *data) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct sighand_struct *sighand = data; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	spin_lock_init(&sighand->siglock); * MX2 has one interrupt *for all* gpio ports. The list is used
	init_waitqueue_head(&sighand->signalfd_wqh); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
void __init proc_caches_init(void) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	sighand_cachep = kmem_cache_create("sighand_cache", * MX2 has one interrupt *for all* gpio ports. The list is used
			sizeof(struct sighand_struct), 0, * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU| * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_NOTRACK, sighand_ctor); * MX2 has one interrupt *for all* gpio ports. The list is used
	signal_cachep = kmem_cache_create("signal_cache", * MX2 has one interrupt *for all* gpio ports. The list is used
			sizeof(struct signal_struct), 0, * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
	files_cachep = kmem_cache_create("files_cache", * MX2 has one interrupt *for all* gpio ports. The list is used
			sizeof(struct files_struct), 0, * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
	fs_cachep = kmem_cache_create("fs_cache", * MX2 has one interrupt *for all* gpio ports. The list is used
			sizeof(struct fs_struct), 0, * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * FIXME! The "sizeof(struct mm_struct)" currently includes the * MX2 has one interrupt *for all* gpio ports. The list is used
	 * whole struct cpumask for the OFFSTACK case. We could change * MX2 has one interrupt *for all* gpio ports. The list is used
	 * this to *only* allocate as much of it as required by the * MX2 has one interrupt *for all* gpio ports. The list is used
	 * maximum number of CPU's we can ever have.  The cpumask_allocation * MX2 has one interrupt *for all* gpio ports. The list is used
	 * is at the end of the structure, exactly for that reason. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	mm_cachep = kmem_cache_create("mm_struct", * MX2 has one interrupt *for all* gpio ports. The list is used
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN, * MX2 has one interrupt *for all* gpio ports. The list is used
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL); * MX2 has one interrupt *for all* gpio ports. The list is used
	vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC); * MX2 has one interrupt *for all* gpio ports. The list is used
	mmap_init(); * MX2 has one interrupt *for all* gpio ports. The list is used
	nsproxy_cache_init(); * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Check constraints on flags passed to the unshare system call. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static int check_unshare_flags(unsigned long unshare_flags) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND| * MX2 has one interrupt *for all* gpio ports. The list is used
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM| * MX2 has one interrupt *for all* gpio ports. The list is used
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET| * MX2 has one interrupt *for all* gpio ports. The list is used
				CLONE_NEWUSER|CLONE_NEWPID)) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -EINVAL; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * Not implemented, but pretend it works if there is nothing to * MX2 has one interrupt *for all* gpio ports. The list is used
	 * unshare. Note that unsharing CLONE_THREAD or CLONE_SIGHAND * MX2 has one interrupt *for all* gpio ports. The list is used
	 * needs to unshare vm. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		/* FIXME: get_task_mm() increments ->mm_users */ * MX2 has one interrupt *for all* gpio ports. The list is used
		if (atomic_read(&current->mm->mm_users) > 1) * MX2 has one interrupt *for all* gpio ports. The list is used
			return -EINVAL; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Unshare the filesystem structure if it is being shared * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct fs_struct *fs = current->fs; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!(unshare_flags & CLONE_FS) || !fs) * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* don't need lock here; in the worst case we'll do useless copy */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (fs->users == 1) * MX2 has one interrupt *for all* gpio ports. The list is used
		return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	*new_fsp = copy_fs_struct(fs); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (!*new_fsp) * MX2 has one interrupt *for all* gpio ports. The list is used
		return -ENOMEM; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * Unshare file descriptor table if it is being shared * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct files_struct *fd = current->files; * MX2 has one interrupt *for all* gpio ports. The list is used
	int error = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if ((unshare_flags & CLONE_FILES) && * MX2 has one interrupt *for all* gpio ports. The list is used
	    (fd && atomic_read(&fd->count) > 1)) { * MX2 has one interrupt *for all* gpio ports. The list is used
		*new_fdp = dup_fd(fd, &error); * MX2 has one interrupt *for all* gpio ports. The list is used
		if (!*new_fdp) * MX2 has one interrupt *for all* gpio ports. The list is used
			return error; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 * unshare allows a process to 'unshare' part of the process * MX2 has one interrupt *for all* gpio ports. The list is used
 * context which was originally shared using clone.  copy_* * MX2 has one interrupt *for all* gpio ports. The list is used
 * functions used by do_fork() cannot be used here directly * MX2 has one interrupt *for all* gpio ports. The list is used
 * because they modify an inactive task_struct that is being * MX2 has one interrupt *for all* gpio ports. The list is used
 * constructed. Here we are modifying the current, active, * MX2 has one interrupt *for all* gpio ports. The list is used
 * task_struct. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct fs_struct *fs, *new_fs = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct files_struct *fd, *new_fd = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct cred *new_cred = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct nsproxy *new_nsproxy = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	int do_sysvsem = 0; * MX2 has one interrupt *for all* gpio ports. The list is used
	int err; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If unsharing a user namespace must also unshare the thread. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & CLONE_NEWUSER) * MX2 has one interrupt *for all* gpio ports. The list is used
		unshare_flags |= CLONE_THREAD | CLONE_FS; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If unsharing a thread from a thread group, must also unshare vm. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & CLONE_THREAD) * MX2 has one interrupt *for all* gpio ports. The list is used
		unshare_flags |= CLONE_VM; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If unsharing vm, must also unshare signal handlers. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & CLONE_VM) * MX2 has one interrupt *for all* gpio ports. The list is used
		unshare_flags |= CLONE_SIGHAND; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * If unsharing namespace, must also unshare filesystem information. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & CLONE_NEWNS) * MX2 has one interrupt *for all* gpio ports. The list is used
		unshare_flags |= CLONE_FS; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	err = check_unshare_flags(unshare_flags); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_unshare_out; * MX2 has one interrupt *for all* gpio ports. The list is used
	/* * MX2 has one interrupt *for all* gpio ports. The list is used
	 * CLONE_NEWIPC must also detach from the undolist: after switching * MX2 has one interrupt *for all* gpio ports. The list is used
	 * to a new ipc namespace, the semaphore arrays from the old * MX2 has one interrupt *for all* gpio ports. The list is used
	 * namespace are unreachable. * MX2 has one interrupt *for all* gpio ports. The list is used
	 */ * MX2 has one interrupt *for all* gpio ports. The list is used
	if (unshare_flags & (CLONE_NEWIPC|CLONE_SYSVSEM)) * MX2 has one interrupt *for all* gpio ports. The list is used
		do_sysvsem = 1; * MX2 has one interrupt *for all* gpio ports. The list is used
	err = unshare_fs(unshare_flags, &new_fs); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_unshare_out; * MX2 has one interrupt *for all* gpio ports. The list is used
	err = unshare_fd(unshare_flags, &new_fd); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_unshare_cleanup_fs; * MX2 has one interrupt *for all* gpio ports. The list is used
	err = unshare_userns(unshare_flags, &new_cred); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_unshare_cleanup_fd; * MX2 has one interrupt *for all* gpio ports. The list is used
	err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy, * MX2 has one interrupt *for all* gpio ports. The list is used
					 new_cred, new_fs); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (err) * MX2 has one interrupt *for all* gpio ports. The list is used
		goto bad_unshare_cleanup_cred; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	if (new_fs || new_fd || do_sysvsem || new_cred || new_nsproxy) { * MX2 has one interrupt *for all* gpio ports. The list is used
		if (do_sysvsem) { * MX2 has one interrupt *for all* gpio ports. The list is used
			/* * MX2 has one interrupt *for all* gpio ports. The list is used
			 * CLONE_SYSVSEM is equivalent to sys_exit(). * MX2 has one interrupt *for all* gpio ports. The list is used
			 */ * MX2 has one interrupt *for all* gpio ports. The list is used
			exit_sem(current); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (new_nsproxy) * MX2 has one interrupt *for all* gpio ports. The list is used
			switch_task_namespaces(current, new_nsproxy); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		task_lock(current); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (new_fs) { * MX2 has one interrupt *for all* gpio ports. The list is used
			fs = current->fs; * MX2 has one interrupt *for all* gpio ports. The list is used
			spin_lock(&fs->lock); * MX2 has one interrupt *for all* gpio ports. The list is used
			current->fs = new_fs; * MX2 has one interrupt *for all* gpio ports. The list is used
			if (--fs->users) * MX2 has one interrupt *for all* gpio ports. The list is used
				new_fs = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
			else * MX2 has one interrupt *for all* gpio ports. The list is used
				new_fs = fs; * MX2 has one interrupt *for all* gpio ports. The list is used
			spin_unlock(&fs->lock); * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (new_fd) { * MX2 has one interrupt *for all* gpio ports. The list is used
			fd = current->files; * MX2 has one interrupt *for all* gpio ports. The list is used
			current->files = new_fd; * MX2 has one interrupt *for all* gpio ports. The list is used
			new_fd = fd; * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		task_unlock(current); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
		if (new_cred) { * MX2 has one interrupt *for all* gpio ports. The list is used
			/* Install the new user namespace */ * MX2 has one interrupt *for all* gpio ports. The list is used
			commit_creds(new_cred); * MX2 has one interrupt *for all* gpio ports. The list is used
			new_cred = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		} * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
bad_unshare_cleanup_cred: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (new_cred) * MX2 has one interrupt *for all* gpio ports. The list is used
		put_cred(new_cred); * MX2 has one interrupt *for all* gpio ports. The list is used
bad_unshare_cleanup_fd: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (new_fd) * MX2 has one interrupt *for all* gpio ports. The list is used
		put_files_struct(new_fd); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
bad_unshare_cleanup_fs: * MX2 has one interrupt *for all* gpio ports. The list is used
	if (new_fs) * MX2 has one interrupt *for all* gpio ports. The list is used
		free_fs_struct(new_fs); * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
bad_unshare_out: * MX2 has one interrupt *for all* gpio ports. The list is used
	return err; * MX2 has one interrupt *for all* gpio ports. The list is used
} * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
/* * MX2 has one interrupt *for all* gpio ports. The list is used
 *	Helper to unshare the files of the current task. * MX2 has one interrupt *for all* gpio ports. The list is used
 *	We don't want to expose copy_files internals to * MX2 has one interrupt *for all* gpio ports. The list is used
 *	the exec layer of the kernel. * MX2 has one interrupt *for all* gpio ports. The list is used
 */ * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
int unshare_files(struct files_struct **displaced) * MX2 has one interrupt *for all* gpio ports. The list is used
{ * MX2 has one interrupt *for all* gpio ports. The list is used
	struct task_struct *task = current; * MX2 has one interrupt *for all* gpio ports. The list is used
	struct files_struct *copy = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
	int error; * MX2 has one interrupt *for all* gpio ports. The list is used
 * MX2 has one interrupt *for all* gpio ports. The list is used
	error = unshare_fd(CLONE_FILES, &copy); * MX2 has one interrupt *for all* gpio ports. The list is used
	if (error || !copy) { * MX2 has one interrupt *for all* gpio ports. The list is used
		*displaced = NULL; * MX2 has one interrupt *for all* gpio ports. The list is used
		return error; * MX2 has one interrupt *for all* gpio ports. The list is used
	} * MX2 has one interrupt *for all* gpio ports. The list is used
	*displaced = task->files; * MX2 has one interrupt *for all* gpio ports. The list is used
	task_lock(task); * MX2 has one interrupt *for all* gpio ports. The list is used
	task->files = copy; * MX2 has one interrupt *for all* gpio ports. The list is used
	task_unlock(task); * MX2 has one interrupt *for all* gpio ports. The list is used
	return 0; * MX2 has one interrupt *for all* gpio ports. The list is used
}