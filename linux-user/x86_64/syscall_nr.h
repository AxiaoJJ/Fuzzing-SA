#define TARGET_NR_read                                0
#define TARGET_NR_write                               1
#define TARGET_NR_open                                2
#define TARGET_NR_close                               3
#define TARGET_NR_stat                                4
#define TARGET_NR_fstat                               5
#define TARGET_NR_lstat                               6
#define TARGET_NR_poll                                7
#define TARGET_NR_lseek                               8
#define TARGET_NR_mmap                                9
#define TARGET_NR_mprotect                           10
#define TARGET_NR_munmap                             11
#define TARGET_NR_brk                                12
#define TARGET_NR_rt_sigaction                       13
#define TARGET_NR_rt_sigprocmask                     14
#define TARGET_NR_rt_sigreturn                       15
#define TARGET_NR_ioctl                              16
#define TARGET_NR_pread64                            17
#define TARGET_NR_pwrite64                           18
#define TARGET_NR_readv                              19
#define TARGET_NR_writev                             20
#define TARGET_NR_access                             21
#define TARGET_NR_pipe                               22
#define TARGET_NR_select                             23
#define TARGET_NR_sched_yield                        24
#define TARGET_NR_mremap                             25
#define TARGET_NR_msync                              26
#define TARGET_NR_mincore                            27
#define TARGET_NR_madvise                            28
#define TARGET_NR_shmget                             29
#define TARGET_NR_shmat                              30
#define TARGET_NR_shmctl                             31
#define TARGET_NR_dup                                32
#define TARGET_NR_dup2                               33
#define TARGET_NR_pause                              34
#define TARGET_NR_nanosleep                          35
#define TARGET_NR_getitimer                          36
#define TARGET_NR_alarm                              37
#define TARGET_NR_setitimer                          38
#define TARGET_NR_getpid                             39
#define TARGET_NR_sendfile                           40
#define TARGET_NR_socket                             41
#define TARGET_NR_connect                            42
#define TARGET_NR_accept                             43
#define TARGET_NR_sendto                             44
#define TARGET_NR_recvfrom                           45
#define TARGET_NR_sendmsg                            46
#define TARGET_NR_recvmsg                            47
#define TARGET_NR_shutdown                           48
#define TARGET_NR_bind                               49
#define TARGET_NR_listen                             50
#define TARGET_NR_getsockname                        51
#define TARGET_NR_getpeername                        52
#define TARGET_NR_socketpair                         53
#define TARGET_NR_setsockopt                         54
#define TARGET_NR_getsockopt                         55
#define TARGET_NR_clone                              56
#define TARGET_NR_fork                               57
#define TARGET_NR_vfork                              58
#define TARGET_NR_execve                             59
#define TARGET_NR_exit                               60
#define TARGET_NR_wait4                              61
#define TARGET_NR_kill                               62
#define TARGET_NR_uname                              63
#define TARGET_NR_semget                             64
#define TARGET_NR_semop                              65
#define TARGET_NR_semctl                             66
#define TARGET_NR_shmdt                              67
#define TARGET_NR_msgget                             68
#define TARGET_NR_msgsnd                             69
#define TARGET_NR_msgrcv                             70
#define TARGET_NR_msgctl                             71
#define TARGET_NR_fcntl                              72
#define TARGET_NR_flock                              73
#define TARGET_NR_fsync                              74
#define TARGET_NR_fdatasync                          75
#define TARGET_NR_truncate                           76
#define TARGET_NR_ftruncate                          77
#define TARGET_NR_getdents                           78
#define TARGET_NR_getcwd                             79
#define TARGET_NR_chdir                              80
#define TARGET_NR_fchdir                             81
#define TARGET_NR_rename                             82
#define TARGET_NR_mkdir                              83
#define TARGET_NR_rmdir                              84
#define TARGET_NR_creat                              85
#define TARGET_NR_link                               86
#define TARGET_NR_unlink                             87
#define TARGET_NR_symlink                            88
#define TARGET_NR_readlink                           89
#define TARGET_NR_chmod                              90
#define TARGET_NR_fchmod                             91
#define TARGET_NR_chown                              92
#define TARGET_NR_fchown                             93
#define TARGET_NR_lchown                             94
#define TARGET_NR_umask                              95
#define TARGET_NR_gettimeofday                       96
#define TARGET_NR_getrlimit                          97
#define TARGET_NR_getrusage                          98
#define TARGET_NR_sysinfo                            99
#define TARGET_NR_times                             100
#define TARGET_NR_ptrace                            101
#define TARGET_NR_getuid                            102
#define TARGET_NR_syslog                            103
#define TARGET_NR_getgid                            104
#define TARGET_NR_setuid                            105
#define TARGET_NR_setgid                            106
#define TARGET_NR_geteuid                           107
#define TARGET_NR_getegid                           108
#define TARGET_NR_setpgid                           109
#define TARGET_NR_getppid                           110
#define TARGET_NR_getpgrp                           111
#define TARGET_NR_setsid                            112
#define TARGET_NR_setreuid                          113
#define TARGET_NR_setregid                          114
#define TARGET_NR_getgroups                         115
#define TARGET_NR_setgroups                         116
#define TARGET_NR_setresuid                         117
#define TARGET_NR_getresuid                         118
#define TARGET_NR_setresgid                         119
#define TARGET_NR_getresgid                         120
#define TARGET_NR_getpgid                           121
#define TARGET_NR_setfsuid                          122
#define TARGET_NR_setfsgid                          123
#define TARGET_NR_getsid                            124
#define TARGET_NR_capget                            125
#define TARGET_NR_capset                            126
#define TARGET_NR_rt_sigpending                     127
#define TARGET_NR_rt_sigtimedwait                   128
#define TARGET_NR_rt_sigqueueinfo                   129
#define TARGET_NR_rt_sigsuspend                     130
#define TARGET_NR_sigaltstack                       131
#define TARGET_NR_utime                             132
#define TARGET_NR_mknod                             133
#define TARGET_NR_uselib                            134
#define TARGET_NR_personality                       135
#define TARGET_NR_ustat                             136
#define TARGET_NR_statfs                            137
#define TARGET_NR_fstatfs                           138
#define TARGET_NR_sysfs                             139
#define TARGET_NR_getpriority                       140
#define TARGET_NR_setpriority                       141
#define TARGET_NR_sched_setparam                    142
#define TARGET_NR_sched_getparam                    143
#define TARGET_NR_sched_setscheduler                144
#define TARGET_NR_sched_getscheduler                145
#define TARGET_NR_sched_get_priority_max            146
#define TARGET_NR_sched_get_priority_min            147
#define TARGET_NR_sched_rr_get_interval             148
#define TARGET_NR_mlock                             149
#define TARGET_NR_munlock                           150
#define TARGET_NR_mlockall                          151
#define TARGET_NR_munlockall                        152
#define TARGET_NR_vhangup                           153
#define TARGET_NR_modify_ldt                        154
#define TARGET_NR_pivot_root                        155
#define TARGET_NR__sysctl                           156
#define TARGET_NR_prctl                             157
#define TARGET_NR_arch_prctl                        158
#define TARGET_NR_adjtimex                          159
#define TARGET_NR_setrlimit                         160
#define TARGET_NR_chroot                            161
#define TARGET_NR_sync                              162
#define TARGET_NR_acct                              163
#define TARGET_NR_settimeofday                      164
#define TARGET_NR_mount                             165
#define TARGET_NR_umount2                           166
#define TARGET_NR_swapon                            167
#define TARGET_NR_swapoff                           168
#define TARGET_NR_reboot                            169
#define TARGET_NR_sethostname                       170
#define TARGET_NR_setdomainname                     171
#define TARGET_NR_iopl                              172
#define TARGET_NR_ioperm                            173
#define TARGET_NR_create_module                     174
#define TARGET_NR_init_module                       175
#define TARGET_NR_delete_module                     176
#define TARGET_NR_get_kernel_syms                   177
#define TARGET_NR_query_module                      178
#define TARGET_NR_quotactl                          179
#define TARGET_NR_nfsservctl                        180
#define TARGET_NR_getpmsg                           181	/* reserved for LiS/STREAMS */
#define TARGET_NR_putpmsg                           182	/* reserved for LiS/STREAMS */
#define TARGET_NR_afs_syscall                       183	/* reserved for AFS */
#define TARGET_NR_tuxcall      		184 /* reserved for tux */
#define TARGET_NR_security			185
#define TARGET_NR_gettid		186
#define TARGET_NR_readahead		187
#define TARGET_NR_setxattr		188
#define TARGET_NR_lsetxattr		189
#define TARGET_NR_fsetxattr		190
#define TARGET_NR_getxattr		191
#define TARGET_NR_lgetxattr		192
#define TARGET_NR_fgetxattr		193
#define TARGET_NR_listxattr		194
#define TARGET_NR_llistxattr		195
#define TARGET_NR_flistxattr		196
#define TARGET_NR_removexattr	197
#define TARGET_NR_lremovexattr	198
#define TARGET_NR_fremovexattr	199
#define TARGET_NR_tkill	200
#define TARGET_NR_time      201
#define TARGET_NR_futex     202
#define TARGET_NR_sched_setaffinity    203
#define TARGET_NR_sched_getaffinity     204
#define TARGET_NR_set_thread_area	205
#define TARGET_NR_io_setup	206
#define TARGET_NR_io_destroy	207
#define TARGET_NR_io_getevents	208
#define TARGET_NR_io_submit	209
#define TARGET_NR_io_cancel	210
#define TARGET_NR_get_thread_area	211
#define TARGET_NR_lookup_dcookie	212
#define TARGET_NR_epoll_create	213
#define TARGET_NR_epoll_ctl_old	214
#define TARGET_NR_epoll_wait_old	215
#define TARGET_NR_remap_file_pages	216
#define TARGET_NR_getdents64	217
#define TARGET_NR_set_tid_address	218
#define TARGET_NR_restart_syscall	219
#define TARGET_NR_semtimedop		220
#define TARGET_NR_fadvise64		221
#define TARGET_NR_timer_create		222
#define TARGET_NR_timer_settime		223
#define TARGET_NR_timer_gettime		224
#define TARGET_NR_timer_getoverrun		225
#define TARGET_NR_timer_delete	226
#define TARGET_NR_clock_settime	227
#define TARGET_NR_clock_gettime	228
#define TARGET_NR_clock_getres	229
#define TARGET_NR_clock_nanosleep	230
#define TARGET_NR_exit_group		231
#define TARGET_NR_epoll_wait		232
#define TARGET_NR_epoll_ctl		233
#define TARGET_NR_tgkill		234
#define TARGET_NR_utimes		235
#define TARGET_NR_vserver		236
#define TARGET_NR_mbind 		237
#define TARGET_NR_set_mempolicy 	238
#define TARGET_NR_get_mempolicy 	239
#define TARGET_NR_mq_open 		240
#define TARGET_NR_mq_unlink 		241
#define TARGET_NR_mq_timedsend 	242
#define TARGET_NR_mq_timedreceive	243
#define TARGET_NR_mq_notify 		244
#define TARGET_NR_mq_getsetattr 	245
#define TARGET_NR_kexec_load 	246
#define TARGET_NR_waitid		247
#define TARGET_NR_add_key		248
#define TARGET_NR_request_key	249
#define TARGET_NR_keyctl		250
#define TARGET_NR_ioprio_set		251
#define TARGET_NR_ioprio_get		252
#define TARGET_NR_inotify_init	253
#define TARGET_NR_inotify_add_watch	254
#define TARGET_NR_inotify_rm_watch	255
#define TARGET_NR_migrate_pages	256
#define TARGET_NR_openat		257
#define TARGET_NR_mkdirat		258
#define TARGET_NR_mknodat		259
#define TARGET_NR_fchownat		260
#define TARGET_NR_futimesat		261
#define TARGET_NR_newfstatat		262
#define TARGET_NR_unlinkat		263
#define TARGET_NR_renameat		264
#define TARGET_NR_linkat		265
#define TARGET_NR_symlinkat		266
#define TARGET_NR_readlinkat		267
#define TARGET_NR_fchmodat		268
#define TARGET_NR_faccessat		269
#define TARGET_NR_pselect6		270
#define TARGET_NR_ppoll		271
#define TARGET_NR_unshare		272
#define TARGET_NR_set_robust_list	273
#define TARGET_NR_get_robust_list	274
#define TARGET_NR_splice		275
#define TARGET_NR_tee		276
#define TARGET_NR_sync_file_range	277
#define TARGET_NR_vmsplice		278
#define TARGET_NR_move_pages		279
#define TARGET_NR_utimensat		280
#define TARGET_NR_epoll_pwait	281
#define TARGET_NR_signalfd		282
#define TARGET_NR_timerfd_create	283
#define TARGET_NR_eventfd		284
#define TARGET_NR_fallocate		285
#define TARGET_NR_timerfd_settime	286
#define TARGET_NR_timerfd_gettime	287
#define TARGET_NR_accept4		288
#define TARGET_NR_signalfd4		289
#define TARGET_NR_eventfd2		290
#define TARGET_NR_epoll_create1	291
#define TARGET_NR_dup3			292
#define TARGET_NR_pipe2		293
#define TARGET_NR_inotify_init1	294
#define TARGET_NR_preadv                295
#define TARGET_NR_pwritev               296
#define TARGET_NR_rt_tgsigqueueinfo     297
#define TARGET_NR_perf_event_open       298
#define TARGET_NR_recvmmsg              299
#define TARGET_NR_fanotify_init         300
#define TARGET_NR_fanotify_mark         301
#define TARGET_NR_prlimit64             302
#define TARGET_NR_name_to_handle_at     303
#define TARGET_NR_open_by_handle_at     304
#define TARGET_NR_clock_adjtime         305
#define TARGET_NR_syncfs                306
#define TARGET_NR_sendmmsg              307
#define TARGET_NR_setns                 308
#define TARGET_NR_getcpu                309
#define TARGET_NR_process_vm_readv      310
#define TARGET_NR_process_vm_writev     311
#define TARGET_NR_kcmp                  312
#define TARGET_NR_finit_module          313
#define TARGET_NR_sched_setattr         314
#define TARGET_NR_sched_getattr         315
#define TARGET_NR_renameat2             316
#define TARGET_NR_seccomp               317
#define TARGET_NR_getrandom             318
#define TARGET_NR_memfd_create          319
#define TARGET_NR_kexec_file_load       320
#define TARGET_NR_bpf                   321
#define TARGET_NR_execveat              322
#define TARGET_NR_userfaultfd           323
#define TARGET_NR_membarrier            324
#define TARGET_NR_mlock2                325
#define TARGET_NR_copy_file_range       326
