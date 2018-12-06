// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

var (
	// ShouldSkip lists system calls that we should skip when parsing
	// Some of these are unsupported or not worth executing
	ShouldSkip = map[string]bool{
		// While we have system call descriptions for execve it is not worth adding
		// the ones in traces. Every trace has an execve at the beginning which means
		// all the system calls afterwards will not execute
		"execve": true,
		// Unsafe to set the addr argument to some random argument. Needs more care
		"arch_prctl": true,
		// Don't produce multithreaded programs.
		"wait4": true,
		"wait":  true,
		"futex": true,
		// Cannot obtain coverage from the forks.
		"clone": true,
		// Can support these calls but need to identify the ones in the trace that are worth keeping
		"mmap":     true,
		"msync":    true,
		"mremap":   true,
		"mprotect": true,
		"madvise":  true,
		"munmap":   true,
		// Not interesting coverage
		"getcwd": true,
		"getcpu": true,
		// Cannot evaluate sigset
		"rt_sigprocmask":  true,
		"rt_sigtimedwait": true,
		"rt_sigreturn":    true,
		"rt_sigqueueinfo": true,
		"rt_sigsuspend":   true,
		// Require function pointers which are not recovered by strace
		"rt_sigaction": true,
	}
)
