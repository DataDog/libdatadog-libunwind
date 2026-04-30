// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod libunwind_x86_64;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod libunwind_aarch64;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use libunwind_aarch64::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use libunwind_x86_64::*;

#[cfg(all(test, target_os = "linux"))]
mod remote_tests {
    use super::*;

    /// Fork a child that stops itself with `PTRACE_TRACEME` + `SIGSTOP`.
    /// The parent waits, unwinds the child's stack, then kills it.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_remote_unwind_child() {
        unsafe {
            let child_pid = libc::fork();
            assert!(child_pid >= 0, "fork failed");

            if child_pid == 0 {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
                libc::raise(libc::SIGSTOP);
                libc::_exit(libc::EXIT_SUCCESS);
            }

            let mut status: libc::c_int = 0;
            libc::waitpid(child_pid, &mut status, libc::WUNTRACED);
            assert!(libc::WIFSTOPPED(status), "child did not stop");

            let addr_space =
                unw_create_addr_space(std::ptr::addr_of!(_UPT_accessors) as *mut UnwAccessors, 0);
            let upt_info = _UPT_create(child_pid);
            let mut cursor: UnwCursor = std::mem::zeroed();
            let ret = unw_init_remote(&mut cursor, addr_space, upt_info);
            assert_eq!(ret, 0, "unw_init_remote failed");

            let mut frames = 0usize;
            while frames <= 256 {
                if unw_step_remote(&mut cursor) <= 0 {
                    break;
                }
                frames += 1;

                let mut ip: UnwWord = 0;
                unw_get_reg_remote(&mut cursor, UNW_REG_IP, &mut ip);
                let mut name: [libc::c_char; 256] = [0; 256];
                let mut offset: UnwWord = 0;
                let sym =
                    if unw_get_proc_name_remote(&mut cursor, name.as_mut_ptr(), 256, &mut offset)
                        == 0
                    {
                        std::ffi::CStr::from_ptr(name.as_ptr())
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        "<unknown>".to_owned()
                    };
                println!("  frame {frames:3}: ip=0x{ip:016x}  {sym}+0x{offset:x}");
            }
            assert!(frames > 0, "expected at least one remote frame");

            _UPT_destroy(upt_info);
            unw_destroy_addr_space(addr_space);
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }
    }

    /// We specifically test that the child process can unwind the parent's stack
    /// because that is the use case in crashtracker
    ///
    ///   1. Parent records its own pid and opens a pipe
    ///   2. Parent forks; now it knows the child pid
    ///   3. Parent calls `prctl(PR_SET_PTRACER, child_pid)` so the kernel
    ///      allows the child to attach (required when ptrace_scope >= 1)
    ///   4. Parent writes one byte to the pipe then blocks in `waitpid`
    ///   5. Child reads the byte, calls `PTRACE_ATTACH` on the parent, waits
    ///      for the parent to stop, unwinds its stack, asserts frames captured,
    ///      detaches, and exits
    ///   6. Parent's `waitpid` returns; asserts child exited cleanly
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_remote_child_ptrace_unwind() {
        unsafe {
            // Use the current thread's TID, not the process TGID. In the
            // parallel test harness the test runs in a worker thread whose
            // TID != getpid(); attaching to the TGID would be on the
            // harness coordinator thread instead.
            let parent_tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;

            let mut pipe_fds: [libc::c_int; 2] = [0; 2];
            assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
            let [pipe_r, pipe_w] = pipe_fds;

            let child_pid = libc::fork();
            assert!(child_pid >= 0, "fork failed");

            if child_pid == 0 {
                libc::close(pipe_w);

                // Wait until the parent has called prctl.
                let mut byte = 0u8;
                libc::read(pipe_r, &mut byte as *mut u8 as *mut libc::c_void, 1);
                libc::close(pipe_r);

                // Attach to the parent thread and wait for it to stop.
                // __WALL is required when the tracee is a thread (TID != TGID).
                let ret = libc::ptrace(
                    libc::PTRACE_ATTACH,
                    parent_tid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
                if ret != 0 {
                    libc::_exit(1);
                }
                let mut status: libc::c_int = 0;
                libc::waitpid(parent_tid, &mut status, libc::__WALL);
                if !libc::WIFSTOPPED(status) {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        parent_tid,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    );
                    libc::_exit(1);
                }

                // Walk the parent thread's stack.
                let addr_space = unw_create_addr_space(
                    std::ptr::addr_of!(_UPT_accessors) as *mut UnwAccessors,
                    0,
                );
                let upt_info = _UPT_create(parent_tid);
                let mut cursor: UnwCursor = std::mem::zeroed();
                let ret = unw_init_remote(&mut cursor, addr_space, upt_info);

                let mut frames = 0usize;
                if ret == 0 {
                    while frames <= 256 {
                        if unw_step_remote(&mut cursor) <= 0 {
                            break;
                        }
                        frames += 1;

                        let mut ip: UnwWord = 0;
                        unw_get_reg_remote(&mut cursor, UNW_REG_IP, &mut ip);
                        let mut name: [libc::c_char; 256] = [0; 256];
                        let mut offset: UnwWord = 0;
                        let sym = if unw_get_proc_name_remote(
                            &mut cursor,
                            name.as_mut_ptr(),
                            256,
                            &mut offset,
                        ) == 0
                        {
                            std::ffi::CStr::from_ptr(name.as_ptr())
                                .to_string_lossy()
                                .into_owned()
                        } else {
                            "<unknown>".to_owned()
                        };
                        // eprintln so it's visible from the forked child
                        eprintln!("  frame {frames:3}: ip=0x{ip:016x}  {sym}+0x{offset:x}");
                    }
                }
                assert!(frames > 0, "Expected at least one remote frame");

                _UPT_destroy(upt_info);
                unw_destroy_addr_space(addr_space);
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    parent_tid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
                libc::_exit(if frames > 0 { 0 } else { 1 });
            }

            // Parent grants ptrace permission to child, then signals it
            libc::close(pipe_r);
            libc::prctl(libc::PR_SET_PTRACER, child_pid as libc::c_ulong, 0, 0, 0);
            libc::write(pipe_w, b"g".as_ptr() as *const libc::c_void, 1);
            libc::close(pipe_w);

            // the child will stop us, unwind our stack, then detach
            let mut status: libc::c_int = 0;
            libc::waitpid(child_pid, &mut status, 0);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child failed: status={status}"
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // Miri cannot execute FFI calls to libunwind
    fn test_basic_unwind() {
        unsafe {
            let mut context: UnwContext = std::mem::zeroed();

            let ret = unw_getcontext(&mut context);
            assert_eq!(ret, 0, "unw_getcontext failed");

            // Initialize cursor
            let mut cursor: UnwCursor = std::mem::zeroed();
            let ret = unw_init_local2(&mut cursor, &mut context, 0);
            assert_eq!(ret, 0, "unw_init_local2 failed");

            // Walk the stack
            let mut frames = 0;
            loop {
                let ret = unw_step(&mut cursor);
                if ret <= 0 {
                    break;
                }
                frames += 1;

                // Limit iterations to prevent infinite loops
                if frames > 100 {
                    break;
                }
            }

            // Should have at least a few frames
            assert!(frames > 0, "Expected at least one stack frame");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Miri cannot execute FFI calls to libunwind
    fn test_get_register() {
        unsafe {
            let mut context: UnwContext = std::mem::zeroed();
            assert_eq!(unw_getcontext(&mut context), 0);

            let mut cursor: UnwCursor = std::mem::zeroed();
            assert_eq!(unw_init_local2(&mut cursor, &mut context, 0), 0);

            // Get instruction pointer
            let mut ip: UnwWord = 0;
            let ret = unw_get_reg(&mut cursor, UNW_REG_IP, &mut ip);
            assert_eq!(ret, 0, "Failed to get IP register");
            assert_ne!(ip, 0, "IP should not be zero");

            // Get stack pointer
            let mut sp: UnwWord = 0;
            let ret = unw_get_reg(&mut cursor, UNW_REG_SP, &mut sp);
            assert_eq!(ret, 0, "Failed to get SP register");
            assert_ne!(sp, 0, "SP should not be zero");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Miri cannot execute FFI calls to libunwind
    fn test_backtrace2() {
        unsafe {
            let mut context: UnwContext = std::mem::zeroed();
            assert_eq!(unw_getcontext(&mut context), 0);
            let mut cursor: UnwCursor = std::mem::zeroed();
            assert_eq!(unw_init_local2(&mut cursor, &mut context, 0), 0);

            // unw_backtrace2 expects an array of void pointers
            let mut frames: [*mut ::std::os::raw::c_void; 100] = [std::ptr::null_mut(); 100];
            let ret = unw_backtrace2(frames.as_mut_ptr(), 100, &mut context, 0);

            // Return value should be >= 0 (number of frames captured)
            assert!(ret >= 0, "unw_backtrace2 failed with error: {}", ret);

            let frame_count = ret as usize;
            assert!(frame_count > 0, "Expected at least one frame");

            // Print captured frames
            for (i, &frame) in frames.iter().enumerate().take(frame_count) {
                let frame_ptr = frame as usize;
                println!("Frame {}: 0x{:016x}", i, frame_ptr);
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Miri cannot execute FFI calls to libunwind
    fn test_get_proc_name() {
        unsafe {
            let mut context: UnwContext = std::mem::zeroed();
            assert_eq!(unw_getcontext(&mut context), 0);
            let mut cursor: UnwCursor = std::mem::zeroed();
            assert_eq!(
                unw_init_local2(&mut cursor, &mut context, UNW_INIT_SIGNAL_FRAME),
                0
            );

            let mut name: [libc::c_char; 100] = [0; 100];
            let ret = unw_get_proc_name(&mut cursor, name.as_mut_ptr(), 100, std::ptr::null_mut());
            assert_eq!(ret, 0, "unw_get_proc_name failed");
            let fn_name = std::ffi::CStr::from_ptr(name.as_ptr()).to_string_lossy();
            assert!(!fn_name.is_empty(), "Name should not be empty");
            // name is managed: _ZN15libdd_libunwind5tests18test_get_proc_name17hec15ec5ad6978a00E
            // we should just chekc that test_get_proc_name is part of it
            assert!(
                fn_name.contains("test_get_proc_name"),
                "Name should contain 'test_get_proc_name'"
            );
        }
    }
}
