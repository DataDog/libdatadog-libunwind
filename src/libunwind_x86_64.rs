// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Context is platform ucontext_t (from libc)
pub type UnwContext = libc::ucontext_t;

pub type UnwWord = u64;

// Opaque cursor structure
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UnwCursor {
    pub opaque: [UnwWord; 127],
}

// Opaque address space handle (unw_addr_space_t)
pub type UnwAddrSpaceT = *mut libc::c_void;

#[repr(C)]
pub struct UnwAccessors;

// This is a subset of the libunwind API.

extern "C" {
    #[link_name = "_ULx86_64_init_local2"]
    pub fn unw_init_local2(cursor: *mut UnwCursor, context: *mut UnwContext, flag: i32) -> i32;
    #[link_name = "_Ux86_64_getcontext"]
    pub fn unw_getcontext(context: *mut UnwContext) -> i32;
    #[link_name = "_ULx86_64_step"]
    pub fn unw_step(cursor: *mut UnwCursor) -> i32;
    #[link_name = "_ULx86_64_get_reg"]
    pub fn unw_get_reg(cursor: *mut UnwCursor, reg: i32, valp: *mut UnwWord) -> i32;
    #[link_name = "_ULx86_64_get_proc_name"]
    pub fn unw_get_proc_name(
        cursor: *mut UnwCursor,
        name: *mut libc::c_char,
        len: usize,
        offset: *mut u64,
    ) -> i32;
    #[link_name = "unw_backtrace2"]
    pub fn unw_backtrace2(
        buffer: *mut *mut ::std::os::raw::c_void,
        size: i32,
        context: *mut UnwContext,
        flag: i32,
    ) -> i32;
}

// Remote unwinding API. Uses _Ux86_64_* symbols from libunwind-x86_64
// because the _ULx86_64_* dont have remote support
#[allow(improper_ctypes)]
extern "C" {
    #[link_name = "_Ux86_64_init_remote"]
    pub fn unw_init_remote(
        cursor: *mut UnwCursor,
        addr_space: UnwAddrSpaceT,
        arg: *mut libc::c_void,
    ) -> i32;
    #[link_name = "_Ux86_64_step"]
    pub fn unw_step_remote(cursor: *mut UnwCursor) -> i32;
    #[link_name = "_Ux86_64_get_reg"]
    pub fn unw_get_reg_remote(cursor: *mut UnwCursor, reg: i32, valp: *mut UnwWord) -> i32;
    #[link_name = "_Ux86_64_get_proc_name"]
    pub fn unw_get_proc_name_remote(
        cursor: *mut UnwCursor,
        name: *mut libc::c_char,
        len: usize,
        offset: *mut UnwWord,
    ) -> i32;
    #[link_name = "_Ux86_64_create_addr_space"]
    pub fn unw_create_addr_space(accessors: *mut UnwAccessors, byteorder: i32) -> UnwAddrSpaceT;
    #[link_name = "_Ux86_64_destroy_addr_space"]
    pub fn unw_destroy_addr_space(addr_space: UnwAddrSpaceT);
    pub fn _UPT_create(pid: libc::pid_t) -> *mut libc::c_void;
    pub fn _UPT_destroy(upt_info: *mut libc::c_void);
    pub static _UPT_accessors: UnwAccessors;
}

// x86_64 register definitions for libunwind
pub const UNW_REG_IP: i32 = 16; // Instruction Pointer
pub const UNW_REG_SP: i32 = 17; // Stack Pointer
pub const UNW_REG_FP: i32 = 15; // Frame Pointer
pub const UNW_INIT_SIGNAL_FRAME: i32 = 1;
