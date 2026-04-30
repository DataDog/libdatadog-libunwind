// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::arch::global_asm;

pub type UnwContext = libc::ucontext_t;

pub type UnwWord = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UnwCursor {
    pub opaque: [UnwWord; 250],
}

// Opaque address space handle (unw_addr_space_t)
pub type UnwAddrSpaceT = *mut libc::c_void;

// Opaque accessor table (unw_accessors_t); never construct directly
#[repr(C)]
pub struct UnwAccessors;

extern "C" {
    #[link_name = "_ULaarch64_init_local2"]
    pub fn unw_init_local2(cursor: *mut UnwCursor, context: *mut UnwContext, flag: i32) -> i32;
    pub fn unw_getcontext(context: *mut UnwContext) -> i32;
    #[link_name = "_ULaarch64_step"]
    pub fn unw_step(cursor: *mut UnwCursor) -> i32;
    #[link_name = "_ULaarch64_get_reg"]
    pub fn unw_get_reg(cursor: *mut UnwCursor, reg: i32, valp: *mut UnwWord) -> i32;
    #[link_name = "_ULaarch64_get_proc_name"]
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

// Remote unwinding API. Uses _Uaarch64_* symbols from libunwind-aarch64
// because the _ULaarch64_* dont have remote support
#[allow(improper_ctypes)]
extern "C" {
    #[link_name = "_Uaarch64_init_remote"]
    pub fn unw_init_remote(
        cursor: *mut UnwCursor,
        addr_space: UnwAddrSpaceT,
        arg: *mut libc::c_void,
    ) -> i32;
    #[link_name = "_Uaarch64_step"]
    pub fn unw_step_remote(cursor: *mut UnwCursor) -> i32;
    #[link_name = "_Uaarch64_get_reg"]
    pub fn unw_get_reg_remote(cursor: *mut UnwCursor, reg: i32, valp: *mut UnwWord) -> i32;
    #[link_name = "_Uaarch64_get_proc_name"]
    pub fn unw_get_proc_name_remote(
        cursor: *mut UnwCursor,
        name: *mut libc::c_char,
        len: usize,
        offset: *mut UnwWord,
    ) -> i32;
    #[link_name = "_Uaarch64_create_addr_space"]
    pub fn unw_create_addr_space(accessors: *mut UnwAccessors, byteorder: i32) -> UnwAddrSpaceT;
    #[link_name = "_Uaarch64_destroy_addr_space"]
    pub fn unw_destroy_addr_space(addr_space: UnwAddrSpaceT);
    pub fn _UPT_create(pid: libc::pid_t) -> *mut libc::c_void;
    pub fn _UPT_destroy(upt_info: *mut libc::c_void);
    pub static _UPT_accessors: UnwAccessors;
}

pub const UNW_REG_IP: i32 = 30; // Instruction Pointer
pub const UNW_REG_SP: i32 = 31; // Stack Pointer
pub const UNW_REG_FP: i32 = 29; // Frame Pointer
pub const UNW_INIT_SIGNAL_FRAME: i32 = 1;

// On aarch64, libunwind's unw_getcontext is a C inline-asm macro (in
// libunwind-aarch64.h), not an exported symbol. Provide a callable function
// that does the same thing: saves all GPRs, SP, and PC into a ucontext_t,
// then returns 0.
//
// Offsets from ucontext_i.h (Linux aarch64):
//   UC_MCONTEXT_OFF = 0xb0
//   SC_GPR_OFF      = 0x08   (regs[0] within mcontext)
//   SC_SP_OFF       = 0x100
//   SC_PC_OFF       = 0x108
//
// GPR base = UC_MCONTEXT_OFF + SC_GPR_OFF = 0xb8
// Register xN is at GPR base + N*8
global_asm!(
    ".global unw_getcontext",
    ".type unw_getcontext, @function",
    "unw_getcontext:",
    ".cfi_startproc",
    "stp  x0,  x1, [x0, #0xb8]",
    "stp  x2,  x3, [x0, #0xc8]",
    "stp  x4,  x5, [x0, #0xd8]",
    "stp  x6,  x7, [x0, #0xe8]",
    "stp  x8,  x9, [x0, #0xf8]",
    "stp x10, x11, [x0, #0x108]",
    "stp x12, x13, [x0, #0x118]",
    "stp x14, x15, [x0, #0x128]",
    "stp x16, x17, [x0, #0x138]",
    "stp x18, x19, [x0, #0x148]",
    "stp x20, x21, [x0, #0x158]",
    "stp x22, x23, [x0, #0x168]",
    "stp x24, x25, [x0, #0x178]",
    "stp x26, x27, [x0, #0x188]",
    "stp x28, x29, [x0, #0x198]",
    "str  x30,     [x0, #0x1a8]",
    // SP (exclude this call frame) and PC (return address)
    "mov  x9, sp",
    "str  x9,  [x0, #0x1b0]",
    "str  x30, [x0, #0x1b8]",
    "mov  x0, #0",
    "ret",
    ".cfi_endproc",
    ".size unw_getcontext, . - unw_getcontext",
);

