// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! RAII helpers for remote libunwind + ptrace (`_UPT_*`).

use std::ptr::NonNull;

use crate::_UPT_accessors;
use crate::_UPT_create;
use crate::_UPT_destroy;
use crate::unw_create_addr_space;
use crate::unw_destroy_addr_space;
use crate::UnwAccessors;
use crate::UnwAddrSpaceT;

/// Opaque ptrace unwind handle
pub struct UptInfo(NonNull<libc::c_void>);

impl UptInfo {
    pub fn new(pid: libc::pid_t) -> Option<Self> {
        let p = unsafe { _UPT_create(pid) };
        NonNull::new(p).map(Self)
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut libc::c_void {
        self.0.as_ptr()
    }
}

impl Drop for UptInfo {
    fn drop(&mut self) {
        unsafe {
            _UPT_destroy(self.0.as_ptr());
        }
    }
}

/// Remote unwind address space using `_UPT_accessors`
pub struct UnwAddrSpace(NonNull<libc::c_void>);

impl UnwAddrSpace {
    pub fn new() -> Option<Self> {
        let p = unsafe {
            unw_create_addr_space(std::ptr::addr_of!(_UPT_accessors) as *mut UnwAccessors, 0)
        };
        NonNull::new(p).map(Self)
    }

    #[inline]
    pub fn as_ptr(&self) -> UnwAddrSpaceT {
        self.0.as_ptr()
    }
}

impl Drop for UnwAddrSpace {
    fn drop(&mut self) {
        unsafe {
            unw_destroy_addr_space(self.0.as_ptr());
        }
    }
}

/// Address space + ptrace info for `unw_init_remote`
pub struct RemoteUnwindResources {
    upt: UptInfo,
    addr_space: UnwAddrSpace,
}

impl RemoteUnwindResources {
    pub fn new(pid: libc::pid_t) -> Option<Self> {
        let addr_space = UnwAddrSpace::new()?;
        let upt = UptInfo::new(pid)?;
        Some(Self { upt, addr_space })
    }

    #[inline]
    pub fn addr_space(&self) -> UnwAddrSpaceT {
        self.addr_space.as_ptr()
    }

    #[inline]
    pub fn upt_arg(&self) -> *mut libc::c_void {
        self.upt.as_ptr()
    }
}
