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

/// Owning handle for the opaque pointer returned by [`_UPT_create`](crate::_UPT_create).
///
/// This is not a view over foreign memory: dropping the value calls [`_UPT_destroy`](crate::_UPT_destroy).
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

/// Owning remote unwind address space (from [`unw_create_addr_space`](crate::unw_create_addr_space) with [`_UPT_accessors`](crate::_UPT_accessors)).
///
/// Dropping calls [`unw_destroy_addr_space`](crate::unw_destroy_addr_space); this is not a non-owning handle.
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

/// Owns the ptrace unwind info and address space used with [`unw_init_remote`](crate::unw_init_remote).
///
/// Dropping runs each type’s destructor (see [`UptInfo`] and [`UnwAddrSpace`]); field order matches the teardown order shown in the libunwind ptrace example.
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
    pub fn upt(&self) -> *mut libc::c_void {
        self.upt.as_ptr()
    }
}
