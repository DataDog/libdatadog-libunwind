// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::CStr;
use std::fs;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::process::{Child, Command};

use libdd_libunwind_sys::{
    unw_get_proc_name_remote, unw_get_reg_remote, unw_init_remote, RemoteUnwindResources,
    UnwCursor, UnwWord, UNW_REG_IP,
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn section_offset(bytes: &[u8], wanted: &str) -> usize {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "fixture must be ELF64");
    assert_eq!(bytes[5], 1, "fixture must be little-endian");

    let shoff = read_u64(bytes, 0x28) as usize;
    let shentsize = read_u16(bytes, 0x3a) as usize;
    let shnum = read_u16(bytes, 0x3c) as usize;
    let shstrndx = read_u16(bytes, 0x3e) as usize;
    let shstr = shoff + shstrndx * shentsize;
    let names = read_u64(bytes, shstr + 0x18) as usize;

    for index in 0..shnum {
        let shdr = shoff + index * shentsize;
        let name = names + read_u32(bytes, shdr) as usize;
        let end = name + bytes[name..].iter().position(|&b| b == 0).unwrap();
        if &bytes[name..end] == wanted.as_bytes() {
            return read_u64(bytes, shdr + 0x18) as usize;
        }
    }
    panic!("missing {wanted} section");
}

fn corrupt_dynamic_symbol_metadata(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let gnu_hash = section_offset(&bytes, ".gnu.hash");
    let bucket_count = read_u32(&bytes, gnu_hash) as usize;
    let bloom_size = read_u32(&bytes, gnu_hash + 8) as usize;
    assert!(bucket_count > 0 && bloom_size > 0);

    // GNU hash header (4 u32s), then ELF64 bloom words (u64s), then u32 buckets.
    let first_bucket = gnu_hash + 16 + bloom_size * 8;
    bytes[first_bucket..first_bucket + 4].copy_from_slice(&0x4000_0000u32.to_le_bytes());

    // Force get_proc_name to skip section symbols and use the corrupted dynamic table.
    bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    fs::write(path, bytes).unwrap();
}

fn compile(cc: &str, args: &[&str], output: &Path) {
    let status = Command::new(cc)
        .args(args)
        .arg("-o")
        .arg(output)
        .status()
        .unwrap();
    assert!(status.success(), "{cc} failed with {status}");
}

/// Reproduces the receiver crash caused by trusting an ELF GNU hash table while
/// resolving a remote frame name. The vulnerable version terminates the test
/// process with SIGSEGV instead of returning an error.
#[test]
fn corrupted_remote_elf_must_not_crash_symbol_lookup() {
    let dir = std::env::temp_dir().join(format!("libdd-libunwind-repro-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();

    let library_c = dir.join("target.c");
    let helper_c = dir.join("helper.c");
    let library = dir.join("libtarget.so");
    let helper = dir.join("helper");

    fs::write(
        &library_c,
        r#"
#include <unistd.h>
__attribute__((visibility("default"), noinline))
void repro_target(int ready_fd) {
  char byte = 'x';
  write(ready_fd, &byte, 1);
  for (;;) __asm__ volatile("" ::: "memory");
}
"#,
    )
    .unwrap();
    fs::write(
        &helper_c,
        r#"
#include <dlfcn.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
int main(int argc, char **argv) {
  prctl(PR_SET_PDEATHSIG, SIGKILL);
  void *handle = dlopen(argv[1], RTLD_NOW);
  void (*target)(int) = (void (*)(int))dlsym(handle, "repro_target");
  if (!target) return 2;
  target(atoi(argv[2]));
  return 0;
}
"#,
    )
    .unwrap();

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    compile(
        &cc,
        &[
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-Wl,--hash-style=gnu",
            library_c.to_str().unwrap(),
        ],
        &library,
    );
    compile(&cc, &[helper_c.to_str().unwrap(), "-ldl"], &helper);

    let mut pipe = [0; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let [read_fd, write_fd] = pipe;
    let child = Command::new(&helper)
        .arg(&library)
        .arg(write_fd.to_string())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    unsafe { libc::close(write_fd) };

    let mut ready = [0];
    let mut reader = unsafe { fs::File::from_raw_fd(read_fd) };
    reader.read_exact(&mut ready).unwrap();

    let pid = child.0.id() as libc::pid_t;
    assert_eq!(
        unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        },
        0
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSTOPPED(status));

    let resources = RemoteUnwindResources::new(pid).unwrap();
    let mut cursor: UnwCursor = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { unw_init_remote(&mut cursor, resources.addr_space(), resources.upt()) },
        0
    );

    let mut ip: UnwWord = 0;
    assert_eq!(
        unsafe { unw_get_reg_remote(&mut cursor, UNW_REG_IP, &mut ip) },
        0
    );
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let mapping = maps
        .lines()
        .filter(|line| line.ends_with(library.to_str().unwrap()))
        .find(|line| {
            let (start, end) = line.split_once(' ').unwrap().0.split_once('-').unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            (start..end).contains(&ip)
        })
        .unwrap_or_else(|| panic!("IP {ip:#x} is outside the target library mappings:\n{maps}"));
    eprintln!("target frame: {mapping}");

    corrupt_dynamic_symbol_metadata(&library);

    let mut name = [0 as libc::c_char; 256];
    let mut offset: UnwWord = 0;
    let result = unsafe {
        unw_get_proc_name_remote(&mut cursor, name.as_mut_ptr(), name.len(), &mut offset)
    };
    assert!(
        result < 0,
        "corrupt ELF unexpectedly resolved to {}",
        unsafe { CStr::from_ptr(name.as_ptr()).to_string_lossy() }
    );

    drop(resources);
    unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    fs::remove_dir_all(dir).unwrap();
}
