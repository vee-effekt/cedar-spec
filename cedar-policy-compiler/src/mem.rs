/// Executable memory region backed by mmap.
use std::ptr;

pub struct ExecutableMemory {
    ptr: *mut u8,
    len: usize,
}

// Safety: The memory is immutable after construction (RX) and the pointer
// is valid for the lifetime of ExecutableMemory.
unsafe impl Send for ExecutableMemory {}
unsafe impl Sync for ExecutableMemory {}

impl ExecutableMemory {
    /// Allocate executable memory, copy `code` into it, and mark it RX.
    pub fn new(code: &[u8]) -> Result<Self, String> {
        if code.is_empty() {
            return Err("empty code".to_string());
        }

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let alloc_size = (code.len() + page_size - 1) & !(page_size - 1);

        #[cfg(target_os = "macos")]
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT;
        #[cfg(not(target_os = "macos"))]
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let mem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                alloc_size,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };

        if mem == libc::MAP_FAILED {
            return Err("mmap failed".to_string());
        }

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
        }

        let rc = unsafe {
            libc::mprotect(mem, alloc_size, libc::PROT_READ | libc::PROT_EXEC)
        };

        if rc != 0 {
            unsafe { libc::munmap(mem, alloc_size); }
            return Err("mprotect failed".to_string());
        }

        Ok(Self {
            ptr: mem as *mut u8,
            len: alloc_size,
        })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}
