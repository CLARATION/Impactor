pub use libc::{chmod, close, free, ftruncate, gettimeofday, malloc, mkdir, read, strncpy, umask, write};

use libc::{lstat as lstat_macos, fstat as fstat_macos, stat as stat_macos, open as open_macos, O_CREAT, O_WRONLY, O_RDWR, O_RDONLY};

use android_loader::sysv64;

#[repr(C)]
pub struct StatLinux {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    __pad0: libc::c_int,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[sysv64]
pub unsafe fn lstat(path: *const libc::c_char, buf: *mut StatLinux) -> libc::c_int {
    let mut st: stat_macos = std::mem::zeroed();
    lstat_macos(path, &mut st);
    *buf = StatLinux {
        st_dev: st.st_dev as _,
        st_ino: st.st_ino as _,
        st_nlink: st.st_nlink as _,
        st_mode: st.st_mode as _,
        st_uid: st.st_uid as _,
        st_gid: st.st_gid as _,
        __pad0: 0 as _,
        st_rdev: st.st_rdev as _,
        st_size: st.st_size as _,
        st_blksize: st.st_blksize as _,
        st_blocks: st.st_blocks as _,
        st_atime: st.st_atime as _,
        st_atime_nsec: st.st_atime_nsec as _,
        st_mtime: st.st_mtime as _,
        st_mtime_nsec: st.st_mtime_nsec as _,
        st_ctime: st.st_ctime as _,
        st_ctime_nsec: st.st_ctime_nsec as _,
        __unused: [0, 0, 0],
    };
    0
}

#[sysv64]
pub unsafe fn fstat(fildes: libc::c_int, buf: *mut StatLinux) -> libc::c_int {
    let mut st: stat_macos = std::mem::zeroed();
    fstat_macos(fildes, &mut st);
    *buf = StatLinux {
        st_dev: st.st_dev as _,
        st_ino: st.st_ino as _,
        st_nlink: st.st_nlink as _,
        st_mode: st.st_mode as _,
        st_uid: st.st_uid as _,
        st_gid: st.st_gid as _,
        __pad0: 0 as _,
        st_rdev: st.st_rdev as _,
        st_size: st.st_size as _,
        st_blksize: st.st_blksize as _,
        st_blocks: st.st_blocks as _,
        st_atime: st.st_atime as _,
        st_atime_nsec: st.st_atime_nsec as _,
        st_mtime: st.st_mtime as _,
        st_mtime_nsec: st.st_mtime_nsec as _,
        st_ctime: st.st_ctime as _,
        st_ctime_nsec: st.st_ctime_nsec as _,
        __unused: [0, 0, 0],
    };
    0
}

#[sysv64]
pub unsafe fn open(path: *const libc::c_char, oflag: libc::c_int) -> libc::c_int {
    let mut win_flag = 0; // binary mode

    if oflag & 0o100 != 0 {
        win_flag |= O_CREAT;
    }

    if oflag & 0o1 == 1 {
        win_flag |= O_WRONLY;
    } else if oflag & 0o2 != 0 {
        win_flag |= O_RDWR;
    } else {
        win_flag |= O_RDONLY;
    }

    let val = open_macos(path, win_flag);

    val
}
