use android_loader::sysv64;
use libc::{O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
use log::debug;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;

#[link(name = "ucrt")]
extern "C" {
    fn _errno() -> *mut libc::c_int;
    fn _timespec64_get(__ts: *mut libc::timespec, __base: libc::c_int) -> libc::c_int;
    fn _chsize(handle: i64, length: u64) -> usize;
}

// took from cosmopolitan libc
#[sysv64]
pub unsafe fn umask(mask: usize) -> usize {
    debug!("umask: Windows specific implementation called!");
    mask
}

#[sysv64]
pub unsafe fn ftruncate(handle: i64, length: u64) -> usize {
    debug!(
        "ftruncate: Windows translate-call. handle: {}, length: {}",
        handle, length
    );
    let ftr = _chsize(handle, length);

    ftr
}

#[repr(C)]
pub struct PosixTimeval {
    tv_sec: u64,
    tv_usec: u64, /* microseconds */
}

#[repr(C)]
pub struct PosixTimespec {
    tv_sec: i64,
    tv_nsec: i64, /* microseconds */
}

#[repr(C)]
pub struct PosixTimezone {
    tz_minuteswest: u32,
    tz_dsttime: u32, /* microseconds */
}

static HECTONANOSECONDS: u64 = 10000000;

impl PosixTimespec {
    pub fn from_windows_time(time: u64) -> PosixTimespec {
        PosixTimespec {
            tv_sec: (time / HECTONANOSECONDS) as i64,
            tv_nsec: (time % HECTONANOSECONDS) as i64 * 100,
        }
    }
}

#[sysv64]
pub unsafe fn gettimeofday(timeval: *mut PosixTimeval, _tz: *mut PosixTimezone) -> isize {
    debug!("gettimeofday: Windows specific implementation called!");
    let mut ts = MaybeUninit::<libc::timespec>::zeroed();

    let ret = _timespec64_get(ts.as_mut_ptr(), 1);
    let ts = ts.assume_init();

    *timeval = PosixTimeval {
        tv_sec: ts.tv_sec as _,
        tv_usec: (ts.tv_nsec / 1000) as _,
    };

    ret as _
}

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

trait ToWindows<T> {
    unsafe fn to_windows(&self) -> T;
}

impl ToWindows<CString> for CStr {
    unsafe fn to_windows(&self) -> CString {
        let path = self
            .to_str()
            .unwrap()
            .to_string()
            .chars()
            .map(|x| match x {
                '/' => '\\',
                c => c,
            })
            .collect::<String>();

        let path = path.trim_start_matches("\\\\?\\").to_string();

        CString::new(path).unwrap()
    }
}

#[sysv64]
pub unsafe fn lstat(path: *const libc::c_char, buf: *mut StatLinux) -> libc::c_int {
    debug!(
        "lstat: Windows translate-call, path: {:?}",
        CStr::from_ptr(path)
    );
    let mut stat_win = MaybeUninit::<libc::stat>::zeroed();
    let path = CStr::from_ptr(path).to_windows();

    let ret = libc::stat(path.as_ptr(), stat_win.as_mut_ptr());
    let stat_win = stat_win.assume_init();

    *buf = stat_win.to_windows();

    ret
}

impl ToWindows<StatLinux> for libc::stat {
    unsafe fn to_windows(&self) -> StatLinux {
        let atime = PosixTimespec::from_windows_time(self.st_atime as u64);
        let mtime = PosixTimespec::from_windows_time(self.st_mtime as u64);
        let ctime = PosixTimespec::from_windows_time(self.st_ctime as u64);

        let mut mode = 0o555;
        let win_mode = self.st_mode;

        if win_mode & 0b11 != 0 {
            mode |= 0o200;
        }

        if win_mode & 0x4000 != 0 {
            mode |= 0o40000;
        }

        StatLinux {
            st_dev: self.st_dev as _,
            st_ino: self.st_ino as _,
            st_nlink: self.st_nlink as _,
            st_mode: mode as _,
            st_uid: self.st_uid as _,
            st_gid: self.st_gid as _,
            __pad0: 0,
            st_rdev: self.st_rdev as _,
            st_size: self.st_size as _,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: atime.tv_sec,
            st_atime_nsec: 0,
            st_mtime: mtime.tv_sec,
            st_mtime_nsec: 0,
            st_ctime: ctime.tv_sec,
            st_ctime_nsec: 0,
            __unused: [0, 0, 0],
        }
    }
}

#[sysv64]
pub unsafe fn fstat(fildes: libc::c_int, buf: *mut StatLinux) -> libc::c_int {
    debug!("fstat: Windows translate-call");
    let mut stat_win = MaybeUninit::<libc::stat>::zeroed();
    let ret = libc::fstat(fildes, stat_win.as_mut_ptr());
    let stat_win = stat_win.assume_init();

    *buf = stat_win.to_windows();

    ret
}

#[sysv64]
pub unsafe fn malloc(size: libc::size_t) -> *mut libc::c_void {
    // debug!("malloc: Windows translate-call");
    libc::malloc(size)
}

#[sysv64]
pub unsafe fn free(p: *mut libc::c_void) {
    // debug!("free: Windows translate-call");
    libc::free(p)
}

#[sysv64]
pub unsafe fn strncpy(
    dst: *mut libc::c_char,
    src: *const libc::c_char,
    n: libc::size_t,
) -> *mut libc::c_char {
    debug!("strncpy: Windows translate-call");
    libc::strncpy(dst, src, n)
}

#[sysv64]
pub unsafe fn chmod(path: *const libc::c_char, mode: libc::c_int) -> libc::c_int {
    debug!("chmod: Windows translate-call");
    libc::chmod(path, mode)
}

#[sysv64]
pub unsafe fn mkdir(path: *const libc::c_char) -> libc::c_int {
    debug!("mkdir: Windows translate-call");
    libc::mkdir(path)
}

#[sysv64]
pub unsafe fn open(path: *const libc::c_char, oflag: libc::c_int) -> libc::c_int {
    debug!("open: Windows translate-call oflag 0o{:o}", oflag);

    let path = CStr::from_ptr(path).to_windows();

    let mut win_flag = 0x8000; // binary mode

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

    let val = libc::open(path.as_ptr(), win_flag);

    val
}

#[sysv64]
pub unsafe fn close(fd: libc::c_int) -> libc::c_int {
    debug!("close: Windows translate-call");
    libc::close(fd)
}

#[sysv64]
pub unsafe fn read(fd: libc::c_int, buf: *mut libc::c_void, count: libc::c_uint) -> libc::c_int {
    debug!("read: Windows translate-call");

    let r = libc::read(fd, buf, count);
    r
}

#[sysv64]
pub unsafe fn write(fd: libc::c_int, buf: *const libc::c_void, count: libc::c_uint) -> libc::c_int {
    debug!("write: Windows translate-call");
    libc::write(fd, buf, count)
}
