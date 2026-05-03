#[cfg(target_os = "macos")]
mod posix_macos;
#[cfg(target_family = "windows")]
mod posix_windows;

use crate::AnisetteError;
use crate::adi_proxy::{
    ADIError, ADIProxy, ConfigurableADIProxy, RequestOTPData, StartProvisioningData,
    SynchronizeData,
};

use android_loader::android_library::AndroidLibrary;
use android_loader::sysv64_type;
use android_loader::{hook_manager, sysv64};
use std::collections::HashMap;
use std::ffi::{CString, c_char};
use std::path::PathBuf;

pub struct StoreServicesCoreADIProxy<'lt> {
    #[allow(dead_code)]
    store_services_core: AndroidLibrary<'lt>,

    local_user_uuid: String,
    device_identifier: String,

    adi_set_android_id: sysv64_type!(fn(id: *const u8, length: u32) -> i32),
    adi_set_provisioning_path: sysv64_type!(fn(path: *const u8) -> i32),

    adi_provisioning_erase: sysv64_type!(fn(ds_id: i64) -> i32),
    adi_synchronize: sysv64_type!(
        fn(
            ds_id: i64,
            sim: *const u8,
            sim_length: u32,
            out_mid: *mut *const u8,
            out_mid_length: *mut u32,
            out_srm: *mut *const u8,
            out_srm_length: *mut u32,
        ) -> i32
    ),
    adi_provisioning_destroy: sysv64_type!(fn(session: u32) -> i32),
    adi_provisioning_end: sysv64_type!(
        fn(session: u32, ptm: *const u8, ptm_length: u32, tk: *const u8, tk_length: u32) -> i32
    ),
    adi_provisioning_start: sysv64_type!(
        fn(
            ds_id: i64,
            spim: *const u8,
            spim_length: u32,
            out_cpim: *mut *const u8,
            out_cpim_length: *mut u32,
            out_session: *mut u32,
        ) -> i32
    ),
    adi_get_login_code: sysv64_type!(fn(ds_id: i64) -> i32),
    adi_dispose: sysv64_type!(fn(ptr: *const u8) -> i32),
    adi_otp_request: sysv64_type!(
        fn(
            ds_id: i64,
            out_mid: *mut *const u8,
            out_mid_size: *mut u32,
            out_otp: *mut *const u8,
            out_otp_size: *mut u32,
        ) -> i32
    ),
}

impl StoreServicesCoreADIProxy<'_> {
    pub fn new<'lt>(
        library_path: &PathBuf,
    ) -> Result<StoreServicesCoreADIProxy<'lt>, AnisetteError> {
        Self::with_custom_provisioning_path(library_path, library_path)
    }

    pub fn with_custom_provisioning_path<'lt>(
        library_path: &PathBuf,
        provisioning_path: &PathBuf,
    ) -> Result<StoreServicesCoreADIProxy<'lt>, AnisetteError> {
        // Should be safe if the library is correct.
        unsafe {
            LoaderHelpers::setup_hooks();

            if !library_path.exists() {
                std::fs::create_dir(library_path)?;
                return Err(AnisetteError::MissingLibraries.into());
            }

            let library_path = library_path.canonicalize()?;

            #[cfg(target_arch = "x86_64")]
            const ARCH: &str = "x86_64";
            #[cfg(target_arch = "x86")]
            const ARCH: &str = "x86";
            #[cfg(target_arch = "arm")]
            const ARCH: &str = "armeabi-v7a";
            #[cfg(target_arch = "aarch64")]
            const ARCH: &str = "arm64-v8a";

            let native_library_path = library_path.join("lib").join(ARCH);

            let path = native_library_path.join("libstoreservicescore.so");
            let path = path.to_str().ok_or(AnisetteError::Misc)?;
            let store_services_core = AndroidLibrary::load(path)?;

            let adi_load_library_with_path: sysv64_type!(fn(path: *const u8) -> i32) =
                std::mem::transmute(
                    store_services_core
                        .get_symbol("kq56gsgHG6")
                        .ok_or(AnisetteError::InvalidLibraryFormat)?,
                );

            let path =
                CString::new(native_library_path.to_str().ok_or(AnisetteError::Misc)?).unwrap();
            assert_eq!((adi_load_library_with_path)(path.as_ptr() as *const u8), 0);

            let adi_set_android_id = store_services_core
                .get_symbol("Sph98paBcz")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_set_provisioning_path = store_services_core
                .get_symbol("nf92ngaK92")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;

            let adi_provisioning_erase = store_services_core
                .get_symbol("p435tmhbla")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_synchronize = store_services_core
                .get_symbol("tn46gtiuhw")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_provisioning_destroy = store_services_core
                .get_symbol("fy34trz2st")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_provisioning_end = store_services_core
                .get_symbol("uv5t6nhkui")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_provisioning_start = store_services_core
                .get_symbol("rsegvyrt87")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_get_login_code = store_services_core
                .get_symbol("aslgmuibau")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_dispose = store_services_core
                .get_symbol("jk24uiwqrg")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;
            let adi_otp_request = store_services_core
                .get_symbol("qi864985u0")
                .ok_or(AnisetteError::InvalidLibraryFormat)?;

            let mut proxy = StoreServicesCoreADIProxy {
                store_services_core,

                local_user_uuid: String::new(),
                device_identifier: String::new(),

                adi_set_android_id: std::mem::transmute(adi_set_android_id),
                adi_set_provisioning_path: std::mem::transmute(adi_set_provisioning_path),

                adi_provisioning_erase: std::mem::transmute(adi_provisioning_erase),
                adi_synchronize: std::mem::transmute(adi_synchronize),
                adi_provisioning_destroy: std::mem::transmute(adi_provisioning_destroy),
                adi_provisioning_end: std::mem::transmute(adi_provisioning_end),
                adi_provisioning_start: std::mem::transmute(adi_provisioning_start),
                adi_get_login_code: std::mem::transmute(adi_get_login_code),
                adi_dispose: std::mem::transmute(adi_dispose),
                adi_otp_request: std::mem::transmute(adi_otp_request),
            };

            proxy.set_provisioning_path(provisioning_path.to_str().ok_or(AnisetteError::Misc)?)?;

            Ok(proxy)
        }
    }
}

impl ADIProxy for StoreServicesCoreADIProxy<'_> {
    fn erase_provisioning(&mut self, ds_id: i64) -> Result<(), ADIError> {
        match (self.adi_provisioning_erase)(ds_id) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn synchronize(&mut self, ds_id: i64, sim: &[u8]) -> Result<SynchronizeData, ADIError> {
        unsafe {
            let sim_size = sim.len() as u32;
            let sim_ptr = sim.as_ptr();

            let mut mid_size: u32 = 0;
            let mut mid_ptr: *const u8 = std::ptr::null();
            let mut srm_size: u32 = 0;
            let mut srm_ptr: *const u8 = std::ptr::null();

            match (self.adi_synchronize)(
                ds_id,
                sim_ptr,
                sim_size,
                &mut mid_ptr,
                &mut mid_size,
                &mut srm_ptr,
                &mut srm_size,
            ) {
                0 => {
                    let mut mid = vec![0; mid_size as usize];
                    let mut srm = vec![0; srm_size as usize];

                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    srm.copy_from_slice(std::slice::from_raw_parts(srm_ptr, srm_size as usize));

                    (self.adi_dispose)(mid_ptr);
                    (self.adi_dispose)(srm_ptr);

                    Ok(SynchronizeData { mid, srm })
                }
                err => Err(ADIError::resolve(err)),
            }
        }
    }

    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError> {
        match (self.adi_provisioning_destroy)(session) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError> {
        let ptm_size = ptm.len() as u32;
        let ptm_ptr = ptm.as_ptr();

        let tk_size = tk.len() as u32;
        let tk_ptr = tk.as_ptr();

        match (self.adi_provisioning_end)(session, ptm_ptr, ptm_size, tk_ptr, tk_size) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn start_provisioning(
        &mut self,
        ds_id: i64,
        spim: &[u8],
    ) -> Result<StartProvisioningData, ADIError> {
        unsafe {
            let spim_size = spim.len() as u32;
            let spim_ptr = spim.as_ptr();

            let mut cpim_size: u32 = 0;
            let mut cpim_ptr: *const u8 = std::ptr::null();

            let mut session: u32 = 0;

            match (self.adi_provisioning_start)(
                ds_id,
                spim_ptr,
                spim_size,
                &mut cpim_ptr,
                &mut cpim_size,
                &mut session,
            ) {
                0 => {
                    let mut cpim = vec![0; cpim_size as usize];

                    cpim.copy_from_slice(std::slice::from_raw_parts(cpim_ptr, cpim_size as usize));

                    (self.adi_dispose)(cpim_ptr);

                    Ok(StartProvisioningData { cpim, session })
                }
                err => Err(ADIError::resolve(err)),
            }
        }
    }

    fn is_machine_provisioned(&self, ds_id: i64) -> bool {
        (self.adi_get_login_code)(ds_id) == 0
    }

    fn request_otp(&self, ds_id: i64) -> Result<RequestOTPData, ADIError> {
        unsafe {
            let mut mid_size: u32 = 0;
            let mut mid_ptr: *const u8 = std::ptr::null();
            let mut otp_size: u32 = 0;
            let mut otp_ptr: *const u8 = std::ptr::null();

            match (self.adi_otp_request)(
                ds_id,
                &mut mid_ptr,
                &mut mid_size,
                &mut otp_ptr,
                &mut otp_size,
            ) {
                0 => {
                    let mut mid = vec![0; mid_size as usize];
                    let mut otp = vec![0; otp_size as usize];

                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    otp.copy_from_slice(std::slice::from_raw_parts(otp_ptr, otp_size as usize));

                    (self.adi_dispose)(mid_ptr);
                    (self.adi_dispose)(otp_ptr);

                    Ok(RequestOTPData { mid, otp })
                }
                err => Err(ADIError::resolve(err)),
            }
        }
    }

    fn set_local_user_uuid(&mut self, local_user_uuid: String) {
        self.local_user_uuid = local_user_uuid;
    }

    fn set_device_identifier(&mut self, device_identifier: String) -> Result<(), ADIError> {
        self.set_identifier(&device_identifier[0..16])?;
        self.device_identifier = device_identifier;
        Ok(())
    }

    fn get_local_user_uuid(&self) -> String {
        self.local_user_uuid.clone()
    }

    fn get_device_identifier(&self) -> String {
        self.device_identifier.clone()
    }

    fn get_serial_number(&self) -> String {
        "0".to_string()
    }
}

impl ConfigurableADIProxy for StoreServicesCoreADIProxy<'_> {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError> {
        match (self.adi_set_android_id)(identifier.as_ptr(), identifier.len() as u32) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError> {
        let path = CString::new(path).unwrap();
        match (self.adi_set_provisioning_path)(path.as_ptr() as *const u8) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }
}

struct LoaderHelpers;

#[cfg(all(target_family = "unix", not(target_os = "macos")))]
use libc::{
    chmod, close, free, fstat, ftruncate, gettimeofday, lstat, malloc, mkdir, open, read, strncpy,
    umask, write,
};
#[cfg(target_os = "macos")]
use posix_macos::*;

static mut ERRNO: i32 = 0;

#[allow(unreachable_code)]
#[sysv64]
unsafe fn __errno_location() -> *mut i32 {
    ERRNO = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    &mut ERRNO
}

#[sysv64]
fn arc4random() -> u32 {
    rand::random()
}

#[sysv64]
unsafe fn __system_property_get(_name: *const c_char, value: *mut c_char) -> i32 {
    *value = '0' as c_char;
    return 1;
}

#[cfg(target_family = "windows")]
use posix_windows::*;

impl LoaderHelpers {
    pub fn setup_hooks() {
        let mut hooks = HashMap::new();
        hooks.insert("arc4random".to_owned(), arc4random as usize);
        hooks.insert("chmod".to_owned(), chmod as usize);
        hooks.insert(
            "__system_property_get".to_owned(),
            __system_property_get as usize,
        );
        hooks.insert("__errno".to_owned(), __errno_location as usize);
        hooks.insert("close".to_owned(), close as usize);
        hooks.insert("free".to_owned(), free as usize);
        hooks.insert("fstat".to_owned(), fstat as usize);
        hooks.insert("ftruncate".to_owned(), ftruncate as usize);
        hooks.insert("gettimeofday".to_owned(), gettimeofday as usize);
        hooks.insert("lstat".to_owned(), lstat as usize);
        hooks.insert("malloc".to_owned(), malloc as usize);
        hooks.insert("mkdir".to_owned(), mkdir as usize);
        hooks.insert("open".to_owned(), open as usize);
        hooks.insert("read".to_owned(), read as usize);
        hooks.insert("strncpy".to_owned(), strncpy as usize);
        hooks.insert("umask".to_owned(), umask as usize);
        hooks.insert("write".to_owned(), write as usize);

        hook_manager::add_hooks(hooks);
    }
}

#[cfg(test)]
mod tests {
    use crate::AnisetteError;
    use crate::{AnisetteConfiguration, AnisetteHeaders};
    use log::info;
    use std::path::PathBuf;

    #[cfg(not(feature = "async"))]
    #[test]
    fn fetch_anisette_ssc() -> Result<(), AnisetteError> {
        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_ssc_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers()?
        );
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn fetch_anisette_ssc_async() -> Result<(), AnisetteError> {
        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_ssc_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers().await?
        );
        Ok(())
    }
}
