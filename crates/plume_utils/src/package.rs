use super::{Bundle, PlistInfoTrait};
use crate::{cgbi, Error, SignerApp, SignerOptions};

use plist::Dictionary;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;
use zip::write::FileOptions;
use zip::ZipArchive;

#[derive(Debug, Clone)]
pub struct Package {
    package_file: PathBuf,
    stage_dir: PathBuf,
    stage_payload_dir: PathBuf,
    info_plist_dictionary: Dictionary,
    archive_entries: Vec<String>,
    pub app_icon_data: Option<Vec<u8>>,
}

impl Package {
    pub fn new(package_file: PathBuf) -> Result<Self, Error> {
        let stage_dir = std::env::temp_dir().join(format!(
            "plume_stage_{:08}",
            Uuid::new_v4().to_string().to_uppercase()
        ));
        let out_package_file = stage_dir.join("stage.ipa");

        fs::create_dir_all(&stage_dir)?;
        fs::copy(&package_file, &out_package_file)?;

        let file = fs::File::open(&out_package_file)?;
        let mut archive = ZipArchive::new(file)?;

        let mut archive_entries = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            archive_entries.push(Self::decoded_zip_name_raw(file.name_raw(), file.name()));
        }

        let info_plist_dictionary =
            Self::get_info_plist_from_archive(&out_package_file, &archive_entries)?;
        let app_icon_data = Self::extract_icon_from_archive(
            &out_package_file,
            &archive_entries,
            &info_plist_dictionary,
        );

        Ok(Self {
            package_file: out_package_file,
            stage_dir: stage_dir.clone(),
            stage_payload_dir: stage_dir.join("Payload"),
            info_plist_dictionary,
            archive_entries,
            app_icon_data,
        })
    }

    pub fn package_file(&self) -> &PathBuf {
        &self.package_file
    }

    fn decoded_zip_name_raw(raw: &[u8], fallback: &str) -> String {
        // Heuristic:
        // 1) If the raw bytes are valid UTF-8, trust that first.
        //    This fixes many IPA files whose ZIP entries are UTF-8 but missing the ZIP UTF-8 flag.
        // 2) Otherwise fall back to the ZIP crate's decoded name().
        match std::str::from_utf8(raw) {
            Ok(s) => s.to_owned(),
            Err(_) => fallback.to_owned(),
        }
    }

    fn safe_decoded_zip_path(name: &str) -> Option<PathBuf> {
        if name.is_empty() || name.contains('\0') {
            return None;
        }

        let mut out = PathBuf::new();

        for part in name.split('/') {
            if part.is_empty() {
                continue;
            }

            match part {
                "." | ".." => return None,
                _ => out.push(part),
            }
        }

        if out.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return None;
        }

        Some(out)
    }

    fn find_top_level_info_plist_path(archive_entries: &[String]) -> Option<&str> {
        archive_entries
            .iter()
            .find(|entry| {
                entry.starts_with("Payload/")
                    && entry.ends_with("/Info.plist")
                    && entry.matches('/').count() == 2
            })
            .map(String::as_str)
    }

    fn read_archive_entry_by_decoded_name(
        archive_path: &Path,
        wanted_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let file = fs::File::open(archive_path)?;
        let mut archive = ZipArchive::new(file)?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let decoded_name = Self::decoded_zip_name_raw(entry.name_raw(), entry.name());

            if decoded_name == wanted_name {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                return Ok(data);
            }
        }

        Err(Error::PackageInfoPlistMissing)
    }

    fn get_info_plist_from_archive(
        archive_path: &Path,
        archive_entries: &[String],
    ) -> Result<Dictionary, Error> {
        let info_plist_path = Self::find_top_level_info_plist_path(archive_entries)
            .ok_or(Error::PackageInfoPlistMissing)?;

        let plist_data = Self::read_archive_entry_by_decoded_name(archive_path, info_plist_path)?;
        Ok(plist::from_bytes(&plist_data)?)
    }

    fn extract_icon_from_archive(
        archive_path: &Path,
        archive_entries: &[String],
        plist: &Dictionary,
    ) -> Option<Vec<u8>> {
        let mut icon_names: Vec<String> = Vec::new();

        let primary_from = |d: &Dictionary| -> Vec<String> {
            d.get("CFBundlePrimaryIcon")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("CFBundleIconFiles"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_string())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

        if let Some(d) = plist.get("CFBundleIcons").and_then(|v| v.as_dictionary()) {
            icon_names.extend(primary_from(d));
        }

        if let Some(d) = plist
            .get("CFBundleIcons~ipad")
            .and_then(|v| v.as_dictionary())
        {
            for n in primary_from(d) {
                if !icon_names.contains(&n) {
                    icon_names.push(n);
                }
            }
        }

        if let Some(arr) = plist.get("CFBundleIconFiles").and_then(|v| v.as_array()) {
            for n in arr
                .iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
            {
                if !icon_names.contains(&n) {
                    icon_names.push(n);
                }
            }
        }

        if icon_names.is_empty() {
            return None;
        }

        let app_prefix = Self::find_top_level_info_plist_path(archive_entries)?
            .trim_end_matches("/Info.plist")
            .to_string();

        let file = fs::File::open(archive_path).ok()?;
        let mut archive = ZipArchive::new(file).ok()?;

        let suffixes = ["@3x.png", "@2x.png", "@1x.png", ".png"];

        for name in &icon_names {
            for suffix in &suffixes {
                let candidate = format!("{app_prefix}/{name}{suffix}");

                for i in 0..archive.len() {
                    let mut entry = archive.by_index(i).ok()?;
                    let decoded_name =
                        Self::decoded_zip_name_raw(entry.name_raw(), entry.name());

                    if decoded_name == candidate {
                        let mut data = Vec::new();
                        if entry.read_to_end(&mut data).is_ok() && !data.is_empty() {
                            return Some(cgbi::normalize(data));
                        }
                    }
                }
            }
        }

        None
    }

    pub fn get_package_bundle(&self) -> Result<Bundle, Error> {
        let file = fs::File::open(&self.package_file)?;
        let mut archive = ZipArchive::new(file)?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let decoded_name = Self::decoded_zip_name_raw(entry.name_raw(), entry.name());

            let rel_path = match Self::safe_decoded_zip_path(&decoded_name) {
                Some(p) => p,
                None => continue,
            };

            let out_path = self.stage_dir.join(rel_path);

            if entry.is_dir() || decoded_name.ends_with('/') {
                fs::create_dir_all(&out_path)?;
                continue;
            }

            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut out_file = fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out_file)?;
            out_file.flush()?;
        }

        let app_dir = fs::read_dir(&self.stage_payload_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.is_dir() && p.extension().and_then(|e| e.to_str()) == Some("app"))
            .ok_or(Error::PackageInfoPlistMissing)?;

        Ok(Bundle::new(app_dir)?)
    }

    pub fn get_archive_based_on_path(&self, path: &PathBuf) -> Result<PathBuf, Error> {
        if path.is_dir() {
            self.clone().archive_package_bundle()
        } else {
            Ok(self.package_file.clone())
        }
    }

    fn path_to_zip_name(path: &Path, prefix: &Path) -> Result<String, Error> {
        let rel = path
            .strip_prefix(prefix)
            .map_err(|_| Error::PackageInfoPlistMissing)?;

        let mut parts: Vec<String> = Vec::new();
        for comp in rel.components() {
            match comp {
                Component::Normal(s) => {
                    let text = s.to_string_lossy().into_owned();
                    parts.push(text);
                }
                Component::CurDir => {}
                _ => return Err(Error::PackageInfoPlistMissing),
            }
        }

        Ok(parts.join("/"))
    }

    fn archive_package_bundle(self) -> Result<PathBuf, Error> {
        let zip_file_path = self.stage_dir.join("resigned.ipa");
        let file = fs::File::create(&zip_file_path)?;
        let mut zip = zip::ZipWriter::new(file);

        let options =
            FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        let payload_dir = self.stage_payload_dir;

        fn add_dir_to_zip(
            zip: &mut zip::ZipWriter<fs::File>,
            path: &Path,
            prefix: &Path,
            options: &FileOptions<'_, zip::write::ExtendedFileOptions>,
        ) -> Result<(), Error> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                let mut name = Package::path_to_zip_name(&entry_path, prefix)?;

                if entry_path.is_dir() {
                    if !name.ends_with('/') {
                        name.push('/');
                    }
                    zip.add_directory(&name, options.clone())?;
                    add_dir_to_zip(zip, &entry_path, prefix, options)?;
                } else if entry_path.is_file() {
                    zip.start_file(&name, options.clone())?;
                    let mut f = fs::File::open(&entry_path)?;
                    std::io::copy(&mut f, zip)?;
                }
            }

            Ok(())
        }

        add_dir_to_zip(&mut zip, &payload_dir, &self.stage_dir, &options)?;
        zip.finish()?;

        Ok(zip_file_path)
    }

    pub fn remove_package_stage(self) {
        let _ = fs::remove_dir_all(&self.stage_dir);
    }
}

macro_rules! get_plist_dict_value {
    ($self:ident, $key:expr) => {{
        $self
            .info_plist_dictionary
            .get($key)
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
    }};
}

impl PlistInfoTrait for Package {
    fn get_name(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleDisplayName")
            .or_else(|| get_plist_dict_value!(self, "CFBundleName"))
            .or_else(|| self.get_executable())
    }

    fn get_executable(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleExecutable")
    }

    fn get_bundle_identifier(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleIdentifier")
    }

    fn get_bundle_name(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleName")
    }

    fn get_version(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleShortVersionString")
    }

    fn get_build_version(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleVersion")
    }
}

impl Package {
    pub fn load_into_signer_options<'settings, 'slf: 'settings>(
        &'slf self,
        settings: &'settings mut SignerOptions,
    ) {
        let app = if self
            .archive_entries
            .iter()
            .any(|entry| entry.contains("SideStoreApp.framework"))
        {
            SignerApp::LiveContainerAndSideStore
        } else {
            SignerApp::from_bundle_identifier(self.get_bundle_identifier().as_deref())
        };

        let new_settings = SignerOptions::new_for_app(app);
        *settings = new_settings;
    }
}
