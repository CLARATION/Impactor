use crate::decompressors::utils::normalize_mode;
use crate::{DecompressError, Decompression, Decompressor, ExtractOpts, Listing};
use ar::Archive;
use lazy_static::lazy_static;
use regex::Regex;
use std::path::{Component, PathBuf};
use std::{fs, io};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

lazy_static! {
    static ref RE: Regex = Regex::new(r"(?i)\.(ar|deb)$").unwrap();
}

fn build_archive(archive: &Path) -> Result<Archive<Box<dyn Read>>, DecompressError> {
    let fd = BufReader::new(File::open(archive)?);
    let out: Archive<Box<dyn Read>> = Archive::new(Box::new(fd));
    Ok(out)
}
#[derive(Default)]
pub struct Ar {
    re: Option<Regex>,
}

impl Ar {
    #[must_use]
    pub fn new(re: Option<Regex>) -> Self {
        Self { re }
    }
    #[must_use]
    pub fn build(re: Option<Regex>) -> Box<Self> {
        Box::new(Self::new(re))
    }
}

impl Decompressor for Ar {
    fn test_mimetype(&self, archive: &str) -> bool {
        archive == "application/x-unix-archive"
    }

    fn test(&self, archive: &Path) -> bool {
        archive
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .map_or(false, |f| self.re.as_ref().unwrap_or(&*RE).is_match(f))
    }

    fn list(&self, archive: &Path) -> Result<Listing, DecompressError> {
        let mut out = build_archive(archive)?;
        let mut entries = vec![];
        while let Some(entry) = out.next_entry() {
            let entry = entry?;
            let header = entry.header();

            let filepath = {
                #[cfg(windows)]
                {
                    PathBuf::from(String::from_utf8_lossy(header.identifier()).to_string())
                }
                #[cfg(unix)]
                {
                    use std::ffi::OsStr;
                    use std::os::unix::prelude::OsStrExt;
                    PathBuf::from(OsStr::from_bytes(header.identifier()))
                }
            };
            entries.push(filepath.to_string_lossy().to_string());
        }
        Ok(Listing { id: "ar", entries })
    }

    fn decompress(
        &self,
        archive: &Path,
        to: &Path,
        _opts: &ExtractOpts,
    ) -> Result<Decompression, DecompressError> {
        let mut out = build_archive(archive)?;
        let mut files = vec![];

        if !to.exists() {
            fs::create_dir_all(to)?;
        }

        // alternative impl: just unpack, and then mv everything back X levels
        while let Some(entry) = out.next_entry() {
            let entry = entry?;
            let header = entry.header();

            let filepath = {
                #[cfg(windows)]
                {
                    PathBuf::from(String::from_utf8_lossy(header.identifier()).to_string())
                }
                #[cfg(unix)]
                {
                    use std::ffi::OsStr;
                    use std::os::unix::prelude::OsStrExt;
                    PathBuf::from(OsStr::from_bytes(header.identifier()))
                }
            };

            if filepath.components().any(|component| match component {
                Component::ParentDir | Component::RootDir | Component::Prefix(..) => true,
                Component::Normal(..) | Component::CurDir => false,
            }) {
                continue;
            }

            // guess what, ar archives don't support components, only 1 level is there, so stripping not relevant!
            // so does create_dir_all'isms

            // because we potentially stripped a component, we may have an empty path, in which case
            // the joined target will be identical to the target folder
            // we take this approach to avoid hardcoding a check against empty ""
            let outpath = to.join(filepath);
            if to == outpath {
                continue;
            }

            #[cfg(unix)]
            let mode = entry.header().mode();

            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut BufReader::new(entry), &mut outfile)?;
            files.push(outpath.to_string_lossy().to_string());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = normalize_mode(mode);
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
        Ok(Decompression { id: "ar", files })
    }
}
