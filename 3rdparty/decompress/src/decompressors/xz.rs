use crate::{DecompressError, Decompression, Decompressor, ExtractOpts, Listing};
use lazy_static::lazy_static;
use regex::Regex;
use std::{fs, fs::File, io, io::BufReader, path::Path};

lazy_static! {
    static ref RE: Regex = Regex::new(r"(?i)\.xz$").unwrap();
}

#[derive(Default)]
pub struct Xz {
    re: Option<Regex>,
}

impl Xz {
    #[must_use]
    pub fn new(re: Option<Regex>) -> Self {
        Self { re }
    }
    #[must_use]
    pub fn build(re: Option<Regex>) -> Box<Self> {
        Box::new(Self::new(re))
    }
}

impl Decompressor for Xz {
    fn test_mimetype(&self, archive: &str) -> bool {
        archive == "application/x-xz"
    }

    fn test(&self, archive: &Path) -> bool {
        archive
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .map_or(false, |f| self.re.as_ref().unwrap_or(&*RE).is_match(f))
    }

    fn list(&self, archive: &Path) -> Result<Listing, DecompressError> {
        Ok(Listing {
            id: "xz",
            entries: vec![archive
                .file_stem()
                .ok_or_else(|| DecompressError::Error("cannot compose a file name".into()))?
                .to_string_lossy()
                .to_string()],
        })
    }

    fn decompress(
        &self,
        archive: &Path,
        to: &Path,
        _opts: &ExtractOpts,
    ) -> Result<Decompression, DecompressError> {
        let fd = BufReader::new(File::open(archive)?);
        let dec = xz2::bufread::XzDecoder::new(fd);
        if !Path::new(to).exists() {
            let _res = fs::create_dir_all(to);
        }
        let target = to.join(
            archive
                .file_stem()
                .ok_or_else(|| DecompressError::Error("cannot compose a file name".to_string()))?,
        );
        let mut outfile = fs::File::create(&target)?;

        io::copy(&mut BufReader::new(dec), &mut outfile)?;
        Ok(Decompression {
            id: "xz",
            files: vec![target.to_string_lossy().to_string()],
        })
    }
}
