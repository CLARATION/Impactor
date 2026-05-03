#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_name_repetitions)]
pub mod decompressors;

use derive_builder::Builder;
use std::borrow::Cow;
use std::{convert::Infallible, io, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecompressError {
    #[error("could not decompress: `{0}`")]
    IO(#[from] io::Error),

    #[error("could not decompress: `{0}`")]
    Error(String),

    #[error("could not decompress: `{0}`")]
    Infallible(#[from] Infallible),

    #[error("no compressor found")]
    MissingCompressor,
}

pub type FilterFn = dyn Fn(&Path) -> bool;
pub type MapFn = dyn Fn(&Path) -> Cow<'_, Path>;

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct ExtractOpts {
    #[builder(default)]
    pub detect_content: bool,

    #[builder(default)]
    pub strip: usize,

    #[builder(setter(custom), default = "Box::new(|_| true)")]
    pub filter: Box<FilterFn>,

    #[builder(setter(custom), default = "Box::new(|path| Cow::from(path))")]
    pub map: Box<MapFn>,
}

impl ExtractOptsBuilder {
    /// Given a predicate, filter a path in.
    #[must_use]
    pub fn filter(mut self, value: impl Fn(&Path) -> bool + 'static) -> Self {
        self.filter = Some(Box::new(value));
        self
    }
    /// Given a mapping function, transform a path into a different or similar path
    #[must_use]
    pub fn map(mut self, value: impl Fn(&Path) -> Cow<'_, Path> + 'static) -> Self {
        self.map = Some(Box::new(value));
        self
    }
}

#[derive(Debug)]
pub struct Decompression {
    pub id: &'static str,
    pub files: Vec<String>,
}

#[derive(Debug)]
pub struct Listing {
    pub id: &'static str,
    pub entries: Vec<String>,
}

///
/// `Decompressor` is a trait that you can implement to add your own decompressor type.
/// A `Decompressor` is inserted into a stack, where given a potential archive file,
/// many decompressors may attempt to test if they're capable of unpacking it.
/// The first `Decompressor` which will test true will be the one selected to unpack.
///
/// It is _recommended_ to let a user pick a regex for testing against a `Path`, although
/// there is no limit to what you can do, as long as a user can override the Decompressor
/// decision when building a custom stack.
///
pub trait Decompressor {
    ///
    /// Test if this `Decompressor` can unpack an archive, given a mimetype.
    fn test_mimetype(&self, mimetype: &str) -> bool;

    ///
    /// Test if this `Decompressor` can unpack an archive, given a path.
    /// The convention is to use `Regex` internally to test a path, because this is
    /// a convenient way for end users to override the behavior.
    /// You may choose to implement a different, but configurable, testing strategy.
    fn test(&self, archive: &Path) -> bool;

    ///
    /// List an archive
    ///
    /// # Errors
    ///
    /// This function will return an error if unpacking fails.
    fn list(&self, archive: &Path) -> Result<Listing, DecompressError>;

    ///
    /// Decompress an archive
    ///
    /// # Errors
    ///
    /// This function will return an error if unpacking fails.
    fn decompress(
        &self,
        archive: &Path,
        to: &Path,
        opts: &ExtractOpts,
    ) -> Result<Decompression, DecompressError>;
}

///
/// Represent a stack of decompressors with a default stack preconfigured when calling `new`
///
pub struct Decompress {
    decompressors: Vec<Box<dyn Decompressor>>,
}

impl Default for Decompress {
    fn default() -> Self {
        Self {
            decompressors: vec![
                Box::<decompressors::zip::Zip>::default(),
                Box::<decompressors::targz::Targz>::default(),
                Box::<decompressors::tarball::Tarball>::default(),
                Box::<decompressors::tarxz::Tarxz>::default(),
                Box::<decompressors::tarbz::Tarbz>::default(),
                Box::<decompressors::tarzst::Tarzst>::default(),
                Box::<decompressors::tarlzma::Tarlzma>::default(),
                // order is important, `gz` is placed only after the targz variant did not match
                // if it's placed above targz, it will unpack and leave a tar archive.
                Box::<decompressors::gz::Gz>::default(),
                Box::<decompressors::ar::Ar>::default(),
                Box::<decompressors::bz2::Bz2>::default(),
                Box::<decompressors::xz::Xz>::default(),
                Box::<decompressors::lzma::Lzma>::default(),
                Box::<decompressors::zstd::Zstd>::default(),
            ],
        }
    }
}

impl Decompress {
    /// Find a decompressor from the stack
    ///
    /// # Errors
    ///
    /// This function will return an error if IO fails
    #[allow(clippy::borrowed_box)]
    pub fn find_decompressor<P: AsRef<Path>>(
        &self,
        archive: P,
        detect_content: bool,
    ) -> Result<&Box<dyn Decompressor>, DecompressError> {
        if detect_content {
            let res = infer::get_from_path(archive.as_ref())?;
            let mt = res.map(|t| t.mime_type());
            mt.and_then(|mt| self.decompressors.iter().find(|dec| dec.test_mimetype(mt)))
        } else {
            println!("f: {:?} ", archive.as_ref());
            self.decompressors
                .iter()
                .find(|dec| dec.test(archive.as_ref()))
        }
        .ok_or(DecompressError::MissingCompressor)
    }

    /// Build given a custom stack of decompressors
    #[must_use]
    pub fn build(decompressors: Vec<Box<dyn Decompressor>>) -> Self {
        Self { decompressors }
    }

    /// List
    ///
    /// # Errors
    ///
    /// This function will return an error if an IO or parsing error happened
    pub fn list<P: AsRef<Path>>(
        &self,
        archive: P,
        opts: &ExtractOpts,
    ) -> Result<Listing, DecompressError> {
        self.find_decompressor(archive.as_ref(), opts.detect_content)
            .and_then(|dec| dec.list(archive.as_ref()))
    }

    /// Decompress with a decompressor that is selected based on file name (cheaper)
    ///
    /// # Errors
    ///
    /// This function will return an error if an IO or parsing error happened
    pub fn decompress<P: AsRef<Path>>(
        &self,
        archive: P,
        to: P,
        opts: &ExtractOpts,
    ) -> Result<Decompression, DecompressError> {
        self.find_decompressor(archive.as_ref(), opts.detect_content)
            .and_then(|dec| dec.decompress(archive.as_ref(), to.as_ref(), opts))
    }

    /// Returns `true` if any of the decompressors in the stack can decompress this
    /// specific archive based on its content (reads first 8kb)
    ///
    /// # Errors
    /// May fail if cannot read the file
    pub fn can_decompress_content<P: AsRef<Path>>(
        &self,
        archive: P,
    ) -> Result<bool, DecompressError> {
        match self.find_decompressor(archive.as_ref(), true) {
            Ok(_) => Ok(true),
            Err(DecompressError::MissingCompressor) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if any of the decompressors in the stack can decompress this
    /// specific archive based on its path (no file opening)
    pub fn can_decompress<P: AsRef<Path>>(&self, archive: P) -> bool {
        self.find_decompressor(archive.as_ref(), false).is_ok()
    }
}

/// Decompress an archive with default decompressor set up
///
/// # Errors
///
/// This function will return an error if IO or parsing failed
pub fn decompress<P: AsRef<Path>>(
    archive: P,
    to: P,
    opts: &ExtractOpts,
) -> Result<Decompression, DecompressError> {
    Decompress::default().decompress(archive, to, opts)
}

/// List an archive with default decompressor set up
///
/// # Errors
///
/// This function will return an error if IO or parsing failed
pub fn list<P: AsRef<Path>>(archive: P, opts: &ExtractOpts) -> Result<Listing, DecompressError> {
    Decompress::default().list(archive, opts)
}

/// Returns `true` if any of the decompressors in the stack can decompress this
/// specific archive based on its path (no file opening)
pub fn can_decompress<P: AsRef<Path>>(archive: P) -> bool {
    Decompress::default().can_decompress(archive)
}

/// Returns `true` if any of the decompressors in the stack can decompress this
/// specific archive based on its content (reads first 8kb)
///
/// # Errors
/// May fail if cannot read the file
pub fn can_decompress_content<P: AsRef<Path>>(archive: P) -> Result<bool, DecompressError> {
    Decompress::default().can_decompress_content(archive)
}
