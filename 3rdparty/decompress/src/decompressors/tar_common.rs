use std::borrow::Cow;
use std::{
    fs::{self},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

use crate::decompressors::utils::normalize_mode;
use crate::{DecompressError, ExtractOpts};
use tar::Archive;

pub fn tar_list(out: &mut Archive<Box<dyn Read>>) -> Result<Vec<String>, DecompressError> {
    Ok(out
        .entries()?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(tar::Entry::path)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>())
}

pub fn tar_extract(
    out: &mut Archive<Box<dyn Read>>,
    to: &Path,
    opts: &ExtractOpts,
) -> Result<Vec<String>, DecompressError> {
    let mut files = vec![];
    if !to.exists() {
        fs::create_dir_all(to)?;
    }

    // alternative impl: just unpack, and then mv everything back X levels
    for entry in out.entries()? {
        let entry = entry?;
        let filepath = entry.path()?;

        // strip prefixed components. this can be 0 parts, in which case strip does not happen.
        // it's done for when archives contain an enclosing folder
        let filepath = filepath.components().skip(opts.strip).collect::<PathBuf>();

        // because we potentially stripped a component, we may have an empty path, in which case
        // the joined target will be identical to the target folder
        // we take this approach to avoid hardcoding a check against empty ""
        let outpath = to.join(filepath);
        if to == outpath {
            continue;
        }

        if !(opts.filter)(outpath.as_path()) {
            continue;
        }

        let outpath: Cow<'_, Path> = (opts.map)(outpath.as_path());

        if entry.header().entry_type() != tar::EntryType::Directory {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }

            let mut outfile = fs::File::create(&outpath)?;

            #[cfg(unix)]
            let h = entry.header().mode();

            io::copy(&mut BufReader::new(entry), &mut outfile)?;
            files.push(outpath.to_string_lossy().to_string());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mode) = h {
                    let mode = normalize_mode(mode);
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }
    Ok(files)
}
