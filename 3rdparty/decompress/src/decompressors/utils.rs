pub fn normalize_mode(mode: u32) -> u32 {
    if mode == 0 {
        0o644
    } else {
        mode
    }
}
