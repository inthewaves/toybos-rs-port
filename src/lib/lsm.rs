use std::path::Path;

#[cfg(feature = "selinux")]
#[inline(always)]
pub fn lsm_get_context(filename: &Path) -> Option<String> {
    // Note: Although Toybox also returns the integer return value from getfilecon, it's not checked
    // anywhere in ls. Also, the selinux crate doesn't expose its raw value.
    Some(
        selinux::SecurityContext::of_path(&filename, true, false)
            .ok()??
            .to_c_string()
            .ok()??
            .to_string_lossy()
            .to_string(),
    )
}

#[cfg(not(feature = "selinux"))]
#[inline(always)]
pub fn lsm_get_context(_filename: &Path) -> Option<String> {
    None
}

#[cfg(feature = "selinux")]
#[inline(always)]
pub fn lsm_lget_context(filename: &Path) -> Option<String> {
    // Note: Although Toybox also returns the integer return value from lgetfilecon, it's not
    // checked anywhere in ls. Also, the selinux crate doesn't expose its raw value.
    Some(
        selinux::SecurityContext::of_path(&filename, false, false)
            .ok()??
            .to_c_string()
            .ok()??
            .to_string_lossy()
            .to_string(),
    )
}

#[cfg(not(feature = "selinux"))]
#[inline(always)]
pub fn lsm_lget_context(_filename: &Path) -> Option<String> {
    None
}
