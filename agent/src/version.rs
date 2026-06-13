pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_DATE: &str = match option_env!("JANUS_BUILD_DATE") {
    Some(value) => value,
    None => "dev",
};
pub const BUILD_SEQUENCE: &str = match option_env!("JANUS_BUILD_SEQUENCE") {
    Some(value) => value,
    None => "0",
};

pub fn full() -> String {
    if BUILD_DATE == "dev" {
        format!("{VERSION}+dev")
    } else {
        format!("{VERSION}+{BUILD_DATE}.{BUILD_SEQUENCE}")
    }
}
