/// Target of a log message, for filtering.
pub mod targets {
    pub const ALL: &str = "all";
    pub const MAIN: &str = "main";
    pub const HTADMIN: &str = "htadmin";

    pub const ALL_TARGETS: &[&str] = &[ALL, MAIN, HTADMIN];
}
