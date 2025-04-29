use colored::CustomColor;
use std::sync::{LazyLock, Mutex};

pub static TERMINAL_THEME: LazyLock<termbg::Theme> = LazyLock::new(|| {
    termbg::theme(std::time::Duration::from_millis(10)).unwrap_or(termbg::Theme::Dark)
});

pub static PAGES_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((0, 169, 233), (0, 169, 223)));
pub static GENERAL_TEXT_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((64, 64, 64), (160, 160, 160)));
pub static PID_BACKGROUND_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((146, 146, 168), (0, 0, 0)));
pub static PID_NUMBER_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((0, 0, 140), (0, 173, 216)));
pub static EXITED_BACKGROUND_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((250, 160, 160), (100, 0, 0)));
pub static OUR_YELLOW: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((112, 127, 35), (187, 142, 35)));
pub static CONTINUED_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((188, 210, 230), (17, 38, 21)));
pub static STOPPED_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((82, 138, 174), (47, 86, 54)));
// TODO!
// find a good alternate color for light mode terminals
pub static PARTITION_1_COLOR: LazyLock<CustomColor> =
    LazyLock::new(|| from_terminal_theme((112, 127, 35), (186, 171, 35)));
pub static PARTITION_2_COLOR: LazyLock<[CustomColor; 3]> =
    LazyLock::new(|| match *TERMINAL_THEME {
        termbg::Theme::Light => [CustomColor::new(0, 169, 223), CustomColor::new(0, 169, 223), CustomColor::new(0, 169, 223)],
        termbg::Theme::Dark => [CustomColor::new(0, 169, 233), CustomColor::new(92, 92, 255), CustomColor::new(0, 218, 233)],
    });
pub static PATHLIKE_ALTERNATOR: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

fn from_terminal_theme(
    (light_R, light_G, light_B): (u8, u8, u8),
    (dark_R, dark_G, dark_B): (u8, u8, u8),
) -> CustomColor {
    match *TERMINAL_THEME {
        termbg::Theme::Light => CustomColor::new(light_R, light_G, light_B),
        termbg::Theme::Dark => CustomColor::new(dark_R, dark_G, dark_B),
    }
}

pub fn switch_pathlike_color() {
    let prev = *PATHLIKE_ALTERNATOR.lock().unwrap();
    *PATHLIKE_ALTERNATOR.lock().unwrap() = (prev + 1) % 3;
}
