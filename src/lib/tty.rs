use std::env;
use std::option::Option::Some;

use libc::ioctl;
use nix::unistd::isatty;

fn convert_env_var_to_u32(key: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(env::var(key)?.parse::<u32>()?)
}

/// Quick and dirty query size of terminal, doesn't do ANSI probe fallback.
/// set x=80 y=25 before calling to provide defaults. Returns false if couldn't
/// determine size.
pub fn terminal_size(xx: Option<&mut u32>, yy: Option<&mut u32>) -> bool {
    // stdin, stdout, stderr
    let mut x = 0u32;
    let mut y = 0u32;
    for i in 0..3 {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if isatty(i).unwrap_or(false) && unsafe { ioctl(i, libc::TIOCGWINSZ, &mut ws) } == 0 {
            if ws.ws_col != 0 {
                x = ws.ws_col as u32
            };
            if ws.ws_row != 0 {
                y = ws.ws_row as u32
            };
            break;
        }
    }
    if let Ok(columns) = convert_env_var_to_u32("COLUMNS") {
        x = columns;
    }
    if let Ok(lines) = convert_env_var_to_u32("LINES") {
        y = lines;
    }

    // Never return 0 for either value, leave it at default instead.
    if x != 0 {
        if let Some(xx) = xx {
            *xx = x;
        }
    }
    if y != 0 {
        if let Some(yy) = yy {
            *yy = y;
        }
    }

    x != 0 || y != 0
}
