pub mod caps;
pub mod clipboard;
pub mod connect_orb;
pub mod connection;
pub mod ctxmenu;
pub mod daemon;
pub mod db;
pub mod dragselect;
pub mod effects;
pub mod elevate;
pub mod finder;
pub mod imageview;
pub mod interaction;
pub mod keymap;
pub mod manual_profile;
pub mod modal;
pub mod modal_anim;
pub mod ping;
pub mod qr;
pub mod scroll;
pub mod scrollbar;
pub mod sharelink;
pub mod subscription;
pub mod sysproxy;
pub mod theme;
pub mod toast;
pub mod ui;
pub mod ui_activity;
mod ui_modal;
mod ui_settings;
pub mod update;
pub mod usage;

#[derive(Debug, Clone)]
pub struct InlineRename {
    pub config_id: i64,
    pub buffer: String,
    pub cursor: usize,
    pub select_all: bool,
}
