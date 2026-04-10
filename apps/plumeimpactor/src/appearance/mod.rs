use iced::{Color, Theme, color};

mod button;
mod fonts;
mod picklist;

pub(crate) use button::{p_button, s_button};
#[allow(unused)]
pub(crate) use fonts::{
    CHEVRON_BACK, DOWNLOAD, FILE, GEAR, MINUS, PLUS, SHARE, STAR, WRENCH, icon, icon_text,
    load_fonts,
};
pub(crate) use picklist::s_pick_list;

pub(crate) const THEME_CORNER_RADIUS: f32 = 4.0;
pub(crate) const THEME_FONT_SIZE: f32 = 12.0;
pub(crate) const THEME_PADDING: f32 = 9.0;
pub(crate) const THEME_ICON_SIZE: f32 = 12.0;

pub(crate) fn p_font() -> iced::Font {
    iced::Font {
        family: iced::font::Family::Name("Hack".into()),
        weight: iced::font::Weight::Normal,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlumeTheme {
    PlumeDark,
}

impl PlumeTheme {
    pub(crate) fn to_iced_theme(self) -> Theme {
        Self::plume_dark()
    }

    fn plume_dark() -> Theme {
        Theme::custom(
            "Plume Dark".to_string(),
            iced::theme::Palette {
                background: color!(0x282021),
                text: color!(0xf2d5cf),
                primary: color!(0xd3869b),
                success: color!(0xd9a6b3),
                danger: color!(0xe78a8a),
                warning: color!(0xf4b8c4),
            },
        )
    }
}

impl Default for PlumeTheme {
    fn default() -> Self {
        Self::PlumeDark
    }
}

pub(crate) fn lighten(color: Color, amount: f32) -> Color {
    Color {
        r: (color.r + amount).min(1.0),
        g: (color.g + amount).min(1.0),
        b: (color.b + amount).min(1.0),
        a: color.a,
    }
}

pub(crate) fn darken(color: Color, amount: f32) -> Color {
    Color {
        r: (color.r - amount).max(0.0),
        g: (color.g - amount).max(0.0),
        b: (color.b - amount).max(0.0),
        a: color.a,
    }
}
