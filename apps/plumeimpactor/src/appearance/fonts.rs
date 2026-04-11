use iced::widget::{Row, Text};
use iced::{Alignment::Center, Font, Length::Fixed, font};
use iced::{Color, Element};

use super::THEME_ICON_SIZE;

pub(crate) fn load_fonts() -> Vec<std::borrow::Cow<'static, [u8]>> {
    vec![
        include_bytes!("./plume_icons.ttf").as_slice().into(),
        include_bytes!("./Hack-Regular.ttf").as_slice().into(),
    ]
}

pub(crate) const GEAR: &str = "\u{e800}";
pub(crate) const CHEVRON_BACK: &str = "\u{e801}";
pub(crate) const DOWNLOAD: &str = "\u{e802}";
pub(crate) const STAR: &str = "\u{e803}";
pub(crate) const WRENCH: &str = "\u{e804}";
pub(crate) const PLUS: &str = "\u{e805}";
pub(crate) const MINUS: &str = "\u{e806}";
pub(crate) const SHARE: &str = "\u{e807}";
pub(crate) const FILE: &str = "\u{f15b}";

pub(crate) fn icon_text<M: 'static>(
    icon: &'static str,
    label: std::borrow::Cow<'_, str>,
    color: Option<Color>,
) -> Element<'static, M> {
    let icon_font = Font {
        family: iced::font::Family::Name("plume_icons".into()),
        weight: iced::font::Weight::Normal,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };

    let mut row = Row::new().spacing(10).align_y(Center);

    let mut icon_text_widget = Text::new(icon)
        .font(icon_font)
        .width(Fixed(THEME_ICON_SIZE));
    if let Some(c) = color {
        icon_text_widget = icon_text_widget.color(c);
    }
    row = row.push(icon_text_widget);
    let str = label.to_string();

    let mut label_widget = Text::new(str);
    if let Some(c) = color {
        label_widget = label_widget.color(c);
    }
    row = row.push(label_widget);

    row.into()
}

pub(crate) fn icon(icon: &'static str) -> Text<'static> {
    let icon_font = Font {
        family: font::Family::Name("plume_icons".into()),
        weight: font::Weight::Normal,
        stretch: font::Stretch::Normal,
        style: font::Style::Normal,
    };

    Text::new(icon)
        .font(icon_font)
        .align_x(Center)
        .width(Fixed(THEME_ICON_SIZE))
}
