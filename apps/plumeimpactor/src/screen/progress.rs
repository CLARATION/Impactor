use std::sync::{Arc, Mutex, mpsc};

use iced::Element;
use iced::Length::Fill;
use iced::Task;
use iced::widget::{button, column, container, row, text};
use rust_i18n::t;

use crate::appearance;

type ProgressReceiver = Arc<Mutex<mpsc::Receiver<(String, i32)>>>;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Message {
    InstallationProgress(String, i32),
    InstallationError(String),
    InstallationFinished,
    Back,
}

#[derive(Debug, Clone)]
pub struct ProgressScreen {
    pub status: String,
    pub progress: i32,
    pub is_installing: bool,
    pub progress_rx: Option<ProgressReceiver>,
}

impl ProgressScreen {
    pub fn new() -> Self {
        Self {
            status: "Idle.".to_string(),
            progress: 0,
            is_installing: false,
            progress_rx: None,
        }
    }

    pub fn start_installation(&mut self, rx: ProgressReceiver) {
        self.is_installing = true;
        self.progress = 0;
        self.status = "Idle.".to_string();
        self.progress_rx = Some(rx);
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::InstallationProgress(status, progress) => {
                self.status = status.clone();
                self.progress = progress;

                if progress == -1 {
                    self.progress_rx = None;
                    self.is_installing = false;

                    let error_msg = status.clone();
                    std::thread::spawn(move || {
                        rfd::MessageDialog::new()
                            .set_title(t!("progress_failed"))
                            .set_description(&error_msg)
                            .set_buttons(rfd::MessageButtons::Ok)
                            .show();
                    });
                } else if progress >= 100 {
                    self.progress_rx = None;
                    self.is_installing = false;

                    return Task::done(Message::InstallationFinished);
                }

                Task::none()
            }
            Message::InstallationError(error) => {
                self.progress = -1;
                self.status = format!("ERR: {}", error);
                self.progress_rx = None;
                self.is_installing = false;

                std::thread::spawn(move || {
                    rfd::MessageDialog::new()
                        .set_title(t!("progress_failed"))
                        .set_description(&error)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                });

                Task::none()
            }
            Message::InstallationFinished => {
                self.progress = 100;
                self.status = t!("progress_finished").to_string();
                self.progress_rx = None;
                self.is_installing = false;

                Task::none()
            }
            Message::Back => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let progress_bar = iced::widget::progress_bar(0.0..=100.0, self.progress as f32);

        let screen_content = column![
            text(t!("progress_installing_application")).size(14),
            text(format!("{}% – {}", self.progress, self.status)).size(14),
            progress_bar,
            container(text("")).height(Fill),
        ]
        .spacing(appearance::THEME_PADDING);

        column![
            container(screen_content).width(Fill).height(Fill),
            self.view_buttons()
        ]
        .into()
    }

    fn view_buttons(&self) -> Element<'_, Message> {
        container(row![
            button(appearance::icon_text(
                appearance::CHEVRON_BACK,
                t!("back"),
                None
            ))
            .on_press_maybe((!self.is_installing).then_some(Message::Back))
            .width(Fill)
            .style(appearance::s_button)
        ])
        .width(Fill)
        .into()
    }
}

impl Default for ProgressScreen {
    fn default() -> Self {
        Self::new()
    }
}
