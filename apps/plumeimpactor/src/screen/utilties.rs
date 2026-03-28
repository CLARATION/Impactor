use iced::widget::{button, column, container, row, rule, scrollable, text, toggler};
use iced::{Center, Color, Element, Task};

use crate::appearance;
use plume_utils::{Device, SignerAppReal};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct StatusMessage {
    text: String,
    is_error: bool,
}

impl StatusMessage {
    fn success(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }

    fn color(&self) -> Color {
        if self.is_error {
            Color::from_rgb(0.9, 0.2, 0.2)
        } else {
            Color::from_rgb(0.2, 0.8, 0.4)
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    RefreshApps(bool),
    AppsLoaded(Result<Vec<SignerAppReal>, String>),
    InstallPairingFile(SignerAppReal),
    Trust,
    PairResult(Result<(), String>),
    InstallPairingResult(String, Result<(), String>),
    ToggleRPPairing(bool),
}

#[derive(Debug, Clone)]
pub struct UtilitiesScreen {
    device: Option<Device>,
    installed_apps: Vec<SignerAppReal>,
    status_message: Option<StatusMessage>,
    app_statuses: HashMap<String, StatusMessage>,
    loading: bool,
    trust_loading: bool,
    pub rppairing_enabled: bool,
}

impl UtilitiesScreen {
    pub fn new(device: Option<Device>) -> Self {
        let mut screen = Self {
            device,
            installed_apps: Vec::new(),
            status_message: None,
            app_statuses: HashMap::new(),
            loading: false,
            trust_loading: false,
            rppairing_enabled: false,
        };

        if screen.device.as_ref().map(|d| d.is_mac).unwrap_or(false) {
            screen.status_message = Some(StatusMessage::error("macOS devices are not supported"));
        }

        screen
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::RefreshApps(supports_remote_pairing) => {
                self.loading = true;
                self.status_message = None;
                self.app_statuses.clear();
                if let Some(device) = &self.device {
                    if device.is_mac {
                        return Task::none();
                    }

                    let device = device.clone();
                    let (tx, rx) = std::sync::mpsc::sync_channel(1);

                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        let result = rt.block_on(async move {
                            device
                                .installed_apps(supports_remote_pairing)
                                .await
                                .map_err(|e| format!("Failed to load apps: {}", e))
                        });
                        let _ = tx.send(result);
                    });

                    Task::perform(
                        async move {
                            std::thread::spawn(move || {
                                rx.recv()
                                    .unwrap_or_else(|_| Err("Failed to receive result".to_string()))
                            })
                            .join()
                            .unwrap()
                        },
                        Message::AppsLoaded,
                    )
                } else {
                    Task::done(Message::AppsLoaded(Err("No device connected".to_string())))
                }
            }
            Message::AppsLoaded(result) => {
                self.loading = false;
                match result {
                    Ok(apps) => {
                        self.installed_apps = apps;
                        self.status_message = None;
                    }
                    Err(e) => {
                        self.status_message = Some(StatusMessage::error(e));
                        self.installed_apps.clear();
                    }
                }
                Task::none()
            }
            Message::InstallPairingFile(app) => {
                if let Some(device) = &self.device {
                    let device = device.clone();
                    let bundle_id = app.bundle_id.clone().unwrap_or_default();
                    let pairing_path = app.app.pairing_file_path().unwrap_or_default();
                    let app_key = Self::app_key(&app);
                    let (tx, rx) = std::sync::mpsc::sync_channel(1);

                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        let result = rt.block_on(async move {
                            device
                                .install_pairing_record(&bundle_id, &pairing_path)
                                .await
                                .map_err(|e| format!("Failed to install pairing record: {}", e))
                        });
                        let _ = tx.send(result);
                    });

                    Task::perform(
                        async move {
                            std::thread::spawn(move || {
                                rx.recv()
                                    .unwrap_or_else(|_| Err("Failed to receive result".to_string()))
                            })
                            .join()
                            .unwrap()
                        },
                        move |result| Message::InstallPairingResult(app_key, result),
                    )
                } else {
                    Task::none()
                }
            }
            Message::Trust => {
                self.trust_loading = true;
                self.status_message = None;
                if let Some(device) = &self.device {
                    let device = device.clone();
                    let (tx, rx) = std::sync::mpsc::sync_channel(1);

                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        let result = rt.block_on(async move {
                            device
                                .pair()
                                .await
                                .map_err(|e| format!("Failed to pair: {}", e))
                        });
                        let _ = tx.send(result);
                    });

                    Task::perform(
                        async move {
                            std::thread::spawn(move || {
                                rx.recv()
                                    .unwrap_or_else(|_| Err("Failed to receive result".to_string()))
                            })
                            .join()
                            .unwrap()
                        },
                        Message::PairResult,
                    )
                } else {
                    Task::none()
                }
            }
            Message::PairResult(result) => {
                self.trust_loading = false;
                match result {
                    Ok(_) => {
                        self.status_message =
                            Some(StatusMessage::success("Device paired successfully!"));
                    }
                    Err(e) => {
                        self.status_message = Some(StatusMessage::error(e));
                    }
                }
                Task::none()
            }
            Message::InstallPairingResult(app_key, result) => {
                let status = match result {
                    Ok(_) => StatusMessage::success("Pairing file installed successfully!"),
                    Err(e) => StatusMessage::error(e),
                };
                self.app_statuses.insert(app_key, status);
                Task::none()
            }
            Message::ToggleRPPairing(enabled) => {
                self.rppairing_enabled = enabled;
                Task::perform(async move { Message::RefreshApps(enabled) }, |msg| msg)
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let mut content = column![].spacing(appearance::THEME_PADDING);

        if let Some(ref device) = self.device {
            content = content.push(
                column![
                    text(format!("Name: {}", device.name)),
                    text(format!("UDID: {}", device.udid)),
                ]
                .spacing(4),
            );
        } else {
            content =
                content.push(text("No device connected").color(Color::from_rgb(0.7, 0.7, 0.7)));
        }

        if let Some(ref status) = self.status_message {
            content = content.push(text(&status.text).size(14).color(status.color()));
        }

        if self.device.is_some() && !self.device.as_ref().unwrap().is_mac {
            let refresh_button_text = if self.loading {
                "Loading..."
            } else {
                "Refresh Installed Apps"
            };

            let trust_button_text = if self.trust_loading {
                "Pairing..."
            } else {
                "Trust Device"
            };

            content = content.push(
                row![
                    button(text(trust_button_text).align_x(Center))
                        .on_press_maybe(if self.trust_loading {
                            None
                        } else {
                            Some(Message::Trust)
                        })
                        .style(appearance::s_button)
                        .width(iced::Length::Fill),
                    button(text(refresh_button_text).align_x(Center))
                        .on_press_maybe(if self.loading {
                            None
                        } else {
                            Some(Message::RefreshApps(self.rppairing_enabled))
                        })
                        .style(appearance::s_button)
                        .width(iced::Length::Fill),
                ]
                .spacing(appearance::THEME_PADDING),
            );
        }

        let toggle = toggler(self.rppairing_enabled)
            .label("Use Remote Pairing")
            .on_toggle(Message::ToggleRPPairing);

        content = content.push(toggle);

        if !self.installed_apps.is_empty() {
            content = content
                .push(container(rule::horizontal(1)).padding([appearance::THEME_PADDING, 0.0]));

            let mut apps_list = column![].spacing(4);

            for app in &self.installed_apps {
                let app_key = Self::app_key(app);
                let mut app_row = column![
                    row![
                        text(format!(
                            "{} ({})",
                            app.app.to_string(),
                            app.bundle_id.clone().unwrap_or("???".to_string())
                        ))
                        .size(14)
                        .width(iced::Length::Fill),
                        button(text("Install Pairing").align_x(Center))
                            .on_press(Message::InstallPairingFile(app.clone()))
                            .style(appearance::s_button)
                    ]
                    .spacing(appearance::THEME_PADDING)
                    .align_y(Center)
                ]
                .spacing(4);

                if let Some(status) = self.app_statuses.get(&app_key) {
                    app_row = app_row.push(text(&status.text).size(13).color(status.color()));
                }

                apps_list = apps_list.push(app_row);
            }

            content = content.push(apps_list);
        }

        container(scrollable(content)).into()
    }

    fn app_key(app: &SignerAppReal) -> String {
        app.bundle_id.clone().unwrap_or_else(|| app.app.to_string())
    }
}
