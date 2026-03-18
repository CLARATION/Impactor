use iced::futures::SinkExt;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Alignment, Element, Fill, Task, window};
use plume_core::{
    AnisetteConfiguration,
    auth::{Account, TwoFactorInput, TwoFactorMethod},
};
use plume_store::{AccountStore, GsaAccount};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};

use crate::appearance;

#[derive(Debug, Clone)]
enum TwoFactorState {
    EnterCode {
        methods: Vec<TwoFactorMethod>,
        method: TwoFactorMethod,
    },
}

#[derive(Debug, Clone)]
pub enum Message {
    EmailChanged(String),
    PasswordChanged(String),
    LoginSubmit,
    LoginCancel,
    LoginSuccess(GsaAccount),
    LoginFailed(String),
    RequestTwoFactorMethod(Vec<TwoFactorMethod>),
    RequestTwoFactorCode(TwoFactorMethod),
    UseSmsInstead,
    TwoFactorCodeChanged(String),
    TwoFactorSubmit,
    TwoFactorCancel,
}

pub struct LoginWindow {
    pub window_id: Option<window::Id>,
    email: String,
    password: String,
    two_factor_code: String,
    login_error: Option<String>,
    two_factor_error: Option<String>,
    is_logging_in: bool,
    two_factor_state: Option<TwoFactorState>,
    two_factor_tx: Option<std_mpsc::Sender<Result<TwoFactorInput, String>>>,
}

impl LoginWindow {
    pub fn new() -> (Self, Task<Message>) {
        let (id, task) = window::open(window::Settings {
            size: iced::Size::new(400.0, 300.0),
            position: window::Position::Centered,
            resizable: false,
            decorations: true,
            ..Default::default()
        });

        (
            Self {
                window_id: Some(id),
                email: String::new(),
                password: String::new(),
                two_factor_code: String::new(),
                login_error: None,
                two_factor_error: None,
                is_logging_in: false,
                two_factor_state: None,
                two_factor_tx: None,
            },
            task.discard(),
        )
    }

    pub fn window_id(&self) -> Option<window::Id> {
        self.window_id
    }

    fn default_two_factor_method(methods: &[TwoFactorMethod]) -> Option<TwoFactorMethod> {
        methods
            .iter()
            .find(|method| matches!(method, TwoFactorMethod::TrustedDevice))
            .cloned()
            .or_else(|| methods.first().cloned())
    }

    fn first_sms_method(methods: &[TwoFactorMethod]) -> Option<TwoFactorMethod> {
        methods
            .iter()
            .find(|method| matches!(method, TwoFactorMethod::Sms(_)))
            .cloned()
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::EmailChanged(email) => {
                self.email = email;
                Task::none()
            }
            Message::PasswordChanged(password) => {
                self.password = password;
                Task::none()
            }
            Message::LoginSubmit => {
                if self.email.trim().is_empty() || self.password.is_empty() {
                    self.login_error = Some("Email and password required".to_string());
                    return Task::none();
                }

                self.is_logging_in = true;
                self.two_factor_state = None;
                self.two_factor_code.clear();
                self.login_error = None;
                self.two_factor_error = None;
                let email = self.email.trim().to_string();
                let password = self.password.clone();
                self.password.clear();

                let (tx, rx) = std_mpsc::channel::<Result<TwoFactorInput, String>>();
                self.two_factor_tx = Some(tx);

                Task::run(Self::perform_login(email, password, rx), |msg| msg)
            }
            Message::RequestTwoFactorMethod(methods) => {
                self.login_error = None;
                self.two_factor_error = None;
                self.two_factor_code.clear();
                let Some(method) = Self::default_two_factor_method(&methods) else {
                    self.is_logging_in = false;
                    self.login_error =
                        Some("No two-factor verification methods are available".to_string());
                    self.two_factor_tx = None;
                    return Task::none();
                };

                self.two_factor_state = Some(TwoFactorState::EnterCode {
                    methods,
                    method: method.clone(),
                });

                if let Some(tx) = &self.two_factor_tx {
                    let _ = tx.send(Ok(TwoFactorInput::Method(method)));
                }
                self.is_logging_in = true;
                Task::none()
            }
            Message::RequestTwoFactorCode(method) => {
                self.is_logging_in = false;
                self.login_error = None;
                self.two_factor_error = None;
                let methods = match self.two_factor_state.take() {
                    Some(TwoFactorState::EnterCode { methods, .. }) => methods,
                    None => vec![method.clone()],
                };
                self.two_factor_state = Some(TwoFactorState::EnterCode { methods, method });
                self.two_factor_code.clear();
                Task::none()
            }
            Message::UseSmsInstead => {
                let sms_method = match &self.two_factor_state {
                    Some(TwoFactorState::EnterCode { methods, .. }) => {
                        Self::first_sms_method(methods)
                    }
                    None => None,
                };

                let Some(sms_method) = sms_method else {
                    self.two_factor_error = Some("No SMS method available".to_string());
                    return Task::none();
                };

                if let Some(TwoFactorState::EnterCode { method, .. }) = &mut self.two_factor_state {
                    *method = sms_method.clone();
                }

                if let Some(tx) = &self.two_factor_tx {
                    let _ = tx.send(Ok(TwoFactorInput::Method(sms_method)));
                }

                self.two_factor_code.clear();
                self.two_factor_error = None;
                self.is_logging_in = true;
                Task::none()
            }
            Message::LoginCancel => {
                if let Some(id) = self.window_id {
                    self.two_factor_tx = None;
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::LoginSuccess(account) => {
                self.login_error = None;
                let path = crate::defaults::get_data_path().join("accounts.json");

                if let Ok(mut store) = tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(async { AccountStore::load(&Some(path.clone())).await })
                {
                    let _ = store.accounts_add_sync(account);
                }

                if let Some(id) = self.window_id {
                    self.two_factor_tx = None;
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::LoginFailed(error) => {
                self.is_logging_in = false;
                self.two_factor_state = None;
                self.two_factor_code.clear();
                self.two_factor_error = None;
                self.login_error = Some(error);
                self.two_factor_tx = None;
                Task::none()
            }
            Message::TwoFactorCodeChanged(code) => {
                self.two_factor_code = code;
                self.two_factor_error = None;
                Task::none()
            }
            Message::TwoFactorSubmit => {
                let code = self.two_factor_code.trim().to_string();
                if code.is_empty() {
                    self.two_factor_error = Some("Code required".to_string());
                    return Task::none();
                }

                if let Some(tx) = &self.two_factor_tx {
                    let _ = tx.send(Ok(TwoFactorInput::Code(code)));
                }
                self.is_logging_in = true;
                Task::none()
            }
            Message::TwoFactorCancel => {
                if let Some(tx) = self.two_factor_tx.take() {
                    let _ = tx.send(Err("Cancelled".to_string()));
                }
                self.two_factor_state = None;
                if let Some(id) = self.window_id {
                    window::close(id)
                } else {
                    Task::none()
                }
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        if self.two_factor_state.is_some() {
            self.view_two_factor()
        } else {
            self.view_login()
        }
    }

    fn view_login(&self) -> Element<'_, Message> {
        let email_input = text_input("Email", &self.email)
            .on_input(Message::EmailChanged)
            .padding(8)
            .width(Fill);

        let mut password_input = text_input("Password", &self.password)
            .on_input(Message::PasswordChanged)
            .secure(true)
            .padding(8)
            .width(Fill);
        if !self.is_logging_in {
            password_input = password_input.on_submit(Message::LoginSubmit);
        }

        let mut content = column![
            text("Your Apple ID is used to sign and install apps. Credentials sent only to Apple.")
                .size(14),
            text("Email:").size(14),
            email_input,
            text("Password:").size(14),
            password_input,
        ]
        .spacing(appearance::THEME_PADDING)
        .align_x(Alignment::Start);

        if let Some(error) = &self.login_error {
            content = content.push(text(error).style(|_theme| text::Style {
                color: Some(iced::Color::from_rgb(1.0, 0.3, 0.3)),
            }));
        }

        let buttons = row![
            container(text("")).width(Fill),
            button("Cancel")
                .on_press(Message::LoginCancel)
                .style(appearance::s_button),
            button(if self.is_logging_in {
                "Logging In..."
            } else {
                "Next"
            })
            .on_press_maybe(if self.is_logging_in {
                None
            } else {
                Some(Message::LoginSubmit)
            })
            .style(appearance::p_button),
        ]
        .spacing(appearance::THEME_PADDING);

        content = content.push(container(text("")).width(Fill));
        content = content.push(buttons);

        container(content).padding(appearance::THEME_PADDING).into()
    }

    fn view_two_factor(&self) -> Element<'_, Message> {
        let mut content = column![text("Two-Factor Authentication").size(20)]
            .spacing(appearance::THEME_PADDING)
            .padding(appearance::THEME_PADDING)
            .align_x(Alignment::Start);

        let buttons = match self.two_factor_state.as_ref() {
            Some(TwoFactorState::EnterCode { methods, method }) => {
                let mut code_input = text_input("Verification Code", &self.two_factor_code)
                    .on_input(Message::TwoFactorCodeChanged)
                    .padding(8)
                    .width(Fill);
                if !self.is_logging_in {
                    code_input = code_input.on_submit(Message::TwoFactorSubmit);
                }

                content = content.push(text(method.prompt()).size(14));
                content = content.push(code_input);

                let can_use_sms = matches!(method, TwoFactorMethod::TrustedDevice)
                    && Self::first_sms_method(methods).is_some();

                let mut buttons = row![].spacing(appearance::THEME_PADDING);

                if can_use_sms {
                    buttons = buttons.push(
                        button("Use SMS")
                            .on_press_maybe(if self.is_logging_in {
                                None
                            } else {
                                Some(Message::UseSmsInstead)
                            })
                            .style(appearance::s_button)
                            .padding(8),
                    );
                }

                buttons = buttons.push(container(text("")).width(Fill));
                buttons = buttons.push(
                    button("Cancel")
                        .on_press(Message::TwoFactorCancel)
                        .style(appearance::s_button)
                        .padding(8),
                );
                buttons = buttons.push(
                    button(if self.is_logging_in {
                        "Verifying..."
                    } else {
                        "Verify"
                    })
                    .on_press_maybe(if self.is_logging_in {
                        None
                    } else {
                        Some(Message::TwoFactorSubmit)
                    })
                    .style(appearance::p_button)
                    .padding(8),
                );

                buttons
            }
            None => row![],
        };

        if let Some(error) = &self.two_factor_error {
            content = content.push(text(error).style(|_theme| text::Style {
                color: Some(iced::Color::from_rgb(1.0, 0.3, 0.3)),
            }));
        }

        content = content.push(buttons);
        container(content).padding(20).into()
    }

    fn perform_login(
        email: String,
        password: String,
        two_factor_rx: std_mpsc::Receiver<Result<TwoFactorInput, String>>,
    ) -> impl iced::futures::Stream<Item = Message> {
        iced::stream::channel(
            10,
            move |mut output: futures::channel::mpsc::Sender<Message>| async move {
                let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                let email_clone = email.clone();

                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    let anisette_config = AnisetteConfiguration::default()
                        .set_configuration_path(crate::defaults::get_data_path());
                    let two_factor_rx = Arc::new(Mutex::new(two_factor_rx));

                    let select_two_factor_method = {
                        let bridge_tx = bridge_tx.clone();
                        let two_factor_rx = Arc::clone(&two_factor_rx);
                        move |options: Vec<TwoFactorMethod>| -> Result<TwoFactorMethod, String> {
                            let _ = bridge_tx.send(Message::RequestTwoFactorMethod(options));

                            match two_factor_rx.lock().map_err(|e| e.to_string())?.recv() {
                                Ok(Ok(TwoFactorInput::Method(method))) => Ok(method),
                                Ok(Ok(TwoFactorInput::Code(_))) => {
                                    Err("Expected a 2FA method selection".to_string())
                                }
                                Ok(Err(err)) => Err(err),
                                Err(_) => Err("Two-factor authentication cancelled".to_string()),
                            }
                        }
                    };

                    let enter_two_factor_code = {
                        let bridge_tx = bridge_tx.clone();
                        let two_factor_rx = Arc::clone(&two_factor_rx);
                        move |method: &TwoFactorMethod| -> Result<TwoFactorInput, String> {
                            let _ = bridge_tx.send(Message::RequestTwoFactorCode(method.clone()));

                            match two_factor_rx.lock().map_err(|e| e.to_string())?.recv() {
                                Ok(Ok(input)) => Ok(input),
                                Ok(Err(err)) => Err(err),
                                Err(_) => Err("Two-factor authentication cancelled".to_string()),
                            }
                        }
                    };

                    let account_result = rt.block_on(Account::login_with_method_selection(
                        || Ok((email_clone.clone(), password.clone())),
                        select_two_factor_method,
                        enter_two_factor_code,
                        anisette_config,
                    ));

                    let final_msg = match account_result {
                        Ok(account) => {
                            match rt.block_on(plume_store::account_from_session(
                                email_clone.clone(),
                                account,
                            )) {
                                Ok(gsa) => Message::LoginSuccess(gsa),
                                Err(e) => Message::LoginFailed(e.to_string()),
                            }
                        }
                        Err(e) => Message::LoginFailed(e.to_string()),
                    };
                    let _ = bridge_tx.send(final_msg);
                });

                while let Some(msg) = bridge_rx.recv().await {
                    let _ = output.send(msg).await;
                }
            },
        )
    }
}
