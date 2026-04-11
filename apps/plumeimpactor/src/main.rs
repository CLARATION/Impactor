#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

rust_i18n::i18n!("../../locales", fallback = "en");

use crate::refresh::spawn_refresh_daemon;

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use single_instance::SingleInstance;

mod appearance;
mod certificate_reset;
mod defaults;
mod macos_app;
mod refresh;
mod relaunch;
mod screen;
mod startup;
mod subscriptions;
mod tray;

pub const APP_NAME: &str = "Impactor";
pub const APP_NAME_VERSIONED: &str = concat!("Impactor", " - Version ", env!("CARGO_PKG_VERSION"));

fn main() -> iced::Result {
    env_logger::init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let _single_instance = match SingleInstance::new(&crate::relaunch::single_instance_key()) {
        Ok(instance) => {
            if !instance.is_single() {
                if let Err(err) = crate::relaunch::notify_running_instance() {
                    log::warn!("Failed to signal existing instance: {err}");
                }
                log::info!("Another instance is already running; exiting.");
                return Ok(());
            }
            Some(instance)
        }
        Err(err) => {
            log::warn!("Failed to acquire single-instance lock: {err}");
            None
        }
    };

    // For tray on linux.
    #[cfg(target_os = "linux")]
    {
        gtk::init().expect("GTK init failed");
    }

    // For notifications on macOS.
    #[cfg(target_os = "macos")]
    {
        notify_rust::get_bundle_identifier_or_default("Impactor");
        notify_rust::set_application("dev.khcrysalis.PlumeImpactor").ok();
    }

    let (_daemon_handle, connected_devices) = spawn_refresh_daemon();
    screen::set_refresh_daemon_devices(connected_devices);

    // We're going to try and try running the iced_daemon with different
    // environment variables so it can run properly
    // RE: https://github.com/claration/Impactor/issues/103, https://github.com/claration/Impactor/issues/90
    #[cfg(target_os = "linux")]
    check_gpu();

    run_daemon()
}

#[cfg(target_os = "linux")]
fn check_gpu() {
    let instance = wgpu::Instance::default();

    let adapter =
        iced::futures::executor::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: None,
            force_fallback_adapter: false,
        }));

    match adapter {
        Ok(adapter) => {
            if !adapter.features().contains(wgpu::Features::SHADER_F16) {
                log::warn!("No FP16 support, falling back to tiny-skia");
                unsafe {
                    std::env::set_var("ICED_BACKEND", "tiny-skia");
                }
            }
        }
        Err(e) => {
            log::warn!("No adapter found: {e}, falling back to tiny-skia");
            unsafe {
                std::env::set_var("ICED_BACKEND", "tiny-skia");
            }
        }
    }
}

fn run_daemon() -> iced::Result {
    iced::daemon(
        screen::Impactor::new,
        screen::Impactor::update,
        screen::Impactor::view,
    )
    .subscription(screen::Impactor::subscription)
    .title(APP_NAME_VERSIONED)
    .theme(appearance::PlumeTheme::default().to_iced_theme())
    .settings(defaults::default_settings())
    .run()
}
