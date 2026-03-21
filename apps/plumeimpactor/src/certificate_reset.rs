use std::sync::{Mutex, OnceLock, mpsc};

pub(crate) const WARNING: &str = "Impactor needs to reset your certificate. This breaks existing SideStore and AltStore installs.";

#[derive(Debug, Clone)]
pub struct ConfirmationRequest {
    pub message: String,
    responder: mpsc::Sender<bool>,
}

impl ConfirmationRequest {
    pub fn respond(&self, accepted: bool) {
        let _ = self.responder.send(accepted);
    }
}

static REQUEST_TX: OnceLock<mpsc::Sender<ConfirmationRequest>> = OnceLock::new();
static REQUEST_RX: OnceLock<Mutex<mpsc::Receiver<ConfirmationRequest>>> = OnceLock::new();

fn request_channel() -> (
    &'static mpsc::Sender<ConfirmationRequest>,
    &'static Mutex<mpsc::Receiver<ConfirmationRequest>>,
) {
    REQUEST_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        let _ = REQUEST_RX.set(Mutex::new(rx));
        tx
    });

    (
        REQUEST_TX
            .get()
            .expect("request sender should be initialized"),
        REQUEST_RX
            .get()
            .expect("request receiver should be initialized"),
    )
}

pub fn request_confirmation(message: &str) -> bool {
    let (response_tx, response_rx) = mpsc::channel();
    let request = ConfirmationRequest {
        message: message.to_string(),
        responder: response_tx,
    };

    let (request_tx, _) = request_channel();
    if request_tx.send(request).is_err() {
        return false;
    }

    response_rx.recv().unwrap_or(false)
}

pub fn confirm() -> bool {
    log::warn!("{WARNING}");
    request_confirmation(WARNING)
}

pub fn wait_for_request() -> Option<ConfirmationRequest> {
    let (_, request_rx) = request_channel();
    request_rx.lock().ok()?.recv().ok()
}
