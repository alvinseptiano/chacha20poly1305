use std::collections::HashSet;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

pub struct MyContext {
    pub key: String,
    pub nonce: String,
    pub file_path: Option<String>,
    pub output_message: Arc<Mutex<String>>,
    pub ciphertext: Arc<Mutex<String>>,
    pub is_processing: bool,
    pub tx: Option<Sender<Vec<String>>>,
    pub rx: Option<Receiver<Vec<String>>>,
    pub selected_algorithm: EncryptAlgorithm,
    pub operation_type: EncryptType,
    pub show_close_buttons: bool,
    pub open_tabs: HashSet<String>,
    pub expanded_tab: Option<String>,
    pub file_metada: String,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum EncryptType {
    Encryption,
    Decryption,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum EncryptAlgorithm {
    Chacha20Poly1305,
    Des,
}

impl Default for EncryptType {
    fn default() -> Self {
        EncryptType::Encryption
    }
}

impl Default for EncryptAlgorithm {
    fn default() -> Self {
        EncryptAlgorithm::Chacha20Poly1305
    }
}
