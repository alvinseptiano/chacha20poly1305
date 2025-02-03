#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod crypto;
mod data;
mod themes;

use crate::crypto::Crypto;
use crate::data::{EncryptAlgorithm, EncryptType};

use egui::{CentralPanel, Frame, Spinner, TopBottomPanel, Ui};
use egui_dock::{DockArea, DockState, NodeIndex, SurfaceIndex, TabViewer};
use egui_extras::{Column, TableBuilder};
use hex::encode as hex_encode;
use human_duration::human_duration;
use mime_guess::MimeGuess;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant};

fn main() -> eframe::Result {
    env_logger::init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_maximized(true)
            .with_decorations(true)
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([400.0, 100.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "Encrypt It",
        options,
        Box::new(|_cc| Ok(Box::<MyApp>::default())),
    )
}

struct MyApp {
    context: data::MyContext,
    tree: DockState<String>,
}

impl TabViewer for data::MyContext {
    type Tab = String;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.as_str().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        match tab.as_str() {
            "ChaCha20-Poly1305" => {
                self.selected_algorithm = EncryptAlgorithm::Chacha20Poly1305;
                self.chacha20poly1305(ui);
            }
            "Des" => {
                self.selected_algorithm = EncryptAlgorithm::Des;
                self.des(ui);
            }
            "Info" => {
                self.create_table(ui);
            }
            "Output" => {
                self.show_output(ui);
            }
            _ => {
                ui.label(tab.as_str());
            }
        }
    }

    fn closeable(&mut self, tab: &mut Self::Tab) -> bool {
        ["ChaCha20-Poly1305", "Des"].contains(&tab.as_str())
    }

    fn on_close(&mut self, tab: &mut Self::Tab) -> bool {
        self.open_tabs.remove(tab);
        true
    }
}

impl data::MyContext {
    fn process_file(&mut self) {
        self.is_processing = true;
        let file_path = self.file_path.clone().unwrap();
        let key = self.key.clone();
        let nonce = self.nonce.clone();
        let selected_algorithm = self.selected_algorithm;
        let tx = self.tx.clone().unwrap();
        let is_encrypt = match self.operation_type {
            EncryptType::Encryption => true,
            EncryptType::Decryption => false,
        };
        let message = if is_encrypt { "Enkripsi" } else { "Dekripsi" };

        let mut vec_key = key.as_bytes().to_vec();
        let mut nonce = nonce.as_bytes().to_vec();
        nonce.resize(24, 0);
        vec_key.resize(32, 0);

        let key_array: [u8; 32] = vec_key
            .try_into()
            .expect("The string could not be converted into a [u8; 32] array");
        let nonce_array: [u8; 24] = nonce
            .try_into()
            .expect("The string could not be converted into a [u8; 24] array");

        thread::spawn(move || {
            let start = Instant::now();
            let duration: Duration;
            let result_message = match selected_algorithm {
                EncryptAlgorithm::Chacha20Poly1305 => {
                    match Crypto::chaca20poly1305(&file_path, &key_array, &nonce_array, is_encrypt)
                    {
                        Ok(ciphertext) => {
                            let hex_ciphertext = hex_encode(ciphertext);
                            duration = start.elapsed();
                            vec![
                                format!("{}", hex_ciphertext),
                                format!(
                                    "{} berhasil ✅ dalam waktu ⏱ {}",
                                    message,
                                    human_duration(&duration)
                                ),
                            ]
                        }
                        Err(_e) => vec!["Dekripsi ❌ gagal!".to_string()],
                    }
                }
                EncryptAlgorithm::Des => match Crypto::des(&file_path, &key_array, is_encrypt) {
                    Ok(ciphertext) => {
                        let hex_ciphertext = hex::encode(ciphertext);
                        duration = start.elapsed();
                        vec![
                            format!("{}", hex_ciphertext),
                            format!(
                                "{} berhasil ✅ dalam waktu ⏱️: {}",
                                message,
                                human_duration(&duration)
                            ),
                        ]
                    }
                    Err(_e) => vec!["Dekripsi ❌ gagal!".to_string()],
                },
            };
            tx.send(result_message).unwrap();
        }); // End of thread
    }

    fn passphrase_input(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            Frame::none().show(ui, |ui| {
                ui.set_min_width(80.0);
                ui.label("Kata Kunci: ");
            });
            ui.text_edit_singleline(&mut self.key)
        });
        ui.add_space(10.0);
        let file_selected = self.file_path.is_some();
        if self.selected_algorithm == EncryptAlgorithm::Chacha20Poly1305 {
            ui.horizontal(|ui| {
                Frame::none().show(ui, |ui| {
                    ui.set_min_width(80.0);
                    ui.label("Nonce: ");
                });
                ui.text_edit_singleline(&mut self.nonce);
            });
        }
        ui.add_space(10.0);
        let process_button = ui.add_enabled(file_selected, egui::Button::new("Proses File"));
        if process_button.clicked() {
            self.update_output_message("Proses Sedang Berlangsung..");
            self.process_file();
        }
        ui.add_space(10.0);
    }

    fn chacha20poly1305(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        self.select_file(ui);
        self.select_operation_type(ui);
        self.passphrase_input(ui);
    }

    fn des(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        self.select_file(ui);
        self.select_operation_type(ui);
        self.passphrase_input(ui);
    }

    fn select_operation_type(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Jenis operasi: ");
            ui.radio_value(
                &mut self.operation_type,
                EncryptType::Encryption,
                "Enkripsi",
            );
            ui.radio_value(
                &mut self.operation_type,
                EncryptType::Decryption,
                "Dekripsi",
            );
        });
    }

    fn select_file(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            Frame::none().show(ui, |ui| {
                ui.set_min_width(80.0);
                ui.label("File: ");
            });
            if ui.button("Buka File").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    let path_str = path.display().to_string();
                    self.file_path = Some(path_str.clone());
                    let _ = self.set_metadata(path_str.clone());
                }
            }
        });
    }

    fn update_output_message(&self, new_text: &str) {
        let mut output_message = self.output_message.lock().unwrap();
        *output_message = new_text.to_string();
    }

    fn update_cipher_text(&self, new_text: &str) {
        let edited = new_text
            .chars() // Convert to an iterator of characters
            .collect::<Vec<_>>() // Collect characters into a Vec<char>
            .chunks(2) // Chunk the characters into pairs
            .map(|chunk| chunk.iter().collect::<String>()) // Convert each chunk to a String
            .collect::<Vec<String>>() // Collect all chunks into a Vec<String>
            .join(" "); // Join them back into a single string with a separator

        let mut output_message = self.ciphertext.lock().unwrap();
        *output_message = edited.to_string();
    }

    fn show_output(&mut self, ui: &mut Ui) {
        ui.label(self.file_metada.clone());
        let output_message = self.output_message.lock().unwrap();

        if self.is_processing {
            ui.horizontal(|ui| {
                ui.label("Proses sedang berlangsung..");
                ui.add(Spinner::new());
            });
        } else {
            ui.label(&*output_message);
        }
    }

    fn create_table(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hex:\n");
        let ciphertext = self.ciphertext.lock().unwrap();
        let rows: Vec<&str> = ciphertext.split_whitespace().collect();
        let column_names = [
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
        ];
        let columns = column_names.len();
        let mut table = TableBuilder::new(ui);

        for _ in 0..columns {
            table = table.column(Column::auto().resizable(true).at_least(20.0));
        }

        table
            .header(20.0, |mut header| {
                for &name in &column_names {
                    header.col(|ui| {
                        ui.label(name);
                    });
                }
            })
            .body(|mut body| {
                for row_chunk in rows.chunks(columns) {
                    body.row(30.0, |mut row| {
                        for cell in row_chunk {
                            row.col(|ui| {
                                ui.label(cell.to_string());
                            });
                        }
                    });
                }
            });
    }

    fn set_metadata(&mut self, path: String) -> std::io::Result<()> {
        let metadata = fs::metadata(path.clone())?; // Get metadata for the file
        let file_size = metadata.len(); // Get the file size

        let mut last_edited = String::new();
        if let Ok(modified) = metadata.modified() {
            let duration = modified.duration_since(UNIX_EPOCH).unwrap();
            let datetime = UNIX_EPOCH + duration;
            let datetime = chrono::DateTime::<chrono::Local>::from(datetime);
            last_edited = datetime.to_string();
        }

        // Set filetype
        let mime_path = Path::new(path.as_str());
        let mut file_type = "application/octet-stream".to_string(); // Default MIME type

        // Extract the file extension
        if let Some(extension) = mime_path.extension() {
            // Convert the extension to a string
            let ext_str = extension.to_string_lossy();
            // Get MIME type from the file extension
            let mime = MimeGuess::from_ext(&ext_str).first_or_octet_stream();
            file_type = mime.clone().to_string();
        }
        self.file_metada = format!(
            "Lokasi: {}\nTipe: {}\nUkuran file: {} bytes\nTanggal: {}",
            path, file_type, file_size, last_edited
        );
        Ok(())
    }
}

impl Default for MyApp {
    fn default() -> Self {
        let mut dock_state =
            DockState::new(vec!["ChaCha20-Poly1305".to_string(), "Des".to_string()]);
        let [_, _] = dock_state.main_surface_mut().split_right(
            NodeIndex::root(),
            0.5,
            vec!["Info".to_owned()],
        );
        let [_, _] = dock_state.main_surface_mut().split_below(
            NodeIndex::root(),
            0.5,
            vec!["Output".to_owned()],
        );
        let (tx, rx) = mpsc::channel();
        let mut open_tabs = HashSet::new();
        let expanded_tab = Some(String::default());
        for node in dock_state[SurfaceIndex::main()].iter() {
            if let Some(tabs) = node.tabs() {
                for tab in tabs {
                    open_tabs.insert(tab.clone());
                }
            }
        }
        let context = data::MyContext {
            key: String::default(),
            nonce: String::default(),
            file_path: None,
            output_message: Arc::new(Mutex::new(String::new())),
            ciphertext: Arc::new(Mutex::new(String::new())),
            is_processing: false,
            tx: Some(tx),
            rx: Some(rx),
            selected_algorithm: EncryptAlgorithm::Chacha20Poly1305,
            operation_type: EncryptType::Encryption,
            show_close_buttons: false,
            file_metada: String::new(),
            open_tabs,
            expanded_tab,
        };
        let mut open_tabs = HashSet::new();

        for node in dock_state[SurfaceIndex::main()].iter() {
            if let Some(tabs) = node.tabs() {
                for tab in tabs {
                    open_tabs.insert(tab.clone());
                }
            }
        }
        Self {
            context,
            tree: dock_state,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        TopBottomPanel::top("egui_dock::MenuBar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Algoritma", |ui| {
                    for tab in &["ChaCha20-Poly1305", "Des"] {
                        let is_open = self.context.open_tabs.contains(*tab);
                        if ui.selectable_label(is_open, *tab).clicked() {
                            if let Some(index) = self.tree.find_tab(&tab.to_string()) {
                                if is_open && self.context.expanded_tab == Some(tab.to_string()) {
                                    self.context.expanded_tab = None; // Collapse if already expanded
                                } else {
                                    self.context.expanded_tab = Some(tab.to_string()); // Expand selected tab
                                    self.tree.remove_tab(index); // Remove from dock before re-adding
                                }
                                self.context.open_tabs.remove(*tab);
                            } else {
                                self.tree[SurfaceIndex::main()]
                                    .push_to_focused_leaf(tab.to_string());
                                self.context.expanded_tab = None; // Reset expanded state
                            }
                        }
                    }
                });
                ui.menu_button("Tentang", |ui| {
                    for tab in &["Author", "License"] {
                        if ui
                            .selectable_label(self.context.open_tabs.contains(*tab), *tab)
                            .clicked()
                        {
                            println!("todo");
                        }
                    }
                });
            })
        });
        CentralPanel::default()
            .frame(Frame::central_panel(&ctx.style()).inner_margin(0.))
            .show(ctx, |ui| {
                DockArea::new(&mut self.tree)
                    .show_close_buttons(self.context.show_close_buttons)
                    .show_inside(ui, &mut self.context);
            });

        if let Some(rx) = &self.context.rx {
            if let Ok(message) = rx.try_recv() {
                self.context.update_cipher_text(&message[0]);
                self.context.update_output_message(&message[1]);
                self.context.is_processing = false;
            }
        }

        if self.context.is_processing {
            ctx.request_repaint(); // Ensure UI is updated during processing
        }
        ctx.set_pixels_per_point(1.8);
        themes::catppuccin::set_theme(&ctx, themes::catppuccin::FRAPPE);
    }
}
