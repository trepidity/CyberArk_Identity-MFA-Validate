mod commands;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::load_config,
            commands::decode_saml,
            commands::validate_assertion,
            commands::load_idp_cert,
            commands::save_raw_xml,
        ])
        .setup(|app| {
            use tauri::Manager;
            app.manage(std::sync::Mutex::new(commands::AppState::default()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
