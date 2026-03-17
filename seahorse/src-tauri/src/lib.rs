mod commands;

pub fn run() {
    // Initialize tracing so debug logs go to stderr (visible in `cargo tauri dev`)
    tracing_subscriber::fmt()
        .with_env_filter("seahorse_tauri_lib=debug,seahorse=debug")
        .with_target(true)
        .init();

    tracing::info!("Seahorse Tauri app starting...");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::load_config,
            commands::decode_saml,
            commands::validate_assertion,
            commands::load_idp_cert,
            commands::load_chain_cert,
            commands::save_raw_xml,
            commands::run_rest_flow,
            commands::run_browser_flow,
            commands::compare_saml,
            commands::compare_revalidate,
        ])
        .setup(|app| {
            use tauri::Manager;
            app.manage(std::sync::Mutex::new(commands::AppState::default()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
