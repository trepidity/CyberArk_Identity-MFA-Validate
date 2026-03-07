use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::WindowBuilder;
use tracing::info;
use wry::WebViewBuilder;

#[cfg(target_os = "macos")]
use tao::platform::macos::WindowExtMacOS;

/// JavaScript injected into every page load (runs at document-start).
/// Uses three layers to intercept the SAMLResponse before it gets POSTed to /security/whoami:
///   1. Override HTMLFormElement.prototype.submit() — catches programmatic form.submit() calls
///   2. Global 'submit' event listener in capture phase — catches event-based submissions
///   3. Polling fallback — catches any edge cases where the above miss it
const INTERCEPT_JS: &str = r#"
(function() {
    var captured = false;

    function sendToRust(value) {
        if (captured) return;
        captured = true;
        window.ipc.postMessage(value);
    }

    // Layer 1: Override HTMLFormElement.prototype.submit() globally.
    // CyberArk's SAML POST binding page uses <body onload="document.forms[0].submit()">
    // This override fires BEFORE the native submit happens.
    var originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        var input = this.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            sendToRust(input.value);
            return; // Block the actual submission
        }
        originalSubmit.call(this);
    };

    // Layer 2: Global submit event listener (capture phase).
    // Fires before any element-level handlers.
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var input = form.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            sendToRust(input.value);
            return false;
        }
    }, true);

    // Layer 3: Poll for SAMLResponse input appearing in the DOM.
    // Fallback in case the form exists before our script runs on some platforms.
    var checkInterval = setInterval(function() {
        var inputs = document.querySelectorAll('input[name="SAMLResponse"]');
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].value) {
                clearInterval(checkInterval);
                sendToRust(inputs[i].value);
                return;
            }
        }
    }, 50);

    // Stop polling after 60 seconds
    setTimeout(function() { clearInterval(checkInterval); }, 60000);
})();
"#;

pub fn build_login_url(tenant: &str, username: &str, appkey: &str) -> String {
    format!(
        "https://{}/run?username={}&appkey={}&failureRedirectUrl=/failure&nozso=True&submitUsername=True",
        tenant, username, appkey
    )
}

/// Opens a native webview window to the CyberArk login URL.
/// Injects JS to intercept the SAMLResponse POST.
/// Returns the base64-encoded SAMLResponse value.
///
/// This function blocks the current (main) thread until the user completes
/// authentication or closes the window.
///
/// IMPORTANT: On macOS, `event_loop.run()` never returns — it calls `std::process::exit()`.
/// We store the result in a shared Arc<Mutex<>> and use `std::process::exit()` ourselves
/// after writing the result. The caller must handle this.
pub fn run_webview_flow(login_url: &str) -> Result<String> {
    info!("[Webview] Opening login URL: {}", login_url);

    // Shared state for the captured SAMLResponse
    let result: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    let mut event_loop = EventLoopBuilder::new().build();
    let window = WindowBuilder::new()
        .with_title("Seahorse - CyberArk Login")
        .with_inner_size(tao::dpi::LogicalSize::new(800.0, 700.0))
        .build(&event_loop)
        .context("Failed to create webview window")?;

    // On macOS, grab the raw NSWindow pointer so we can forcibly close it later.
    // tao's Window::drop doesn't reliably close the native window after run_return.
    #[cfg(target_os = "macos")]
    let ns_window = window.ns_window();

    let proxy = event_loop.create_proxy();

    let _webview = WebViewBuilder::new()
        .with_url(login_url)
        .with_initialization_script(INTERCEPT_JS)
        .with_ipc_handler(move |msg| {
            let body = msg.body();
            info!("[Webview IPC] Received SAMLResponse ({} chars)", body.len());
            {
                let mut guard = result_clone.lock().unwrap();
                *guard = Some(body.to_string());
            }
            // Signal the event loop to exit
            let _ = proxy.send_event(());
        })
        .build(&window)
        .context("Failed to create webview")?;

    info!("[Webview] Window opened, waiting for SAMLResponse...");

    // Use run_return so we can return control to the caller after the webview closes.
    // Unlike run(), run_return() does NOT call std::process::exit().
    event_loop.run_return(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(()) => {
                info!("[Webview] SAMLResponse captured, exiting event loop");
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                info!("[Webview] Window closed by user");
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });

    // On macOS, explicitly close the native NSWindow via objc messaging.
    // tao's run_return stops the event loop but doesn't close the window,
    // leaving a zombie window on screen.
    #[cfg(target_os = "macos")]
    {
        info!("[Webview] Closing NSWindow via objc");
        unsafe {
            use objc::runtime::Object;
            use objc::{msg_send, sel, sel_impl};
            let ns_win = ns_window as *mut Object;
            let () = msg_send![ns_win, orderOut: std::ptr::null::<Object>()];
            let () = msg_send![ns_win, close];
        }
    }

    info!("[Webview] Window closed and resources released");

    let guard = result.lock().unwrap();
    guard
        .clone()
        .context("Webview closed without receiving SAMLResponse")
}
