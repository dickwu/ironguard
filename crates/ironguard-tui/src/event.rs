use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use crate::actions;
use crate::app::{App, ConfirmAction, Screen, SetupPhase};

pub fn handle_events(app: &mut App) -> Result<bool> {
    if !event::poll(Duration::from_millis(250))? {
        return Ok(false);
    }

    let Event::Key(key) = event::read()? else {
        return Ok(false);
    };

    // only handle key press, not release/repeat
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    // ctrl+c always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return Ok(true);
    }

    match &app.screen {
        Screen::Dashboard => handle_dashboard(app, key.code),
        Screen::Help => handle_help(app, key.code),
        Screen::Logs => handle_logs(app, key.code),
        Screen::ClientList => handle_client_list(app, key.code),
        Screen::ClientCreate => handle_client_create(app, key.code),
        Screen::Service => handle_service(app, key.code),
        Screen::Confirm(_) => handle_confirm(app, key.code),
        Screen::Setup(_) => handle_setup(app, key.code),
    }

    Ok(true)
}

fn handle_dashboard(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') | KeyCode::Char('h') => app.go_to(Screen::Help),
        KeyCode::Char('l') => app.go_to(Screen::Logs),
        KeyCode::Char('c') => {
            app.input_name.clear();
            app.input_endpoint.clear();
            app.input_field = 0;
            app.go_to(Screen::ClientCreate);
        }
        KeyCode::Char('p') => app.go_to(Screen::ClientList),
        KeyCode::Char('s') => app.go_to(Screen::Setup(SetupPhase::Welcome)),
        KeyCode::Char('d') => {
            app.refresh_service();
            app.go_to(Screen::Service);
        }
        KeyCode::Char('r') => {
            if app.server_running {
                app.go_to(Screen::Confirm(ConfirmAction::Restart));
            } else {
                do_start(app);
            }
        }
        KeyCode::Char('x') => {
            if app.server_running {
                app.go_to(Screen::Confirm(ConfirmAction::Stop));
            }
        }
        _ => {}
    }
}

fn handle_help(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => app.go_back(),
        _ => {}
    }
}

fn handle_logs(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Char('q') => app.go_back(),
        KeyCode::Up | KeyCode::Char('k') => {
            app.log_scroll = app.log_scroll.saturating_add(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        KeyCode::Home => {
            app.log_scroll = app.logs.len().saturating_sub(1) as u16;
        }
        KeyCode::End => {
            app.log_scroll = 0;
        }
        _ => {}
    }
}

fn handle_client_list(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Char('q') => app.go_back(),
        KeyCode::Char('c') => {
            app.input_name.clear();
            app.input_endpoint.clear();
            app.input_field = 0;
            app.go_to(Screen::ClientCreate);
        }
        _ => {}
    }
}

fn handle_client_create(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => app.go_back(),
        KeyCode::Tab => {
            app.input_field = (app.input_field + 1) % 2;
        }
        KeyCode::Backspace => {
            let field = current_input_field(app);
            field.pop();
        }
        KeyCode::Char(c) => {
            let field = current_input_field(app);
            field.push(c);
        }
        KeyCode::Enter => {
            let name = app.input_name.trim().to_owned();
            if name.is_empty() {
                app.set_status("Name cannot be empty");
                return;
            }
            let endpoint = if app.input_endpoint.trim().is_empty() {
                None
            } else {
                Some(app.input_endpoint.trim().to_owned())
            };
            match actions::config::create_client(&name, endpoint.as_deref()) {
                Ok(info) => {
                    app.push_log(&format!("Client created: {} ({})", info.name, info.ip));
                    app.set_status(&format!("Created client: {}", info.name));
                    app.refresh();
                    app.go_back();
                }
                Err(e) => {
                    app.set_status(&format!("Error: {e}"));
                }
            }
        }
        _ => {}
    }
}

fn current_input_field(app: &mut App) -> &mut String {
    if app.input_field == 0 {
        &mut app.input_name
    } else {
        &mut app.input_endpoint
    }
}

fn handle_service(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Char('q') => app.go_back(),
        KeyCode::Char('i') => {
            match actions::system::install_service(&app.sys, &app.interface) {
                Ok(()) => {
                    app.push_service_log("Service installed.");
                    app.push_log("Service installed.");
                }
                Err(e) => app.push_service_log(&format!("Install error: {e}")),
            }
            app.refresh_service();
        }
        KeyCode::Char('e') => {
            match actions::system::enable_service(&app.sys, &app.interface) {
                Ok(msg) => {
                    app.push_service_log(&msg);
                    app.push_log(&msg);
                }
                Err(e) => app.push_service_log(&format!("Enable error: {e}")),
            }
            app.refresh_service();
        }
        KeyCode::Char('d') => {
            match actions::system::disable_service(&app.sys, &app.interface) {
                Ok(msg) => {
                    app.push_service_log(&msg);
                    app.push_log(&msg);
                }
                Err(e) => app.push_service_log(&format!("Disable error: {e}")),
            }
            app.refresh_service();
        }
        KeyCode::Char('u') => {
            match actions::system::uninstall_service(&app.sys, &app.interface) {
                Ok(msg) => {
                    app.push_service_log(&msg);
                    app.push_log(&msg);
                }
                Err(e) => app.push_service_log(&format!("Uninstall error: {e}")),
            }
            app.refresh_service();
        }
        KeyCode::Char('f') => {
            app.refresh_service();
            app.push_service_log("Status refreshed.");
        }
        _ => {}
    }
}

fn handle_confirm(app: &mut App, key: KeyCode) {
    let action = match &app.screen {
        Screen::Confirm(a) => a.clone(),
        _ => return,
    };

    match key {
        KeyCode::Char('y') | KeyCode::Enter => {
            match action {
                ConfirmAction::Restart => {
                    do_restart(app);
                }
                ConfirmAction::Stop => {
                    do_stop(app);
                }
                ConfirmAction::RemoveClient(name) => match actions::config::remove_client(&name) {
                    Ok(()) => {
                        app.push_log(&format!("Removed client: {name}"));
                        app.set_status(&format!("Removed: {name}"));
                        app.refresh();
                    }
                    Err(e) => app.set_status(&format!("Error: {e}")),
                },
            }
            app.go_back();
        }
        KeyCode::Char('n') | KeyCode::Esc => app.go_back(),
        _ => {}
    }
}

fn handle_setup(app: &mut App, key: KeyCode) {
    let phase = match &app.screen {
        Screen::Setup(p) => p.clone(),
        _ => return,
    };

    match key {
        KeyCode::Esc => app.go_back(),
        KeyCode::Enter => {
            let next = run_setup_phase(app, &phase);
            if let Some(next_phase) = next {
                app.screen = Screen::Setup(next_phase);
            } else {
                app.go_back();
            }
        }
        _ => {}
    }
}

fn run_setup_phase(app: &mut App, phase: &SetupPhase) -> Option<SetupPhase> {
    match phase {
        SetupPhase::Welcome => {
            app.setup_log.clear();
            app.setup_log.push("Starting IronGuard setup...".into());
            Some(SetupPhase::Keys)
        }
        SetupPhase::Keys => {
            match actions::keys::ensure_server_keys() {
                Ok(pk) => {
                    app.setup_log
                        .push(format!("Server keys ready. Public key: {}", &pk[..20]));
                    app.public_key = pk;
                }
                Err(e) => {
                    app.setup_log.push(format!("Key error: {e}"));
                    return None;
                }
            }
            Some(SetupPhase::Config)
        }
        SetupPhase::Config => {
            let iface = app.interface.clone();
            match actions::config::ensure_server_config(&iface, app.port) {
                Ok(()) => app.setup_log.push("Config created.".into()),
                Err(e) => {
                    app.setup_log.push(format!("Config error: {e}"));
                    return None;
                }
            }
            Some(SetupPhase::Service)
        }
        SetupPhase::Service => {
            match actions::system::install_service(&app.sys, &app.interface) {
                Ok(()) => app.setup_log.push("Service installed.".into()),
                Err(e) => app.setup_log.push(format!("Service: {e}")),
            }
            Some(SetupPhase::Firewall)
        }
        SetupPhase::Firewall => {
            match actions::system::configure_firewall(&app.sys, app.port) {
                Ok(msg) => app.setup_log.push(format!("Firewall: {msg}")),
                Err(e) => app.setup_log.push(format!("Firewall: {e}")),
            }
            actions::system::enable_ip_forwarding(&app.sys).ok();
            app.setup_log.push("IP forwarding enabled.".into());
            Some(SetupPhase::Done)
        }
        SetupPhase::Done => {
            app.push_log("Setup complete.");
            app.set_status("Setup complete");
            app.refresh();
            None
        }
    }
}

fn do_start(app: &mut App) {
    match actions::server::start(&app.sys, &app.interface) {
        Ok(()) => {
            app.push_log("Server started.");
            app.set_status("Server started");
            app.refresh();
        }
        Err(e) => app.set_status(&format!("Start failed: {e}")),
    }
}

fn do_stop(app: &mut App) {
    match actions::server::stop(&app.sys, &app.interface) {
        Ok(()) => {
            app.push_log("Server stopped.");
            app.set_status("Server stopped");
            app.server_running = false;
            app.server_pid = None;
        }
        Err(e) => app.set_status(&format!("Stop failed: {e}")),
    }
}

fn do_restart(app: &mut App) {
    do_stop(app);
    std::thread::sleep(std::time::Duration::from_secs(1));
    do_start(app);
}
