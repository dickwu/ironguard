mod clients;
mod dashboard;
mod help;
mod logs;
mod setup;

use ratatui::prelude::*;

use crate::app::{App, Screen};

pub fn render(frame: &mut Frame, app: &App) {
    match &app.screen {
        Screen::Dashboard => dashboard::render(frame, app),
        Screen::Setup(_) => setup::render(frame, app),
        Screen::ClientCreate => clients::render_create(frame, app),
        Screen::ClientList => clients::render_list(frame, app),
        Screen::Logs => logs::render(frame, app),
        Screen::Help => help::render(frame, app),
        Screen::Confirm(action) => {
            // render dashboard underneath, then overlay confirm
            dashboard::render(frame, app);
            render_confirm(frame, action);
        }
    }
}

fn render_confirm(frame: &mut Frame, action: &crate::app::ConfirmAction) {
    use ratatui::widgets::{Block, Borders, Clear, Paragraph};

    let msg = match action {
        crate::app::ConfirmAction::Restart => "Restart the server?",
        crate::app::ConfirmAction::Stop => "Stop the server?",
        crate::app::ConfirmAction::RemoveClient(name) => {
            // Can't format with borrowed name in const context, handled below
            return render_confirm_with_name(frame, name);
        }
    };

    let area = centered_rect(40, 7, frame.area());
    let block = Block::default()
        .title(" Confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let text = format!("{msg}\n\n  [y] Yes    [n] No");
    let para = Paragraph::new(text).block(block);
    frame.render_widget(Clear, area);
    frame.render_widget(para, area);
}

fn render_confirm_with_name(frame: &mut Frame, name: &str) {
    use ratatui::widgets::{Block, Borders, Clear, Paragraph};

    let area = centered_rect(40, 7, frame.area());
    let block = Block::default()
        .title(" Confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let text = format!("Remove client '{name}'?\n\n  [y] Yes    [n] No");
    let para = Paragraph::new(text).block(block);
    frame.render_widget(Clear, area);
    frame.render_widget(para, area);
}

/// Create a centered rectangle of given width/height (in terminal cells).
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
