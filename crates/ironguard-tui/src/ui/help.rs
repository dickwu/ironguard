use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

pub fn render(frame: &mut Frame, _app: &App) {
    let block = Block::default()
        .title(" Help ")
        .title_style(Style::default().fg(Color::Cyan).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let text = vec![
        Line::from(""),
        section("Dashboard"),
        key("s", "Run setup wizard"),
        key("c", "Create a new client"),
        key("p", "View client/peer list"),
        key("d", "Service manager (daemon)"),
        key("r", "Start or restart server"),
        key("x", "Stop server"),
        key("l", "View logs"),
        key("?", "This help"),
        key("q", "Quit"),
        Line::from(""),
        section("Service Manager"),
        key("i", "Install service"),
        key("e", "Enable (start at boot)"),
        key("d", "Disable (don't start at boot)"),
        key("u", "Uninstall service"),
        key("f", "Refresh status"),
        key("Esc", "Back to dashboard"),
        Line::from(""),
        section("Client Create"),
        key("Tab", "Switch between fields"),
        key("Enter", "Create the client"),
        key("Esc", "Cancel"),
        Line::from(""),
        section("Logs"),
        key("j / Down", "Scroll down"),
        key("k / Up", "Scroll up"),
        key("Home", "Jump to top"),
        key("End", "Jump to bottom"),
        key("Esc", "Back to dashboard"),
        Line::from(""),
        section("Global"),
        key("Ctrl+C", "Force quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Esc or ? to close this help",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, frame.area());
}

fn section(title: &str) -> Line<'_> {
    Line::from(Span::styled(
        format!("  {title}"),
        Style::default().fg(Color::White).bold(),
    ))
}

fn key<'a>(k: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::raw("    "),
        Span::styled(format!("{k:<12}"), Style::default().fg(Color::Yellow)),
        Span::raw(desc),
    ])
}
