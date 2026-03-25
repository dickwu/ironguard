use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // status panel
            Constraint::Length(10), // actions
            Constraint::Min(4),     // log
            Constraint::Length(3),  // keybindings
        ])
        .margin(1)
        .split(frame.area());

    render_info(frame, app, chunks[0]);
    render_actions(frame, app, chunks[1]);
    render_log(frame, app, chunks[2]);
    render_keys(frame, chunks[3]);
}

fn render_info(frame: &mut Frame, app: &App, area: Rect) {
    let platform = app.sys.platform_name();
    let (label, file_path, installed, enabled, active) = match &app.service_info {
        Some(info) => (
            info.label.as_str(),
            info.file_path.as_str(),
            info.installed,
            info.enabled,
            info.active,
        ),
        None => ("?", "?", false, false, false),
    };

    let yes_no = |v: bool| -> (&str, Color) {
        if v {
            ("Yes", Color::Green)
        } else {
            ("No", Color::Red)
        }
    };

    let (installed_txt, installed_clr) = yes_no(installed);
    let (enabled_txt, enabled_clr) = yes_no(enabled);
    let (active_txt, active_clr) = yes_no(active);

    let enabled_hint = if installed && !enabled {
        "  (won't start at boot)"
    } else if installed && enabled {
        "  (starts at boot)"
    } else {
        ""
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Platform:   "),
            Span::styled(platform, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  Service:    "),
            Span::styled(label, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("  File:       "),
            Span::styled(file_path, Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::raw("  Installed:  "),
            Span::styled(installed_txt, Style::default().fg(installed_clr)),
        ]),
        Line::from(vec![
            Span::raw("  Enabled:    "),
            Span::styled(enabled_txt, Style::default().fg(enabled_clr)),
            Span::styled(enabled_hint, Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::raw("  Active:     "),
            Span::styled(active_txt, Style::default().fg(active_clr)),
        ]),
    ];

    let block = Block::default()
        .title(" Service Manager ")
        .title_style(Style::default().fg(Color::Cyan).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}

fn render_actions(frame: &mut Frame, app: &App, area: Rect) {
    let installed = app.service_info.as_ref().is_some_and(|i| i.installed);
    let enabled = app.service_info.as_ref().is_some_and(|i| i.enabled);

    let mut items: Vec<ListItem> = Vec::new();

    if !installed {
        items.push(action_item("i", "Install service", Color::Green));
    } else {
        items.push(action_item("i", "Reinstall service", Color::Yellow));
    }

    if installed && !enabled {
        items.push(action_item("e", "Enable (start at boot)", Color::Green));
    }
    if installed && enabled {
        items.push(action_item(
            "d",
            "Disable (don't start at boot)",
            Color::Yellow,
        ));
    }
    if installed {
        items.push(action_item("u", "Uninstall service", Color::Red));
    }

    items.push(action_item("f", "Refresh status", Color::Cyan));

    let list = List::new(items).block(
        Block::default()
            .title(" Actions ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

fn action_item<'a>(key: &'a str, desc: &'a str, color: Color) -> ListItem<'a> {
    ListItem::new(Line::from(vec![
        Span::raw("    "),
        Span::styled(format!("[{key}]"), Style::default().fg(color).bold()),
        Span::raw(format!("  {desc}")),
    ]))
}

fn render_log(frame: &mut Frame, app: &App, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let start = app.service_log.len().saturating_sub(visible);
    let lines: Vec<Line> = app.service_log[start..]
        .iter()
        .map(|l| {
            Line::from(Span::styled(
                format!("  {l}"),
                Style::default().fg(Color::White),
            ))
        })
        .collect();

    let block = Block::default()
        .title(" Log ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn render_keys(frame: &mut Frame, area: Rect) {
    let text = vec![Line::from(vec![
        Span::styled(" [Esc]", Style::default().fg(Color::Yellow)),
        Span::raw(" back"),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}
