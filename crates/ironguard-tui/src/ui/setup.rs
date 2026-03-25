use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};

use crate::app::{App, SetupPhase};

pub fn render(frame: &mut Frame, app: &App) {
    let phase = match &app.screen {
        crate::app::Screen::Setup(p) => p,
        _ => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title + progress
            Constraint::Length(9), // steps
            Constraint::Min(4),    // output log
            Constraint::Length(3), // keys
        ])
        .margin(1)
        .split(frame.area());

    // progress bar
    let (step, total) = phase_progress(phase);
    let ratio = step as f64 / total as f64;
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" Setup  Step {step}/{total} "))
                .title_style(Style::default().fg(Color::Cyan).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(ratio);
    frame.render_widget(gauge, chunks[0]);

    // step list
    let steps = [
        ("Welcome", SetupPhase::Welcome),
        ("Generate keys", SetupPhase::Keys),
        ("Create config", SetupPhase::Config),
        ("Install service", SetupPhase::Service),
        ("Firewall + forwarding", SetupPhase::Firewall),
        ("Done", SetupPhase::Done),
    ];

    let items: Vec<ListItem> = steps
        .iter()
        .enumerate()
        .map(|(i, (label, _step_phase))| {
            let (prefix, style) = if phase_index(phase) > i {
                ("  OK ", Style::default().fg(Color::Green))
            } else if phase_index(phase) == i {
                ("  >> ", Style::default().fg(Color::Yellow).bold())
            } else {
                ("     ", Style::default().fg(Color::DarkGray))
            };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(*label, style),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Steps ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, chunks[1]);

    // output log
    let log_lines: Vec<Line> = app
        .setup_log
        .iter()
        .map(|l| {
            Line::from(Span::styled(
                format!("  {l}"),
                Style::default().fg(Color::White),
            ))
        })
        .collect();

    let log = Paragraph::new(log_lines).block(
        Block::default()
            .title(" Output ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(log, chunks[2]);

    // keybindings
    let key_text = if matches!(phase, SetupPhase::Done) {
        " [Enter] finish    [Esc] cancel"
    } else {
        " [Enter] next step    [Esc] cancel"
    };
    let keys = Paragraph::new(Line::from(vec![Span::styled(
        key_text,
        Style::default().fg(Color::Yellow),
    )]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(keys, chunks[3]);
}

fn phase_index(phase: &SetupPhase) -> usize {
    match phase {
        SetupPhase::Welcome => 0,
        SetupPhase::Keys => 1,
        SetupPhase::Config => 2,
        SetupPhase::Service => 3,
        SetupPhase::Firewall => 4,
        SetupPhase::Done => 5,
    }
}

fn phase_progress(phase: &SetupPhase) -> (usize, usize) {
    (phase_index(phase), 6)
}
