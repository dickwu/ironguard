use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(3)])
        .split(frame.area());

    let visible = chunks[0].height.saturating_sub(2) as usize;
    let total = app.logs.len();
    let scroll = app.log_scroll as usize;

    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(visible);

    let lines: Vec<Line> = app.logs[start..end]
        .iter()
        .map(|l| {
            let style = if l.contains("error") || l.contains("Error") || l.contains("failed") {
                Style::default().fg(Color::Red)
            } else if l.contains("warn") || l.contains("Warn") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(l.as_str(), style))
        })
        .collect();

    let title = format!(" Logs ({total} lines) ");
    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(Color::Cyan).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, chunks[0]);

    // keybindings
    let keys = Paragraph::new(Line::from(vec![
        Span::styled(" [j/k]", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("[Home/End]", Style::default().fg(Color::Yellow)),
        Span::raw(" top/bottom  "),
        Span::styled("[Esc]", Style::default().fg(Color::Yellow)),
        Span::raw(" back"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(keys, chunks[1]);
}
