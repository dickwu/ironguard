use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::app::App;

pub fn render_create(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Length(3), // name input
            Constraint::Length(3), // endpoint input
            Constraint::Min(4),    // instructions
            Constraint::Length(3), // status bar
        ])
        .margin(2)
        .split(frame.area());

    // title
    let title = Paragraph::new(" Create Client")
        .style(Style::default().fg(Color::Cyan).bold())
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(title, chunks[0]);

    // name input
    let name_style = if app.input_field == 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let name_border = if app.input_field == 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let name_input = Paragraph::new(format!(" {}", app.input_name))
        .style(name_style)
        .block(
            Block::default()
                .title(" Name ")
                .borders(Borders::ALL)
                .border_style(name_border),
        );
    frame.render_widget(name_input, chunks[1]);

    // endpoint input
    let ep_style = if app.input_field == 1 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let ep_border = if app.input_field == 1 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let placeholder = if app.input_endpoint.is_empty() && app.input_field != 1 {
        " (optional) server-ip:51820"
    } else {
        ""
    };
    let ep_text = if app.input_endpoint.is_empty() {
        placeholder.to_owned()
    } else {
        format!(" {}", app.input_endpoint)
    };
    let ep_input = Paragraph::new(ep_text).style(ep_style).block(
        Block::default()
            .title(" Endpoint ")
            .borders(Borders::ALL)
            .border_style(ep_border),
    );
    frame.render_widget(ep_input, chunks[2]);

    // instructions
    let instructions = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tab", Style::default().fg(Color::Yellow)),
            Span::raw("  switch field"),
        ]),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Color::Yellow)),
            Span::raw("  create client"),
        ]),
        Line::from(vec![
            Span::styled("  Esc", Style::default().fg(Color::Yellow)),
            Span::raw("  cancel"),
        ]),
    ]);
    frame.render_widget(instructions, chunks[3]);

    // status
    if !app.status_msg.is_empty() {
        let status =
            Paragraph::new(format!("  {}", app.status_msg)).style(Style::default().fg(Color::Red));
        frame.render_widget(status, chunks[4]);
    }

    // set cursor position
    let cursor_x = if app.input_field == 0 {
        chunks[1].x + app.input_name.len() as u16 + 2
    } else {
        chunks[2].x + app.input_endpoint.len() as u16 + 2
    };
    let cursor_y = if app.input_field == 0 {
        chunks[1].y + 1
    } else {
        chunks[2].y + 1
    };
    frame.set_cursor_position(Position::new(cursor_x, cursor_y));
}

pub fn render_list(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // table
            Constraint::Length(3), // keys
        ])
        .split(frame.area());

    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(Color::DarkGray)),
        Cell::from("IP").style(Style::default().fg(Color::DarkGray)),
        Cell::from("Public Key").style(Style::default().fg(Color::DarkGray)),
        Cell::from("Created").style(Style::default().fg(Color::DarkGray)),
    ]);

    let rows: Vec<Row> = app
        .clients
        .iter()
        .map(|c| {
            let pk_short = if c.public_key.len() > 20 {
                format!("{}...", &c.public_key[..20])
            } else {
                c.public_key.clone()
            };
            Row::new(vec![
                Cell::from(c.name.as_str()),
                Cell::from(c.ip.as_str()),
                Cell::from(pk_short).style(Style::default().fg(Color::DarkGray)),
                Cell::from(c.created.as_str()),
            ])
        })
        .collect();

    let empty_rows = if rows.is_empty() {
        vec![Row::new(vec![
            Cell::from("  No clients. Press [c] to create one.")
                .style(Style::default().fg(Color::DarkGray)),
        ])]
    } else {
        vec![]
    };

    let display = if rows.is_empty() { empty_rows } else { rows };

    let widths = [
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Min(24),
        Constraint::Length(22),
    ];

    let table = Table::new(display, widths).header(header).block(
        Block::default()
            .title(format!(" Clients ({}) ", app.clients.len()))
            .title_style(Style::default().fg(Color::Cyan).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(table, chunks[0]);

    // keybindings
    let keys = Paragraph::new(Line::from(vec![
        Span::styled(" [c]", Style::default().fg(Color::Yellow)),
        Span::raw("reate  "),
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
