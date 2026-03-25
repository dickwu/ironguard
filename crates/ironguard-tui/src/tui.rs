use std::io::{self, stdout};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;

use crate::app::App;
use crate::event;
use crate::ui;

pub fn run() -> Result<()> {
    let mut terminal = setup_terminal()?;
    let result = run_loop(&mut terminal);
    restore_terminal()?;
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    let mut app = App::new();
    app.refresh();
    app.push_log("IronGuard TUI started.");

    let tick_rate = Duration::from_secs(2);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| ui::render(frame, &app))?;

        event::handle_events(&mut app)?;

        if app.should_quit {
            break;
        }

        // periodic refresh
        if last_tick.elapsed() >= tick_rate {
            app.refresh();
            last_tick = Instant::now();
        }
    }

    Ok(())
}
