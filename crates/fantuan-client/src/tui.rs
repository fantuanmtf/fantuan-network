//! Terminal UI for the Fantuan client.
//!
//! The UI is a thin shell over the control protocol: history loads on channel
//! switches and live events stream in from the node.

use crate::control::{ControlClient, Event};
use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

const HISTORY_LIMIT: usize = 200;

struct DisplayLine {
    from: String,
    timestamp: u64,
    text: String,
}

struct App {
    uid: String,
    fingerprint: String,
    peers: usize,
    channels: Vec<String>,
    current: usize,
    history: HashMap<String, Vec<DisplayLine>>,
    input: String,
    status: String,
}

impl App {
    fn new(status: crate::control::Status) -> Self {
        let channels = if status.channels.is_empty() {
            vec!["#general".to_string()]
        } else {
            status.channels.clone()
        };
        Self {
            uid: status.uid,
            fingerprint: status.fingerprint,
            peers: status.peers,
            channels,
            current: 0,
            history: HashMap::new(),
            input: String::new(),
            status: "ready".to_string(),
        }
    }

    fn current_channel(&self) -> String {
        self.channels
            .get(self.current)
            .cloned()
            .unwrap_or_else(|| "#general".to_string())
    }

    fn push(&mut self, topic: &str, line: DisplayLine) {
        let entry = self.history.entry(topic.to_string()).or_default();
        if entry.len() >= HISTORY_LIMIT {
            entry.remove(0);
        }
        entry.push(line);
    }

    fn select_channel(&mut self, channel: &str) {
        if !self.channels.iter().any(|c| c == channel) {
            self.channels.push(channel.to_string());
        }
        if let Some(index) = self.channels.iter().position(|c| c == channel) {
            self.current = index;
        }
    }
}

/// Run the TUI until the user quits.
pub async fn run(mut client: ControlClient) -> Result<()> {
    let status = client.status().await?;
    let mut app = App::new(status);
    refresh(&mut client, &mut app).await;
    client.subscribe_events().await?;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let (key_tx, mut key_rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        loop {
            if let Ok(true) = event::poll(Duration::from_millis(200))
                && let Ok(CrosstermEvent::Key(key)) = event::read()
                && key_tx.send(key).is_err()
            {
                break;
            }
        }
    });

    let result = event_loop(&mut terminal, &mut client, &mut app, &mut key_rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    client: &mut ControlClient,
    app: &mut App,
    key_rx: &mut mpsc::UnboundedReceiver<KeyEvent>,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;
        tokio::select! {
            Some(key) = key_rx.recv() => {
                if handle_key(key, app, client).await? {
                    break;
                }
            }
            event = client.next_event() => {
                match event {
                    Ok(Event::Channel { channel, from, text, timestamp }) => {
                        app.push(
                            &channel,
                            DisplayLine { from: short(&from).to_string(), timestamp, text },
                        );
                    }
                    Ok(Event::Forum { board, from, title, body, timestamp }) => {
                        app.push(
                            &format!("bbs:{board}"),
                            DisplayLine {
                                from: short(&from).to_string(),
                                timestamp,
                                text: format!("{title}: {body}"),
                            },
                        );
                    }
                    Ok(Event::Message { from, text }) => {
                        let label = short(&from).to_string();
                        app.push("dms", DisplayLine { from: label.clone(), timestamp: 0, text });
                        app.status = format!("direct message from {label}");
                    }
                    Ok(Event::Relay { from }) => {
                        app.status = format!("relay delivered from {}", short(&from));
                    }
                    Err(error) => {
                        app.status = format!("event stream ended: {error}");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_key(key: KeyEvent, app: &mut App, client: &mut ControlClient) -> Result<bool> {
    match key.code {
        KeyCode::Esc => return Ok(true),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
        KeyCode::Enter => {
            let input = std::mem::take(&mut app.input);
            return submit(&input, app, client).await;
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char(character) => app.input.push(character),
        KeyCode::Down if app.current + 1 < app.channels.len() => {
            app.current += 1;
            refresh(client, app).await;
        }
        KeyCode::Up if app.current > 0 => {
            app.current -= 1;
            refresh(client, app).await;
        }
        _ => {}
    }
    Ok(false)
}

/// Returns true when the UI should quit.
async fn submit(input: &str, app: &mut App, client: &mut ControlClient) -> Result<bool> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(false);
    }

    if let Some(command) = input.strip_prefix('/') {
        let mut parts = command.splitn(3, ' ');
        let name = parts.next().unwrap_or_default();
        match name {
            "quit" | "q" => return Ok(true),
            "join" => {
                if let Some(channel) = parts.next().map(str::trim).filter(|c| !c.is_empty()) {
                    app.select_channel(channel);
                    refresh(client, app).await;
                    app.status = format!("joined {channel}");
                }
            }
            "read" => refresh(client, app).await,
            "peers" => {
                let peers = client.peers().await?;
                app.peers = peers.len();
                app.status = format!("{} peers known", peers.len());
            }
            "dm" => {
                let mut rest = parts;
                if let (Some(to), Some(text)) = (rest.next(), rest.next()) {
                    match client.send(to.trim(), text.trim()).await {
                        Ok(()) => app.status = format!("relay sent to {}", short(to.trim())),
                        Err(error) => app.status = format!("send failed: {error}"),
                    }
                } else {
                    app.status = "usage: /dm <fingerprint|uid> <text>".to_string();
                }
            }
            "post" => {
                let mut rest = parts;
                if let (Some(board), Some(rest)) = (rest.next(), rest.next()) {
                    let mut fields = rest.splitn(2, ' ');
                    if let (Some(title), Some(body)) = (fields.next(), fields.next()) {
                        match client.forum(board.trim(), title.trim(), body.trim()).await {
                            Ok(()) => app.status = format!("posted to {}", board.trim()),
                            Err(error) => app.status = format!("forum post failed: {error}"),
                        }
                    } else {
                        app.status = "usage: /post <board> <title> <body>".to_string();
                    }
                } else {
                    app.status = "usage: /post <board> <title> <body>".to_string();
                }
            }
            other => app.status = format!("unknown command /{other}"),
        }
        return Ok(false);
    }

    let channel = app.current_channel();
    match client.post(&channel, input).await {
        Ok(()) => app.status = format!("sent to {channel}"),
        Err(error) => app.status = format!("post failed: {error}"),
    }
    Ok(false)
}

async fn refresh(client: &mut ControlClient, app: &mut App) {
    let channel = app.current_channel();
    match client.read(&channel, HISTORY_LIMIT).await {
        Ok(messages) => {
            let lines = messages
                .into_iter()
                .map(|message| DisplayLine {
                    from: short(&message.from).to_string(),
                    timestamp: message.timestamp,
                    text: message.text,
                })
                .collect();
            app.history.insert(channel, lines);
        }
        Err(error) => app.status = format!("read failed: {error}"),
    }
}

fn short(fingerprint: &str) -> &str {
    fingerprint.get(..8).unwrap_or(fingerprint)
}

fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(frame.area());

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", app.uid),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{}  ", short(&app.fingerprint))),
        Span::raw(format!("peers {}  ", app.peers)),
        Span::styled(app.status.clone(), Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("fantuan"));
    frame.render_widget(header, chunks[0]);

    let body = Layout::horizontal([Constraint::Length(22), Constraint::Min(10)]).split(chunks[1]);

    let channels: Vec<ListItem> = app
        .channels
        .iter()
        .enumerate()
        .map(|(index, channel)| {
            let style = if index == app.current {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(format!(" {channel}")).style(style)
        })
        .collect();
    frame.render_widget(
        List::new(channels).block(Block::default().borders(Borders::ALL).title("channels")),
        body[0],
    );

    let current = app.current_channel();
    let text = app
        .history
        .get(&current)
        .map(|lines| {
            lines
                .iter()
                .map(|line| format!("[{}] {}: {}", line.timestamp, line.from, line.text))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(current)),
        body[1],
    );

    let input = Paragraph::new(app.input.clone())
        .block(Block::default().borders(Borders::ALL).title("message"));
    frame.render_widget(input, chunks[2]);
    frame.set_cursor_position((chunks[2].x + 1 + app.input.len() as u16, chunks[2].y + 1));
}
