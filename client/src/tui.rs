use std::{io, time::Duration};

use clipmesh_protocol::{crypto::ClipboardItem, routing, wire::ChannelSummary};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
};

use crate::{
    commands, history,
    state::{self, Paths},
    sync::{self, EngineCommand, Snapshot},
};

pub async fn run(paths: Paths) -> anyhow::Result<()> {
    let engine = sync::start(paths.clone())?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, &paths, &engine).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let stop = engine.stop().await;
    result.and(stop)
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    paths: &Paths,
    engine: &sync::Engine,
) -> anyhow::Result<()> {
    let tabs = ["Status", "Channels", "Clipboard", "History", "Security"];
    let mut selected = 0usize;
    let mut channel_selected = 0usize;
    let mut available_channels = Vec::new();
    let mut channels_loaded = false;
    let mut channels_error = None;
    let mut history_selected = 0usize;
    loop {
        let snapshot = engine.snapshot.borrow().clone();
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(2),
                ])
                .split(frame.area());
            let titles: Vec<Line<'_>> = tabs
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    Line::from(Span::styled(
                        *value,
                        if index == selected {
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        },
                    ))
                })
                .collect();
            frame.render_widget(
                Tabs::new(titles)
                    .select(selected)
                    .block(
                        Block::default()
                            .title(" ClipMesh · foreground sync ")
                            .borders(Borders::ALL),
                    )
                    .highlight_style(Style::default().fg(Color::Cyan)),
                chunks[0],
            );
            match selected {
                0 => status(frame, chunks[1], &snapshot),
                1 => channels(
                    frame,
                    chunks[1],
                    paths,
                    &available_channels,
                    channel_selected,
                    channels_error.as_deref(),
                ),
                2 => clipboard(frame, chunks[1], &snapshot),
                3 => history_view(frame, chunks[1], paths, history_selected),
                _ => security(frame, chunks[1], paths),
            }
            let help = match selected {
                1 => "↑/↓ select  j join  s send  r receive  c create  u refresh  ←/→ tabs  q quit",
                3 => "↑/↓ select  y copy  e resend  d delete  ←/→ tabs  q quit",
                _ => "←/→ tabs  p pair  t send text  space pause  q quit",
            };
            frame.render_widget(
                Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
                chunks[2],
            );
        })?;
        if selected == 1 && !channels_loaded {
            channels_loaded = true;
            match commands::available_channels(paths).await {
                Ok(channels) => {
                    available_channels = channels;
                    channels_error = None;
                    let length = channel_entries(paths, &available_channels).len();
                    channel_selected = channel_selected.min(length.saturating_sub(1));
                }
                Err(error) => channels_error = Some(error.to_string()),
            }
            continue;
        }
        if event::poll(Duration::from_millis(150))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Left => selected = selected.saturating_sub(1),
                KeyCode::Right => selected = (selected + 1).min(tabs.len() - 1),
                KeyCode::Up if selected == 1 => {
                    channel_selected = channel_selected.saturating_sub(1);
                }
                KeyCode::Down if selected == 1 => {
                    let length = channel_entries(paths, &available_channels).len();
                    if length > 0 {
                        channel_selected = (channel_selected + 1).min(length - 1);
                    }
                }
                KeyCode::Up if selected == 3 => {
                    history_selected = history_selected.saturating_sub(1);
                }
                KeyCode::Down if selected == 3 => {
                    let length = history::recent(&paths.history_db, 100)?.len();
                    if length > 0 {
                        history_selected = (history_selected + 1).min(length - 1);
                    }
                }
                KeyCode::Char('1'..='5') => {
                    if let KeyCode::Char(value) = key.code {
                        selected = value.to_digit(10).unwrap() as usize - 1;
                    }
                }
                KeyCode::Char('p') => {
                    suspend(terminal)?;
                    let server = commands::prompt("Server URL: ", false)?;
                    let name = commands::prompt("Device name: ", false)?;
                    let result = commands::pair(paths, &server, &name, None).await;
                    resume(terminal)?;
                    result?;
                    let _ = engine.commands.send(EngineCommand::Reload).await;
                    channels_loaded = false;
                }
                KeyCode::Char('t') => {
                    suspend(terminal)?;
                    let text = commands::prompt("Text to copy and send: ", false)?;
                    resume(terminal)?;
                    if !text.is_empty() {
                        engine
                            .commands
                            .send(EngineCommand::Publish(ClipboardItem::Text(
                                text.into_bytes(),
                            )))
                            .await?;
                    }
                }
                KeyCode::Char('s') if selected == 1 => {
                    if let Some(channel_id) =
                        selected_channel(paths, &available_channels, channel_selected)
                    {
                        toggle_route(paths, channel_id, true)?;
                    }
                }
                KeyCode::Char('r') if selected == 1 => {
                    if let Some(channel_id) =
                        selected_channel(paths, &available_channels, channel_selected)
                    {
                        toggle_route(paths, channel_id, false)?;
                    }
                }
                KeyCode::Char('c') if selected == 1 => {
                    suspend(terminal)?;
                    let name = commands::prompt("New channel name: ", false)?;
                    let result = commands::create_channel(paths, &name).await;
                    resume(terminal)?;
                    result?;
                    channels_loaded = false;
                    let _ = engine.commands.send(EngineCommand::Reload).await;
                }
                KeyCode::Char('j') if selected == 1 => {
                    if let Some(channel_id) =
                        selected_channel(paths, &available_channels, channel_selected)
                        && !state::load(paths)?
                            .channels
                            .iter()
                            .any(|channel| channel.id == channel_id)
                    {
                        suspend(terminal)?;
                        let result = commands::join_channel(paths, channel_id).await;
                        resume(terminal)?;
                        result?;
                        channels_loaded = false;
                        let _ = engine.commands.send(EngineCommand::Reload).await;
                    }
                }
                KeyCode::Char('u') if selected == 1 => {
                    channels_loaded = false;
                    channels_error = None;
                }
                KeyCode::Char('y') if selected == 3 => {
                    if let Some(id) = selected_history(paths, history_selected)? {
                        let item = commands::history_item(paths, id)?;
                        engine.commands.send(EngineCommand::Copy(item)).await?;
                    }
                }
                KeyCode::Char('e') if selected == 3 => {
                    if let Some(id) = selected_history(paths, history_selected)? {
                        let item = commands::history_item(paths, id)?;
                        engine.commands.send(EngineCommand::Publish(item)).await?;
                    }
                }
                KeyCode::Char('d') if selected == 3 => {
                    if let Some(id) = selected_history(paths, history_selected)? {
                        suspend(terminal)?;
                        let answer =
                            commands::prompt("Delete this local history entry? [y/N] ", false)?;
                        resume(terminal)?;
                        if answer.eq_ignore_ascii_case("y") {
                            history::delete(&paths.history_db, id)?;
                        }
                    }
                }
                KeyCode::Char(' ') => {
                    let value = state::load(paths)?;
                    commands::update_pause(
                        paths,
                        Some(!value.pause_sending),
                        Some(!value.pause_receiving),
                    )?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn status(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, value: &Snapshot) {
    let state = if !value.configured {
        "Not paired"
    } else if value.connected {
        "Connected"
    } else {
        "Offline"
    };
    let body = format!(
        "{state}\n\nServer   {}\nURL      {}\nDevice   {}\nChannels {} · {} send · {} receive\nLast sync {}\n\n{}",
        value.server_name,
        value.server_url,
        value.device_name,
        value.channel_count,
        value.send_count,
        value.receive_count,
        value
            .last_sync
            .map(|time| chrono::DateTime::from_timestamp_millis(time)
                .unwrap()
                .to_rfc3339())
            .unwrap_or_else(|| "—".into()),
        value.last_error.as_deref().unwrap_or("")
    );
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::default().title(" Status ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}
fn channels(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    paths: &Paths,
    available: &[ChannelSummary],
    selected: usize,
    error: Option<&str>,
) {
    let value = state::load(paths).unwrap_or_default();
    let entries = channel_entries_from_state(&value, available);
    let mut items: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(index, channel)| {
            let joined = value.channels.iter().any(|joined| joined.id == channel.id);
            let route = value
                .routes
                .iter()
                .find(|route| route.channel_id == channel.id);
            let members = channel
                .member_count
                .map(|count| count.to_string())
                .unwrap_or_else(|| "—".into());
            ListItem::new(format!(
                "{} {}  [{}] members:{}  send:{} receive:{}\n    {}",
                if index == selected { "›" } else { " " },
                channel.name,
                if joined { "joined" } else { "available" },
                members,
                yn(route.is_some_and(|v| v.send_enabled)),
                yn(route.is_some_and(|v| v.receive_enabled)),
                channel.id
            ))
        })
        .collect();
    if items.is_empty() {
        items.push(ListItem::new(match error {
            Some(error) => format!("Could not load server channels: {error}\nPress u to retry."),
            None => "No channels are available. Press c to create one.".into(),
        }));
    } else if let Some(error) = error {
        items.push(ListItem::new(format!(
            "\nServer refresh failed: {error}\nShowing locally joined channels. Press u to retry."
        )));
    }
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(" Server channels · select one and press j to join ")
                .borders(Borders::ALL),
        ),
        area,
    );
}
fn clipboard(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, value: &Snapshot) {
    frame.render_widget(Paragraph::new(format!("Type: {}\nSize: {} bytes\n\n{}\n\nPress t to enter text, copy it locally, and send it through the active route.", value.current_type.as_deref().unwrap_or("—"), value.current_size, value.current_preview.as_deref().unwrap_or("No supported clipboard item yet."))).block(Block::default().title(" Current clipboard ").borders(Borders::ALL)).wrap(Wrap { trim: false }), area);
}
fn history_view(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    paths: &Paths,
    selected: usize,
) {
    let rows = history::recent(&paths.history_db, 100).unwrap_or_default();
    let items = rows
        .iter()
        .enumerate()
        .map(|(index, row)| ListItem::new(format_history_row(index == selected, row)))
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(" Encrypted local history · newest first ")
                .borders(Borders::ALL),
        ),
        area,
    );
}
fn security(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, paths: &Paths) {
    let value = state::load(paths).unwrap_or_default();
    frame.render_widget(Paragraph::new(format!("Sending:   {}\nReceiving: {}\n\nTokens, device keys, channel root keys, and the outbox key are stored only in the OS credential store. History retains authenticated channel ciphertext.\n\nBackground mode: clipmesh service install/start/stop/status", if value.pause_sending { "paused" } else { "active" }, if value.pause_receiving { "paused" } else { "active" })).block(Block::default().title(" Security & settings ").borders(Borders::ALL)).wrap(Wrap { trim: false }), area);
}
fn suspend(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
fn resume(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(())
}
fn yn(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

#[derive(Clone, Debug)]
struct ChannelEntry {
    id: uuid::Uuid,
    name: String,
    member_count: Option<u32>,
}

fn channel_entries(paths: &Paths, available: &[ChannelSummary]) -> Vec<ChannelEntry> {
    channel_entries_from_state(&state::load(paths).unwrap_or_default(), available)
}

fn channel_entries_from_state(
    value: &state::StateFile,
    available: &[ChannelSummary],
) -> Vec<ChannelEntry> {
    let mut entries = available
        .iter()
        .map(|channel| ChannelEntry {
            id: channel.id,
            name: channel.name.clone(),
            member_count: Some(channel.member_count),
        })
        .collect::<Vec<_>>();
    entries.extend(
        value
            .channels
            .iter()
            .filter(|channel| !available.iter().any(|remote| remote.id == channel.id))
            .map(|channel| ChannelEntry {
                id: channel.id,
                name: channel.name.clone(),
                member_count: None,
            }),
    );
    entries
}

fn selected_channel(
    paths: &Paths,
    available: &[ChannelSummary],
    selected: usize,
) -> Option<uuid::Uuid> {
    channel_entries(paths, available)
        .get(selected)
        .map(|channel| channel.id)
}

fn toggle_route(paths: &Paths, channel_id: uuid::Uuid, send: bool) -> anyhow::Result<()> {
    let mut value = state::load(paths)?;
    if !value
        .channels
        .iter()
        .any(|channel| channel.id == channel_id)
    {
        return Ok(());
    }
    let enabled = value
        .routes
        .iter()
        .find(|route| route.channel_id == channel_id)
        .is_some_and(|route| {
            if send {
                route.send_enabled
            } else {
                route.receive_enabled
            }
        });
    routing::set_route(
        &mut value.routes,
        channel_id,
        send.then_some(!enabled),
        (!send).then_some(!enabled),
    )
    .map_err(anyhow::Error::msg)?;
    state::save(paths, &value)
}

fn format_history_row(selected: bool, row: &history::HistoryRow) -> String {
    format!(
        "{} {} · {} · {} · {}\n    from {} · {}",
        if selected { "›" } else { " " },
        row.direction,
        row.content_type,
        row.channel_name,
        row.delivery_status,
        row.origin_device_name,
        row.local_id
    )
}

fn selected_history(paths: &Paths, selected: usize) -> anyhow::Result<Option<uuid::Uuid>> {
    Ok(history::recent(&paths.history_db, 100)?
        .get(selected)
        .map(|row| row.local_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_row_identifies_the_origin_device() {
        let row = history::HistoryRow {
            local_id: uuid::Uuid::nil(),
            item_id: uuid::Uuid::nil(),
            channel_id: uuid::Uuid::nil(),
            channel_name: "Shared".into(),
            origin_device_name: "Living-room PC".into(),
            direction: "received".into(),
            content_type: "text/plain".into(),
            stored_at: 0,
            delivery_status: "received".into(),
        };

        let rendered = format_history_row(true, &row);

        assert!(rendered.contains("from Living-room PC"));
    }
}
