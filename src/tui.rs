use crate::intercept::{
    parse_request_text, parse_response_text, serialize_request, serialize_response,
    InterceptId, InterceptedItem, Verdict,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct PendingItem {
    item: InterceptedItem,
    received_at: Instant,
}

struct HistoryEntry {
    id: InterceptId,
    method: String,
    uri: String,
    status: Option<u16>,
    verdict: String,
    _detail: String,
}

enum Mode {
    Normal,
    Editing {
        content: Vec<String>,
        original_text: String,
        cursor: (usize, usize),
        scroll: usize,
    },
}

struct TuiApp {
    rx: mpsc::Receiver<InterceptedItem>,
    active: Arc<AtomicBool>,
    pending: Option<PendingItem>,
    history: Vec<HistoryEntry>,
    history_state: ListState,
    mode: Mode,
    detail_scroll: u16,
}

impl TuiApp {
    fn new(rx: mpsc::Receiver<InterceptedItem>, active: Arc<AtomicBool>) -> Self {
        Self {
            rx,
            active,
            pending: None,
            history: Vec::new(),
            history_state: ListState::default(),
            mode: Mode::Normal,
            detail_scroll: 0,
        }
    }

    fn poll_intercepted(&mut self) {
        if self.pending.is_some() {
            return;
        }
        if let Ok(item) = self.rx.try_recv() {
            self.pending = Some(PendingItem {
                item,
                received_at: Instant::now(),
            });
        }
    }

    fn forward_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            match pending.item {
                InterceptedItem::Request {
                    id,
                    method,
                    uri,
                    headers,
                    body,
                    reply,
                    ..
                } => {
                    let _ = reply.send(Verdict::Forward {
                        headers: Box::new(headers),
                        body,
                        method: None,
                        uri: None,
                        status: None,
                    });
                    self.history.push(HistoryEntry {
                        id,
                        method: method.to_string(),
                        uri: uri.to_string(),
                        status: None,
                        verdict: "FWD".into(),
                        _detail: String::new(),
                    });
                }
                InterceptedItem::Response {
                    id,
                    status,
                    headers,
                    body,
                    reply,
                    ..
                } => {
                    let _ = reply.send(Verdict::Forward {
                        headers: Box::new(headers),
                        body,
                        method: None,
                        uri: None,
                        status: None,
                    });
                    if let Some(entry) = self.history.iter_mut().rev().find(|e| e.id == id - 1) {
                        entry.status = Some(status.as_u16());
                    }
                }
            }
            self.detail_scroll = 0;
        }
    }

    fn drop_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            match pending.item {
                InterceptedItem::Request {
                    id,
                    method,
                    uri,
                    reply,
                    ..
                } => {
                    let _ = reply.send(Verdict::Drop);
                    self.history.push(HistoryEntry {
                        id,
                        method: method.to_string(),
                        uri: uri.to_string(),
                        status: None,
                        verdict: "DROP".into(),
                        _detail: String::new(),
                    });
                }
                InterceptedItem::Response { reply, .. } => {
                    let _ = reply.send(Verdict::Drop);
                }
            }
            self.detail_scroll = 0;
        }
    }

    fn start_edit(&mut self) {
        if let Some(ref pending) = self.pending {
            // Reject editing for binary bodies — would corrupt the payload
            let body = match &pending.item {
                InterceptedItem::Request { body, .. } => body,
                InterceptedItem::Response { body, .. } => body,
            };
            if !crate::intercept::is_text_body(body) {
                return; // binary body, cannot edit as text
            }

            let text = match &pending.item {
                InterceptedItem::Request {
                    method,
                    uri,
                    version,
                    headers,
                    body,
                    ..
                } => serialize_request(method, uri, *version, headers, body),
                InterceptedItem::Response {
                    status,
                    version,
                    headers,
                    body,
                    ..
                } => serialize_response(*status, *version, headers, body),
            };
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            self.mode = Mode::Editing {
                content: lines,
                original_text: text,
                cursor: (0, 0),
                scroll: 0,
            };
        }
    }

    fn finish_edit(&mut self) {
        if let Mode::Editing {
            ref content,
            ref original_text,
            ..
        } = self.mode
        {
            let text = content.join("\r\n");

            // No-op edit: if text unchanged, forward with original bytes
            if text == *original_text {
                self.mode = Mode::Normal;
                self.forward_pending();
                return;
            }
            if let Some(pending) = self.pending.take() {
                match pending.item {
                    InterceptedItem::Request {
                        id, reply, method, uri, ..
                    } => {
                        if let Some((_method, _uri, new_headers, new_body)) =
                            parse_request_text(&text)
                        {
                            // Method/URI edits are intentionally ignored —
                            // the upstream connection is already resolved.
                            // Only header and body edits are applied.
                            let _ = reply.send(Verdict::Forward {
                                headers: Box::new(new_headers),
                                body: new_body,
                                method: None,
                                uri: None,
                                status: None,
                            });
                        } else {
                            let _ = reply.send(Verdict::Drop);
                        }
                        self.history.push(HistoryEntry {
                            id,
                            method: method.to_string(),
                            uri: uri.to_string(),
                            status: None,
                            verdict: "EDIT".into(),
                            _detail: String::new(),
                        });
                    }
                    InterceptedItem::Response {
                        reply, ..
                    } => {
                        if let Some((new_status, new_headers, new_body)) =
                            parse_response_text(&text)
                        {
                            let _ = reply.send(Verdict::Forward {
                                headers: Box::new(new_headers),
                                body: new_body,
                                method: None,
                                uri: None,
                                status: Some(new_status),
                            });
                        } else {
                            let _ = reply.send(Verdict::Drop);
                        }
                    }
                }
            }
        }
        self.mode = Mode::Normal;
        self.detail_scroll = 0;
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match &mut self.mode {
            Mode::Editing {
                content,
                cursor,
                scroll,
                ..
            } => {
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.finish_edit();
                    }
                    KeyCode::Char(c) => {
                        if cursor.0 < content.len() {
                            content[cursor.0].insert(cursor.1, c);
                            cursor.1 += 1;
                        }
                    }
                    KeyCode::Backspace => {
                        if cursor.1 > 0 && cursor.0 < content.len() {
                            cursor.1 -= 1;
                            content[cursor.0].remove(cursor.1);
                        } else if cursor.1 == 0 && cursor.0 > 0 {
                            let line = content.remove(cursor.0);
                            cursor.0 -= 1;
                            cursor.1 = content[cursor.0].len();
                            content[cursor.0].push_str(&line);
                        }
                    }
                    KeyCode::Enter => {
                        if cursor.0 < content.len() {
                            let rest = content[cursor.0].split_off(cursor.1);
                            content.insert(cursor.0 + 1, rest);
                            cursor.0 += 1;
                            cursor.1 = 0;
                        }
                    }
                    KeyCode::Left => {
                        if cursor.1 > 0 {
                            cursor.1 -= 1;
                        }
                    }
                    KeyCode::Right => {
                        if cursor.0 < content.len() && cursor.1 < content[cursor.0].len() {
                            cursor.1 += 1;
                        }
                    }
                    KeyCode::Up => {
                        if cursor.0 > 0 {
                            cursor.0 -= 1;
                            cursor.1 = cursor.1.min(content[cursor.0].len());
                        }
                        if *scroll > 0 && cursor.0 < *scroll {
                            *scroll -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if cursor.0 + 1 < content.len() {
                            cursor.0 += 1;
                            cursor.1 = cursor.1.min(content[cursor.0].len());
                        }
                    }
                    _ => {}
                }
                false
            }
            Mode::Normal => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Char(' ') => {
                    let was = self.active.load(Ordering::Relaxed);
                    self.active.store(!was, Ordering::Relaxed);
                    false
                }
                KeyCode::Char('f') => {
                    self.forward_pending();
                    false
                }
                KeyCode::Char('d') => {
                    self.drop_pending();
                    false
                }
                KeyCode::Char('e') => {
                    self.start_edit();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let i = self.history_state.selected().unwrap_or(0);
                    if i > 0 {
                        self.history_state.select(Some(i - 1));
                    }
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let i = self.history_state.selected().unwrap_or(0);
                    if i + 1 < self.history.len() {
                        self.history_state.select(Some(i + 1));
                    }
                    false
                }
                KeyCode::PageUp => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(10);
                    false
                }
                KeyCode::PageDown => {
                    self.detail_scroll += 10;
                    false
                }
                _ => false,
            },
        }
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(frame.area());

        // Status bar
        let intercept_status = if self.active.load(Ordering::Relaxed) {
            Span::styled(" INTERCEPT ON ", Style::default().fg(Color::Black).bg(Color::Green))
        } else {
            Span::styled(" INTERCEPT OFF ", Style::default().fg(Color::Black).bg(Color::Red))
        };
        let pending_count = if self.pending.is_some() { 1 } else { 0 };
        let status = Line::from(vec![
            intercept_status,
            Span::raw(format!(
                "  Pending: {}  History: {}",
                pending_count,
                self.history.len()
            )),
        ]);
        frame.render_widget(Paragraph::new(status), chunks[0]);

        // Main area
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(chunks[1]);

        // History list
        let items: Vec<ListItem> = self
            .history
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let style = match e.verdict.as_str() {
                    "DROP" => Style::default().fg(Color::Red),
                    "EDIT" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::Green),
                };
                let status_str = e
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "...".into());
                ListItem::new(format!(
                    "{:>3} {} {:>3} {} {}",
                    i + 1,
                    e.verdict,
                    status_str,
                    e.method,
                    truncate_uri(&e.uri, 30)
                ))
                .style(style)
            })
            .collect();
        let history_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" History "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(history_list, main_chunks[0], &mut self.history_state);

        // Right pane
        match &self.mode {
            Mode::Editing {
                content,
                cursor,
                scroll,
                ..
            } => {
                let visible: Vec<Line> = content
                    .iter()
                    .skip(*scroll)
                    .enumerate()
                    .map(|(i, line)| {
                        let actual_line = i + scroll;
                        if actual_line == cursor.0 {
                            // Show cursor position with highlight
                            let mut spans = Vec::new();
                            let col = cursor.1.min(line.len());
                            spans.push(Span::raw(&line[..col]));
                            if col < line.len() {
                                spans.push(Span::styled(
                                    &line[col..col + 1],
                                    Style::default().bg(Color::White).fg(Color::Black),
                                ));
                                spans.push(Span::raw(&line[col + 1..]));
                            } else {
                                spans.push(Span::styled(
                                    " ",
                                    Style::default().bg(Color::White).fg(Color::Black),
                                ));
                            }
                            Line::from(spans)
                        } else {
                            Line::from(line.as_str())
                        }
                    })
                    .collect();
                let editor = Paragraph::new(visible)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" EDITING [Ctrl+S save | Esc cancel] "),
                    )
                    .wrap(Wrap { trim: false });
                frame.render_widget(editor, main_chunks[1]);
            }
            Mode::Normal => {
                let detail_text = if let Some(ref pending) = self.pending {
                    let _header = Span::styled(
                        " PENDING ",
                        Style::default().fg(Color::Black).bg(Color::Yellow),
                    );
                    let body = match &pending.item {
                        InterceptedItem::Request {
                            method,
                            uri,
                            version,
                            headers,
                            body,
                            ..
                        } => serialize_request(method, uri, *version, headers, body),
                        InterceptedItem::Response {
                            status,
                            version,
                            headers,
                            body,
                            ..
                        } => serialize_response(*status, *version, headers, body),
                    };
                    let elapsed = pending.received_at.elapsed();
                    format!(
                        "{} (waiting {:.1}s)\n\n{}",
                        if matches!(pending.item, InterceptedItem::Request { .. }) {
                            "REQUEST"
                        } else {
                            "RESPONSE"
                        },
                        elapsed.as_secs_f32(),
                        body
                    )
                } else {
                    // Show selected history entry or empty
                    if let Some(idx) = self.history_state.selected() {
                        if let Some(entry) = self.history.get(idx) {
                            format!(
                                "#{} {} {} {}\nVerdict: {}",
                                entry.id, entry.method, entry.uri,
                                entry.status.map(|s| s.to_string()).unwrap_or_default(),
                                entry.verdict
                            )
                        } else {
                            "No selection".into()
                        }
                    } else {
                        "Waiting for requests...".into()
                    }
                };

                let detail = Paragraph::new(detail_text)
                    .block(Block::default().borders(Borders::ALL).title(" Detail "))
                    .wrap(Wrap { trim: false })
                    .scroll((self.detail_scroll, 0));
                frame.render_widget(detail, main_chunks[1]);
            }
        }

        // Help bar
        let help = if matches!(self.mode, Mode::Editing { .. }) {
            " Ctrl+S: save & forward | Esc: cancel | Arrows: nav | Note: headers+body only, method/URI ignored"
        } else {
            " f: forward | d: drop | e: edit | space: toggle | j/k: scroll | q: quit"
        };
        frame.render_widget(
            Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
            chunks[2],
        );
    }
}

fn truncate_uri(uri: &str, max: usize) -> String {
    if uri.len() <= max {
        uri.to_string()
    } else {
        format!("{}...", &uri[..max - 3])
    }
}

/// Run the TUI on the current thread (should be called from a dedicated OS thread).
pub fn run_tui(
    rx: mpsc::Receiver<InterceptedItem>,
    active: Arc<AtomicBool>,
) -> io::Result<()> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(rx, active);

    loop {
        terminal.draw(|f| app.render(f))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key) {
                    break;
                }
            }
        }

        app.poll_intercepted();
    }

    terminal::disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
