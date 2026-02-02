use chrono::Local;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui_image::StatefulImage;

use crate::app::{App, Mode};
use crate::store::EntrySource;
use crate::sync::ConnectionStatus;

/// Render the entire UI.
pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Min(5),    // main content
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    render_title_bar(frame, chunks[0], app);
    render_main(frame, chunks[1], app);
    render_status_bar(frame, chunks[2], app);
}

fn render_title_bar(frame: &mut Frame, area: Rect, app: &App) {
    let ws_indicator = match app.ws_status {
        ConnectionStatus::Connected => {
            Span::styled(" [WS: Connected] ", Style::default().fg(Color::Green))
        }
        ConnectionStatus::Connecting => {
            Span::styled(" [WS: Connecting...] ", Style::default().fg(Color::Yellow))
        }
        ConnectionStatus::Disconnected => {
            Span::styled(" [WS: Disconnected] ", Style::default().fg(Color::DarkGray))
        }
    };

    let title = Line::from(vec![
        Span::styled(
            " o-clip ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("| {} entries ", app.total_count)),
        ws_indicator,
    ]);

    let bar = Paragraph::new(title).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

fn render_main(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_list(frame, chunks[0], app);
    render_preview(frame, chunks[1], app);
}

fn render_list(frame: &mut Frame, area: Rect, app: &App) {
    let title = if app.mode == Mode::Search {
        format!(" Search: {} ", app.search_query)
    } else {
        " Clipboard History ".to_string()
    };

    let items: Vec<ListItem> = app
        .entries
        .iter()
        .map(|entry| {
            let type_tag = match entry.content_type.as_str() {
                "text" => Span::styled("[T] ", Style::default().fg(Color::Blue)),
                "url" => Span::styled("[U] ", Style::default().fg(Color::Magenta)),
                "files" => Span::styled("[F] ", Style::default().fg(Color::Green)),
                "image" => Span::styled("[I] ", Style::default().fg(Color::Yellow)),
                _ => Span::styled("[?] ", Style::default().fg(Color::DarkGray)),
            };

            let time_str = entry
                .created_at
                .with_timezone(&Local)
                .format("%H:%M:%S")
                .to_string();
            let time_span =
                Span::styled(format!("{time_str} "), Style::default().fg(Color::DarkGray));

            let source_tag = match entry.source {
                EntrySource::Remote => Span::styled("R ", Style::default().fg(Color::Cyan)),
                EntrySource::Local => Span::styled("L ", Style::default().fg(Color::DarkGray)),
            };

            let preview_text =
                truncate_line(&entry.preview, area.width.saturating_sub(18) as usize);
            let preview_span = Span::raw(preview_text);

            let line = Line::from(vec![time_span, source_tag, type_tag, preview_span]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(if app.mode == Mode::Search {
                    Color::Yellow
                } else {
                    Color::White
                })),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 60))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_preview(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some(entry) = app.selected_entry().cloned() else {
        let paragraph = Paragraph::new(Text::raw("No entry selected"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Preview ")
                    .border_style(Style::default().fg(Color::White)),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
        return;
    };

    let title = format!(
        " Preview [{}] - {} bytes ",
        entry.content_type, entry.byte_size
    );

    // For entries with a loaded image preview (image type or file pointing to an image).
    let is_image_file_entry = entry.content_type == "files"
        && entry
            .to_clipboard_content()
            .is_some_and(|c| matches!(&c, crate::clipboard::ClipboardContent::Files(paths) if paths.iter().any(|p| crate::app::is_image_file(p))));

    if (entry.content_type == "image" || is_image_file_entry) && app.image_preview.is_some() {
        let metadata = entry
            .to_clipboard_content()
            .map(|c| match c {
                crate::clipboard::ClipboardContent::Image(info) => {
                    format!(
                        " {}x{} {:?} | {:.1} KB",
                        info.width,
                        info.height,
                        info.format,
                        info.data_size as f64 / 1024.0,
                    )
                }
                crate::clipboard::ClipboardContent::Files(paths) => paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            })
            .unwrap_or_default();

        // Split area: image takes most space, metadata gets 1 line at bottom.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        // Render image inside a bordered block.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::White));
        let inner = block.inner(chunks[0]);
        frame.render_widget(block, chunks[0]);

        let image_widget = StatefulImage::default();
        if let Some(ref mut proto) = app.image_preview {
            frame.render_stateful_widget(image_widget, inner, proto);
        }

        // Metadata line below the image.
        let meta_line =
            Paragraph::new(Span::styled(metadata, Style::default().fg(Color::DarkGray)))
                .style(Style::default().bg(Color::Black));
        frame.render_widget(meta_line, chunks[1]);
        return;
    }

    // Non-image entries (or images without decoded data): text preview.
    let display = match entry.content_type.as_str() {
        "text" | "url" => entry
            .to_clipboard_content()
            .map(|c| match c {
                crate::clipboard::ClipboardContent::Text(t) => t,
                crate::clipboard::ClipboardContent::Url(u) => u,
                _ => entry.content.clone(),
            })
            .unwrap_or_else(|| entry.content.clone()),
        "files" => entry
            .to_clipboard_content()
            .map(|c| match c {
                crate::clipboard::ClipboardContent::Files(paths) => paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => entry.content.clone(),
            })
            .unwrap_or_else(|| entry.content.clone()),
        "image" => entry
            .to_clipboard_content()
            .map(|c| match c {
                crate::clipboard::ClipboardContent::Image(info) => {
                    format!(
                        "Image:\n  Width: {} px\n  Height: {} px\n  Bits/pixel: {}\n  Size: {:.1} KB\n  Format: {:?}",
                        info.width,
                        info.height,
                        info.bits_per_pixel,
                        info.data_size as f64 / 1024.0,
                        info.format,
                    )
                }
                _ => entry.content.clone(),
            })
            .unwrap_or_else(|| entry.content.clone()),
        _ => entry.content.clone(),
    };

    let paragraph = Paragraph::new(Text::raw(display))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::White)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let msg = if let Some(ref status) = app.status_message {
        Span::styled(format!(" {status} "), Style::default().fg(Color::Green))
    } else {
        Span::raw("")
    };

    let keybinds = match app.mode {
        Mode::Normal => " q:Quit  j/k:Navigate  Enter:Copy  d:Delete  /:Search  r:Reconnect WS ",
        Mode::Search => " Esc:Cancel  Enter:Confirm  Type to search... ",
    };

    let line = Line::from(vec![
        msg,
        Span::styled(keybinds, Style::default().fg(Color::DarkGray)),
    ]);

    let bar = Paragraph::new(line).style(Style::default().bg(Color::Black));
    frame.render_widget(bar, area);
}

fn truncate_line(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or(s);
    if line.len() > max {
        format!(
            "{}...",
            &line[..line.floor_char_boundary(max.saturating_sub(3))]
        )
    } else {
        line.to_string()
    }
}
