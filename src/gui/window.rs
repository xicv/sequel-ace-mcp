//! The egui window: renders [`ViewState`] and forwards button clicks as
//! [`GrantChoice`]s. Deliberately thin — every state transition lives in
//! the unit-tested reducer (`super::app`) and the connection loop
//! (`super::companion`).

use super::SessionInfo;
use super::app::{Status, ViewState, apply_event, apply_not_delivered};
use super::companion::CompanionEvent;
use crate::approval::GrantChoice;
use std::time::{Duration, Instant};

pub struct ApprovalsApp {
    state: ViewState,
    choices: tokio::sync::mpsc::Sender<GrantChoice>,
    events: std::sync::mpsc::Receiver<CompanionEvent>,
    /// Edit buffer for the pending snippet (egui TextEdit wants &mut
    /// String); re-synced whenever the pending request id changes.
    snippet_buf: String,
    snippet_for: Option<String>,
    sessions: Vec<SessionInfo>,
    sessions_refreshed: Instant,
    /// Smoke-test support: close the window after N frames.
    smoke_remaining: Option<u32>,
    frames_seen: u64,
}

impl ApprovalsApp {
    pub fn new(
        state: ViewState,
        choices: tokio::sync::mpsc::Sender<GrantChoice>,
        events: std::sync::mpsc::Receiver<CompanionEvent>,
        smoke_frames: Option<u32>,
    ) -> Self {
        Self {
            state,
            choices,
            events,
            snippet_buf: String::new(),
            snippet_for: None,
            sessions: Vec::new(),
            sessions_refreshed: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now),
            smoke_remaining: smoke_frames,
            frames_seen: 0,
        }
    }

    fn send_choice(&mut self, choice: GrantChoice) {
        if let Some(p) = self.state.pending.as_mut() {
            p.answering = Some(choice.clone());
        }
        // blocking_send is the sanctioned way to hand a value into the
        // async companion loop from this non-async UI thread.
        if self.choices.blocking_send(choice.clone()).is_err() {
            apply_not_delivered(&mut self.state, choice);
        }
    }

    fn render(&mut self, ui: &mut egui::Ui) {
        ui.heading("sequel-mcp approvals");
        ui.add_space(4.0);

        // Status line.
        let (color, label) = match &self.state.status {
            Status::Connecting => (egui::Color32::YELLOW, "connecting…".to_string()),
            Status::Waiting => (
                egui::Color32::LIGHT_GREEN,
                "waiting for approval requests".to_string(),
            ),
            Status::Disconnected(reason) => (
                egui::Color32::LIGHT_RED,
                format!("no server ({reason}) — retrying"),
            ),
        };
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("●").color(color).strong());
            ui.label(label);
        });
        ui.label(
            egui::RichText::new(format!("socket: {}", self.state.socket.display()))
                .small()
                .weak(),
        );
        let live = self.sessions.iter().filter(|s| s.alive).count();
        ui.label(
            egui::RichText::new(if live == 0 {
                "servers live: 0 — start one with `sequel-mcp serve`".to_string()
            } else {
                format!(
                    "servers live: {live} (pids {})",
                    self.sessions
                        .iter()
                        .filter(|s| s.alive)
                        .map(|s| s.pid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .small()
            .weak(),
        );
        ui.add_space(6.0);

        // Pending request card, or the idle placeholder.
        let mut action: Option<GrantChoice> = None;
        if let Some(p) = self.state.pending.as_ref() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!(" {} ", p.request.category.to_uppercase()))
                            .background_color(category_color(&p.request.category))
                            .color(egui::Color32::WHITE)
                            .strong(),
                    );
                    ui.label(egui::RichText::new("confirmation required").strong());
                });
                ui.add_space(6.0);
                egui::Grid::new("request-fields")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("connection");
                        ui.strong(&p.request.connection);
                        ui.end_row();
                        if let Some(db) = &p.request.database {
                            ui.label("database");
                            ui.label(db);
                            ui.end_row();
                        }
                        if !p.request.tables.is_empty() {
                            ui.label("tables");
                            ui.label(p.request.tables.join(", "));
                            ui.end_row();
                        }
                    });
                ui.add_space(4.0);
                egui::Frame::default()
                    .fill(ui.visuals().code_bg_color)
                    .inner_margin(egui::Margin::symmetric(8, 8))
                    .corner_radius(egui::CornerRadius::same(4))
                    .show(ui, |ui| {
                        let rows = 2.max(snippet_rows(&self.snippet_buf)).min(12);
                        ui.add(
                            egui::TextEdit::multiline(&mut self.snippet_buf)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(rows)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                    });
                let secs = p.arrived.elapsed().as_secs();
                if secs >= 55 {
                    ui.label(
                        egui::RichText::new(format!(
                            "waiting {secs}s — server deadline is 60s, this may already be expired"
                        ))
                        .color(egui::Color32::from_rgb(0xff, 0xb3, 0x00)),
                    );
                } else {
                    ui.label(egui::RichText::new(format!("waiting {secs}s")).weak());
                }
                ui.add_space(4.0);
                match &p.answering {
                    Some(choice) => {
                        ui.label(format!("delivering {}…", choice_word(choice)));
                    }
                    None => {
                        ui.horizontal(|ui| {
                            if ui
                                .add_sized([160.0, 32.0], egui::Button::new("Approve once"))
                                .clicked()
                            {
                                action = Some(GrantChoice::Once);
                            }
                            if ui
                                .add_sized([190.0, 32.0], egui::Button::new("Approve for session"))
                                .clicked()
                            {
                                action = Some(GrantChoice::Session);
                            }
                            if ui
                                .add_sized(
                                    [120.0, 32.0],
                                    egui::Button::new(
                                        egui::RichText::new("Decline").color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(0xb7, 0x1c, 0x1c)),
                                )
                                .clicked()
                            {
                                action = Some(GrantChoice::Decline);
                            }
                        });
                    }
                }
            });
        } else {
            ui.label(
                egui::RichText::new(
                    "No pending request. When the server needs a confirmation it appears here.",
                )
                .weak(),
            );
        }

        // History.
        ui.add_space(8.0);
        ui.separator();
        ui.label(egui::RichText::new("Recent answers").strong());
        if self.state.history.is_empty() {
            ui.weak("nothing answered yet");
        } else {
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .show(ui, |ui| {
                    egui::Grid::new("history")
                        .num_columns(4)
                        .spacing([12.0, 3.0])
                        .show(ui, |ui| {
                            for h in self.state.history.iter().take(50) {
                                ui.monospace(&h.ts);
                                ui.label(
                                    egui::RichText::new(&h.choice)
                                        .color(choice_color(h.choice.as_str())),
                                );
                                ui.label(&h.connection);
                                ui.weak(&h.result);
                                ui.end_row();
                            }
                        });
                });
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.weak(format!(
                "answered this session: {} · frames: {}",
                self.state.answered_total, self.frames_seen
            ));
        });

        if let Some(choice) = action {
            self.send_choice(choice);
        }
    }
}

impl eframe::App for ApprovalsApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frames_seen += 1;
        while let Ok(event) = self.events.try_recv() {
            apply_event(&mut self.state, event);
        }
        if self.sessions_refreshed.elapsed() >= Duration::from_secs(5) {
            self.sessions = super::live_sessions();
            self.sessions_refreshed = Instant::now();
        }
        // Re-sync the snippet edit buffer when the pending request changes.
        let pending_id = self.state.pending.as_ref().map(|p| p.request.id.clone());
        if pending_id != self.snippet_for {
            self.snippet_for = pending_id;
            self.snippet_buf = self
                .state
                .pending
                .as_ref()
                .map(|p| p.request.snippet.clone())
                .unwrap_or_default();
        }

        self.render(ui);

        // Repaint cadence: often enough for the pending countdown, rarely
        // otherwise (the companion queues events; egui polls them).
        let busy = self.state.pending.is_some();
        ui.ctx().request_repaint_after(if busy {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(1)
        });

        if let Some(n) = &mut self.smoke_remaining {
            *n = n.saturating_sub(1);
            if *n == 0 {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }
}

fn choice_word(choice: &GrantChoice) -> &'static str {
    match choice {
        GrantChoice::Once => "once",
        GrantChoice::Session => "session",
        GrantChoice::Decline => "decline",
    }
}

fn choice_color(word: &str) -> egui::Color32 {
    match word {
        "once" => egui::Color32::LIGHT_GREEN,
        "session" => egui::Color32::LIGHT_BLUE,
        "decline" => egui::Color32::LIGHT_RED,
        _ => egui::Color32::GRAY,
    }
}

fn category_color(category: &str) -> egui::Color32 {
    let c = category.to_ascii_lowercase();
    if c.contains("ddl") || c.contains("admin") || c.contains("drop") {
        egui::Color32::from_rgb(0xc6, 0x28, 0x28)
    } else if c.contains("write")
        || c.contains("insert")
        || c.contains("update")
        || c.contains("delete")
    {
        egui::Color32::from_rgb(0xef, 0x6c, 0x00)
    } else {
        egui::Color32::from_rgb(0x37, 0x47, 0x4f)
    }
}

fn snippet_rows(snippet: &str) -> usize {
    snippet.lines().count()
}
