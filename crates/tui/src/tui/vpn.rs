use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{
    Request, Response, VpnActiveStatus, VpnErrorDetail, VpnProfileSummary,
};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Default, Clone)]
pub(crate) struct VpnData {
    pub(crate) profiles: Vec<VpnProfileSummary>,
    pub(crate) active: Option<VpnActiveStatus>,
    pub(crate) selected_profile: usize,
    pub(crate) error: Option<VpnErrorDetail>,
    pub(crate) focus: VpnFocus,
    pub(crate) enabled: Option<bool>,
    pub(crate) delete_confirmation: Option<String>,
    pub(crate) opened_profile: Option<String>,
    pub(crate) status_known: bool,
    pub(crate) profiles_known: bool,
    pub(crate) chain: Option<Vec<traffic_masq_protocol::VpnHopConfigView>>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnFocus {
    #[default]
    List,
    Connect,
    Details,
    Import,
    Create,
    Settings,
    Delete,
    Route,
    ToggleEnabled,
}

fn actions(screen: Screen) -> &'static [VpnFocus] {
    match screen {
        Screen::VpnProfile => &[VpnFocus::Connect, VpnFocus::Route, VpnFocus::Delete],
        Screen::VpnSettings => &[VpnFocus::ToggleEnabled],
        _ => &[
            VpnFocus::Connect,
            VpnFocus::Details,
            VpnFocus::Create,
            VpnFocus::Import,
            VpnFocus::Settings,
        ],
    }
}

fn selected_name(app: &TuiApp) -> Option<&str> {
    if app.screen == Screen::VpnProfile {
        app.vpn.opened_profile.as_deref()
    } else {
        app.vpn
            .profiles
            .get(app.vpn.selected_profile)
            .map(|p| p.name.as_str())
    }
}

fn standalone_selected(app: &TuiApp) -> bool {
    app.vpn.status_known
        && app
            .vpn
            .active
            .as_ref()
            .is_some_and(|active| Some(active.profile_name.as_str()) == selected_name(app))
}

async fn open_route(app: &mut TuiApp, client: &ApiClient) {
    super::router::load_router_data(app, client).await;
    app.screen = Screen::Router;
}

fn profile_state(app: &TuiApp, name: &str) -> String {
    let tunnel = connection_state(app, name);
    let chain = match &app.vpn.chain {
        None => "chain usage: unknown".into(),
        Some(chain) => {
            let hops: Vec<_> = chain
                .iter()
                .enumerate()
                .filter(|(_, hop)| hop.profile_name == name)
                .map(|(i, _)| (i + 1).to_string())
                .collect();
            if hops.is_empty() {
                "not in saved chain".into()
            } else {
                format!("saved chain: hop {}", hops.join(", "))
            }
        }
    };
    format!("{tunnel} | {chain}")
}

fn connection_state(app: &TuiApp, name: &str) -> &'static str {
    if app.vpn.enabled == Some(false) {
        "VPN disabled"
    } else if !app.vpn.status_known {
        "status unknown"
    } else if let Some(active) = app.vpn.active.as_ref().filter(|a| a.profile_name == name) {
        if active.up {
            "connected"
        } else {
            "interface down"
        }
    } else {
        "disconnected"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnImportField {
    Sources,
    PrivateKey,
    Address,
    PublicKey,
    Endpoint,
    AllowedIps,
    LocalFile,
    Refresh,
    Forwarding,
    Import,
    Cancel,
    Name,
    Path,
    ForwardIp,
    ForwardPort,
    ForwardPassword,
}

#[derive(Clone, Default)]
pub(crate) struct ManualProfile {
    private_key: zeroize::Zeroizing<String>,
    address: String,
    public_key: String,
    endpoint: String,
    allowed_ips: String,
}

impl ManualProfile {
    fn contents(&self) -> Result<String, &'static str> {
        let values = [
            &*self.private_key,
            &self.address,
            &self.public_key,
            &self.endpoint,
            &self.allowed_ips,
        ];
        if values
            .iter()
            .any(|v| v.trim().is_empty() || v.contains(['\n', '\r', '\0']))
        {
            return Err("Complete all WireGuard fields with single-line values");
        }
        Ok(format!("[Interface]\nPrivateKey = {}\nAddress = {}\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\n", self.private_key.trim(), self.address.trim(), self.public_key.trim(), self.endpoint.trim(), self.allowed_ips.trim()))
    }
}

#[derive(Clone)]
pub(crate) struct VpnImportEditor {
    pub(crate) field: VpnImportField,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) cursor: usize,
    pub(crate) sources: Option<(String, Vec<String>)>,
    pub(crate) selected_source: usize,
    pub(crate) source_name: Option<String>,
    pub(crate) manual: Option<ManualProfile>,
    pub(crate) forwarding_enabled: bool,
    pub(crate) forward_ip: String,
    pub(crate) forward_port: String,
    pub(crate) forward_password: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for VpnImportEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnImportEditor")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("forward_ip", &self.forward_ip)
            .field("forward_port", &self.forward_port)
            .field("forward_password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VpnImportEditor {
    fn fields(&self) -> &[VpnImportField] {
        use VpnImportField::*;
        if self.manual.is_some() {
            return if self.forwarding_enabled {
                &[
                    Name,
                    Forwarding,
                    PrivateKey,
                    Address,
                    PublicKey,
                    Endpoint,
                    AllowedIps,
                    ForwardIp,
                    ForwardPort,
                    ForwardPassword,
                    Import,
                    Cancel,
                ]
            } else {
                &[
                    Name, Forwarding, PrivateKey, Address, PublicKey, Endpoint, AllowedIps, Import,
                    Cancel,
                ]
            };
        }
        if self.sources.is_some() {
            return &[Sources, LocalFile, Refresh, Cancel];
        }
        match (self.source_name.is_some(), self.forwarding_enabled) {
            (false, false) => &[Name, Path, Forwarding, Import, Cancel],
            (false, true) => &[
                Name,
                Path,
                Forwarding,
                ForwardIp,
                ForwardPort,
                ForwardPassword,
                Import,
                Cancel,
            ],
            (true, false) => &[Forwarding, Import, Cancel],
            (true, true) => &[
                Forwarding,
                ForwardIp,
                ForwardPort,
                ForwardPassword,
                Import,
                Cancel,
            ],
        }
    }

    fn move_field(&mut self, key: KeyCode) {
        self.field = match key {
            KeyCode::Tab | KeyCode::BackTab => {
                super::input::move_wrapped(self.fields(), self.field, key == KeyCode::Tab)
            }
            _ => super::input::move_clamped(
                self.fields(),
                self.field,
                matches!(key, KeyCode::Down | KeyCode::Right | KeyCode::Enter),
            ),
        };
        self.reset_cursor();
    }

    fn toggle_forwarding(&mut self) {
        self.forwarding_enabled = !self.forwarding_enabled;
        self.field = VpnImportField::Forwarding;
        self.reset_cursor();
    }

    fn open_source(&mut self, forwarding: bool) {
        let Some(name) = self
            .sources
            .as_ref()
            .and_then(|(_, names)| names.get(self.selected_source))
            .cloned()
        else {
            return;
        };
        self.name = name.clone();
        self.source_name = Some(name);
        self.sources = None;
        self.forwarding_enabled = forwarding;
        self.field = if forwarding {
            VpnImportField::ForwardIp
        } else {
            VpnImportField::Forwarding
        };
        self.reset_cursor();
    }

    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            VpnImportField::PrivateKey => Some(&self.manual.as_ref()?.private_key),
            VpnImportField::Address => Some(&self.manual.as_ref()?.address),
            VpnImportField::PublicKey => Some(&self.manual.as_ref()?.public_key),
            VpnImportField::Endpoint => Some(&self.manual.as_ref()?.endpoint),
            VpnImportField::AllowedIps => Some(&self.manual.as_ref()?.allowed_ips),
            VpnImportField::Name => Some(&self.name),
            VpnImportField::Path => Some(&self.path),
            VpnImportField::ForwardIp => Some(&self.forward_ip),
            VpnImportField::ForwardPort => Some(&self.forward_port),
            VpnImportField::ForwardPassword => Some(&self.forward_password),
            _ => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self
            .active_value()
            .map(super::input::grapheme_count)
            .unwrap_or(0);
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let value = match self.field {
            VpnImportField::PrivateKey => &mut self.manual.as_mut()?.private_key,
            VpnImportField::Address => &mut self.manual.as_mut()?.address,
            VpnImportField::PublicKey => &mut self.manual.as_mut()?.public_key,
            VpnImportField::Endpoint => &mut self.manual.as_mut()?.endpoint,
            VpnImportField::AllowedIps => &mut self.manual.as_mut()?.allowed_ips,
            VpnImportField::Name => &mut self.name,
            VpnImportField::Path => &mut self.path,
            VpnImportField::ForwardIp => &mut self.forward_ip,
            VpnImportField::ForwardPort => &mut self.forward_port,
            VpnImportField::ForwardPassword => &mut self.forward_password,
            _ => return None,
        };
        Some(super::input::TextEditor::new(value, &mut self.cursor))
    }
}

pub(super) fn confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    let name = app.vpn.delete_confirmation.as_ref()?;
    Some(super::confirmation::Dialog {
        secondary: None,
        title: "Delete saved VPN profile?",
        action: "Delete",
        lines: vec![
            format!("Profile: {name}"),
            "The saved VPN configuration and its keys will be deleted.".into(),
            "Deletion is immediate and cannot be undone.".into(),
        ],
    })
}

pub(crate) fn render_vpn(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let block = panel(match app.screen {
        Screen::VpnProfile => "VPN profile",
        Screen::VpnSettings => "VPN settings",
        _ => "VPN profiles",
    });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let regions = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(inner);
    let content = regions[0];
    let mut lines = vec![Line::styled(
        match app.vpn.enabled {
            Some(true) => "VPN enabled",
            Some(false) => "VPN disabled — Connect also enables VPN",
            None => "VPN availability unknown — r: refresh",
        },
        Style::default().fg(theme::MUTED),
    )];
    if app.vpn.enabled == Some(true) && app.vpn.status_known {
        if let Some(active) = &app.vpn.active {
            lines.push(Line::from(format!(
                "Active: {} on {} ({})",
                active.profile_name,
                active.interface,
                if active.up { "up" } else { "down" }
            )));
        }
    }
    if let Some(detail) = &app.vpn.error {
        lines.push(Line::styled(
            describe_vpn_error(detail),
            Style::default().fg(theme::BAD),
        ));
    }
    if app.screen == Screen::VpnSettings {
        lines.extend([
            Line::from("Enable/disable requires confirmation; without it, changes roll back."),
            Line::from("To disable: remove the saved chain in Route, select Direct policy,"),
            Line::from("then disconnect the standalone tunnel. This is not an emergency stop."),
            Line::from("Saved profiles remain in the library while VPN is disabled."),
        ]);
    } else if app.screen == Screen::VpnProfile {
        if let Some(name) = selected_name(app) {
            lines.push(Line::styled(
                name.to_owned(),
                Style::default().fg(theme::ACCENT),
            ));
            lines.push(Line::from(profile_state(app, name)));
            lines.push(Line::from(
                "Traffic routing and VPN chains are configured in Route.",
            ));
            if app.router.staged {
                let hops: Vec<_> = app
                    .router
                    .proposed_router_config
                    .vpn_chain
                    .iter()
                    .enumerate()
                    .filter(|(_, hop)| hop.profile_name == name)
                    .map(|(i, _)| (i + 1).to_string())
                    .collect();
                lines.push(Line::from(format!(
                    "Unapplied Route draft: {}",
                    if hops.is_empty() {
                        "profile not in chain".into()
                    } else {
                        format!("hop {}", hops.join(", "))
                    }
                )));
            }
            lines.push(Line::from(
                "Connect/disconnect uses a confirmed router transaction. Chain tunnels are separate.",
            ));
            if let Some(active) = &app.vpn.active {
                if active.profile_name != name && app.vpn.status_known {
                    lines.push(Line::from(format!(
                        "Disconnect profile '{}' before connecting another.",
                        active.profile_name
                    )));
                }
            }
            lines.push(Line::from(
                "Additional action: delete saved profile (confirmation required).",
            ));
        }
    } else {
        if !app.vpn.profiles_known {
            lines.push(Line::styled(
                "Profile library unavailable; displayed entries may be stale.",
                Style::default().fg(theme::WARN),
            ));
        }
        let header = lines.len() as u16;
        let list = Rect::new(
            content.x,
            content.y.saturating_add(header),
            content.width,
            content.height.saturating_sub(header),
        );
        let visible = list.height.max(1) as usize;
        let scroll = app
            .vpn
            .selected_profile
            .saturating_sub(visible - 1)
            .min(app.vpn.profiles.len().saturating_sub(visible));
        app.ui.list_area = Some(list);
        app.ui.list_row_height = 1;
        app.ui.list_count = app.vpn.profiles.len();
        app.ui.list_scroll_offset = scroll;
        if app.vpn.profiles.is_empty() {
            lines.push(Line::from(if app.vpn.profiles_known {
                "(none imported)"
            } else {
                "(library unavailable)"
            }));
        }
        for (index, profile) in app
            .vpn
            .profiles
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible)
        {
            let selected = index == app.vpn.selected_profile;
            lines.push(Line::styled(
                format!(
                    "{} {} — {}",
                    if selected { "▶" } else { " " },
                    profile.name,
                    connection_state(app, &profile.name)
                ),
                if selected {
                    Style::default().fg(theme::ACCENT)
                } else {
                    Style::default()
                },
            ));
        }
    }
    let lines = if app.screen == Screen::Vpn {
        lines
    } else {
        super::layout::wrap_lines(lines, content.width)
    };
    frame.render_widget(Paragraph::new(lines), content);
    let mut x = regions[1].x;
    let mut y = regions[1].y;
    for (slot, focus) in actions(app.screen).iter().enumerate() {
        let label = match focus {
            VpnFocus::Connect if standalone_selected(app) => "[Disconnect]",
            VpnFocus::Connect => "[Connect]",
            VpnFocus::Details => "[Open profile]",
            VpnFocus::Create => "[Create]",
            VpnFocus::Import => "[Import]",
            VpnFocus::Settings => "[VPN settings]",
            VpnFocus::Delete => "[Delete profile]",
            VpnFocus::Route => "[Open Route]",
            VpnFocus::ToggleEnabled if app.vpn.enabled == Some(true) => "[Disable VPN]",
            VpnFocus::ToggleEnabled => "[Enable VPN]",
            VpnFocus::List => continue,
        };
        let width = label.len() as u16;
        if x + width > regions[1].right() {
            x = regions[1].x;
            y += 1;
        }
        let rect = Rect::new(x, y, width.min(regions[1].width), 1).intersection(regions[1]);
        if rect.is_empty() {
            continue;
        }
        app.ui.buttons.push((rect, slot));
        frame.render_widget(
            Paragraph::new(label).style(if app.vpn.focus == *focus {
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::SELECTED_BG)
            } else {
                Style::default().fg(theme::ACCENT)
            }),
            rect,
        );
        x += width + 1;
    }
    frame.render_widget(
        Paragraph::new(
            if app.screen == Screen::Vpn && app.vpn.focus == VpnFocus::List {
                "r: refresh | Enter: connect / disconnect | Tab: actions | Esc: back"
            } else {
                "r: refresh | Enter: activate action | Esc: back"
            },
        )
        .style(Style::default().fg(theme::MUTED)),
        Rect::new(
            regions[1].x,
            regions[1].bottom().saturating_sub(1),
            regions[1].width,
            1,
        ),
    );
}

pub(crate) fn render_vpn_import(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    use VpnImportField::*;
    let Some(editor) = &app.vpn_import else {
        return;
    };
    let block = panel(if editor.manual.is_some() {
        "Create VPN profile"
    } else {
        "Import VPN profile"
    });
    let inner = block.inner(area);
    let style = Style::default().fg(theme::ACCENT);
    let mut lines = Vec::new();
    let mut interactions = Vec::new();
    if let Some((directory, names)) = &editor.sources {
        lines.push(Line::from(format!("WireGuard configs: {directory}")));
        lines.push(Line::from(
            "Up/Down: select | Tab: actions | Enter/Space: open",
        ));
        let visible_rows = inner.height.saturating_sub(6).max(1) as usize;
        let start = editor.selected_source.saturating_sub(visible_rows - 1);
        if names.is_empty() {
            lines.push(Line::from(
                "No .conf files found. Use Local file or Refresh.",
            ));
        }
        for (index, name) in names.iter().enumerate().skip(start).take(visible_rows) {
            lines.push(super::layout::field_row(
                name,
                editor.field == Sources && index == editor.selected_source,
                style,
            ));
        }
    } else if let Some(source) = &editor.source_name {
        lines.push(Line::from(format!("Source config: {source}")));
    }
    for (slot, field) in editor.fields().iter().enumerate() {
        if *field == Sources {
            continue;
        }
        let selected = editor.field == *field;
        let row = lines.len() as u16;
        let line = match field {
            Address | PublicKey | Endpoint | AllowedIps => {
                let manual = editor.manual.as_ref().unwrap();
                let (label, value) = match field {
                    Address => ("Address (CIDR)", &manual.address),
                    PublicKey => ("Peer public key", &manual.public_key),
                    Endpoint => ("Endpoint (host:port)", &manual.endpoint),
                    _ => ("Allowed IPs", &manual.allowed_ips),
                };
                super::layout::text_field_row(label, value, selected, editor.cursor, true, style)
            }
            Name | Path | ForwardIp | ForwardPort => {
                let (label, value) = match field {
                    Name => ("Name", editor.name.as_str()),
                    Path => ("File path", editor.path.as_str()),
                    ForwardIp => ("Forward IP", editor.forward_ip.as_str()),
                    _ => ("Forward port", editor.forward_port.as_str()),
                };
                super::layout::text_field_row(label, value, selected, editor.cursor, true, style)
            }
            ForwardPassword | PrivateKey => {
                let (label, value) = if *field == PrivateKey {
                    (
                        "Private key: ",
                        &*editor.manual.as_ref().unwrap().private_key,
                    )
                } else {
                    ("Forward password: ", &*editor.forward_password)
                };
                let mut line = super::layout::field_row(label, selected, style);
                line.spans.extend(super::input::render_masked_with_cursor(
                    super::input::grapheme_count(value),
                    editor.cursor,
                    selected,
                    '•',
                    line.style,
                ));
                line
            }
            _ => {
                let label = match field {
                    Forwarding if editor.forwarding_enabled => "Type: WireGuard + wgobfs",
                    Forwarding => "Type: WireGuard",
                    Import if editor.manual.is_some() => "Save profile",
                    Import => "Import",
                    Cancel => "Cancel",
                    LocalFile => "Local file",
                    Refresh => "Refresh",
                    _ => unreachable!("text fields handled above"),
                };
                interactions.push((row, slot));
                super::layout::field_row(label, selected, style)
            }
        };
        lines.push(line);
    }
    if editor.sources.is_none() && editor.forwarding_enabled {
        lines.push(Line::from("All forwarding fields are required."));
    }
    lines.push(Line::from(
        "Arrows/Tab: focus | Enter/Space: action | Esc: cancel",
    ));
    let offset = super::layout::focused_lines_offset(&lines, inner.height) as u16;
    for (row, slot) in interactions {
        if row >= offset && row - offset < inner.height {
            app.ui.buttons.push((
                Rect::new(inner.x, inner.y + row - offset, inner.width, 1),
                slot,
            ));
        }
    }
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), inner);
}

pub(crate) fn enter_list(app: &mut TuiApp) {
    app.screen = Screen::Vpn;
    app.vpn.opened_profile = None;
    app.vpn.focus = VpnFocus::List;
}

pub(crate) fn focus_import_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.vpn_import.as_mut() {
        if let Some(field) = editor.fields().get(slot).copied() {
            editor.field = field;
            editor.reset_cursor();
        }
    }
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(focus) = actions(app.screen).get(slot) {
        app.vpn.focus = *focus;
    }
}

pub(crate) async fn handle_vpn_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    if app.vpn.delete_confirmation.is_some() {
        match key {
            KeyCode::Esc => app.vpn.delete_confirmation = None,
            KeyCode::Enter => {
                let name = app
                    .vpn
                    .delete_confirmation
                    .take()
                    .expect("confirmation open");
                vpn_delete_profile(app, client, name).await;
            }
            _ => {}
        }
        return;
    }
    let fields: Vec<_> = if app.screen == Screen::Vpn {
        std::iter::once(VpnFocus::List)
            .chain(actions(app.screen).iter().copied())
            .collect()
    } else {
        actions(app.screen).to_vec()
    };
    match key {
        KeyCode::Char('r') => load_vpn_data(app, client).await,
        KeyCode::Esc if app.screen != Screen::Vpn => {
            enter_list(app);
        }
        KeyCode::Esc if app.vpn.focus != VpnFocus::List => app.vpn.focus = VpnFocus::List,
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Tab | KeyCode::BackTab => {
            app.vpn.focus = super::input::move_wrapped(&fields, app.vpn.focus, key == KeyCode::Tab);
        }
        KeyCode::Up if app.vpn.focus == VpnFocus::List => {
            app.vpn.selected_profile = app.vpn.selected_profile.saturating_sub(1);
        }
        KeyCode::Down if app.vpn.focus == VpnFocus::List => {
            if app.vpn.selected_profile + 1 < app.vpn.profiles.len() {
                app.vpn.selected_profile += 1;
            } else {
                app.vpn.focus = VpnFocus::Connect;
            }
        }
        KeyCode::Up | KeyCode::Left => {
            app.vpn.focus = super::input::move_clamped(&fields, app.vpn.focus, false)
        }
        KeyCode::Down | KeyCode::Right => {
            app.vpn.focus = super::input::move_clamped(&fields, app.vpn.focus, true)
        }
        KeyCode::Home => app.vpn.selected_profile = 0,
        KeyCode::End => app.vpn.selected_profile = app.vpn.profiles.len().saturating_sub(1),
        KeyCode::Enter | KeyCode::Char(' ') => match app.vpn.focus {
            VpnFocus::Details => {
                if app.vpn.profiles_known {
                    if let Some(name) = selected_name(app).map(str::to_owned) {
                        app.vpn.opened_profile = Some(name);
                        app.screen = Screen::VpnProfile;
                        app.vpn.focus = VpnFocus::Connect;
                        load_vpn_chain_usage(app, client).await;
                    }
                }
            }
            VpnFocus::List | VpnFocus::Connect => {
                if standalone_selected(app) {
                    vpn_deactivate(app, client).await;
                } else {
                    vpn_activate_selected(app, client).await;
                }
            }
            VpnFocus::Create => {
                app.vpn_import = Some(VpnImportEditor {
                    field: VpnImportField::Name,
                    name: String::new(),
                    path: String::new(),
                    cursor: 0,
                    sources: None,
                    selected_source: 0,
                    source_name: None,
                    manual: Some(ManualProfile {
                        allowed_ips: "0.0.0.0/0".into(),
                        ..Default::default()
                    }),
                    forwarding_enabled: false,
                    forward_ip: String::new(),
                    forward_port: String::new(),
                    forward_password: Default::default(),
                });
                app.screen = Screen::VpnImport;
            }
            VpnFocus::Import => open_vpn_import(app, client).await,
            VpnFocus::Delete => vpn_delete_selected(app),
            VpnFocus::Route => open_route(app, client).await,
            VpnFocus::Settings => {
                app.screen = Screen::VpnSettings;
                app.vpn.focus = VpnFocus::ToggleEnabled;
            }
            VpnFocus::ToggleEnabled => toggle_vpn_enabled(app, client).await,
        },
        _ => {}
    }
}

async fn toggle_vpn_enabled(app: &mut TuiApp, client: &ApiClient) {
    let Some(enabled) = app.vpn.enabled else {
        load_vpn_data(app, client).await;
        app.push_message(LogLevel::Warn, "Refresh VPN status before changing it");
        return;
    };
    if set_vpn_enabled(app, client, !enabled).await {
        load_vpn_data(app, client).await;
    }
}

async fn set_vpn_enabled(app: &mut TuiApp, client: &ApiClient, enabled: bool) -> bool {
    app.vpn.enabled = None;
    app.vpn.status_known = false;
    match client.request(&Request::SetVpnEnabled { enabled }).await {
        Ok(Response::RouterError { detail }) => {
            app.push_message(
                LogLevel::Error,
                super::router::describe_router_error(&detail),
            );
        }
        Ok(Response::RouterTransactionPending { token, plan }) => {
            super::router::open_pending(app, token, app.screen, Some(plan));
            app.push_message(
                LogLevel::Info,
                "VPN availability applied temporarily; confirm before connecting a profile",
            );
            return false;
        }
        Ok(Response::VpnConfig { enabled: actual }) if actual == enabled => {
            app.vpn.enabled = Some(enabled);
            app.push_message(
                LogLevel::Info,
                if enabled {
                    "VPN enabled and saved"
                } else {
                    "VPN disabled and saved"
                },
            );
            return true;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
    false
}

async fn open_vpn_import(app: &mut TuiApp, client: &ApiClient) {
    let sources = match client.request(&Request::VpnListSources).await {
        Ok(Response::VpnSources {
            directory,
            profiles,
        }) => Some((directory, profiles.into_iter().map(|p| p.name).collect())),
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
            None
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            None
        }
        _ => None,
    };
    app.vpn_import = Some(VpnImportEditor {
        field: if sources.is_some() {
            VpnImportField::Sources
        } else {
            VpnImportField::Name
        },
        name: String::new(),
        path: String::new(),
        cursor: 0,
        sources,
        selected_source: 0,
        source_name: None,
        manual: None,
        forwarding_enabled: false,
        forward_ip: String::new(),
        forward_port: String::new(),
        forward_password: zeroize::Zeroizing::new(String::new()),
    });
    app.screen = Screen::VpnImport;
}

pub(crate) async fn handle_vpn_import_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.vpn_import.as_mut() else {
        enter_list(app);
        return;
    };

    use VpnImportField::*;
    if key == KeyCode::Esc
        || (editor.field == Cancel && matches!(key, KeyCode::Enter | KeyCode::Char(' ')))
    {
        app.vpn_import = None;
        enter_list(app);
        return;
    }
    if editor.sources.is_some() {
        if !editor.fields().contains(&editor.field) {
            editor.field = Sources;
        }
        // Shortcuts activate the same focusable actions as Enter/Space.
        let key = match key {
            KeyCode::Char('p') => {
                editor.field = LocalFile;
                KeyCode::Enter
            }
            KeyCode::Char('r') => {
                editor.field = Refresh;
                KeyCode::Enter
            }
            other => other,
        };
        match key {
            KeyCode::Up if editor.field == Sources => {
                editor.selected_source = editor.selected_source.saturating_sub(1)
            }
            KeyCode::Down
                if editor.field == Sources
                    && editor.selected_source + 1 < editor.sources.as_ref().unwrap().1.len() =>
            {
                editor.selected_source += 1
            }
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Tab
            | KeyCode::BackTab => editor.move_field(key),
            KeyCode::Char('o') => editor.open_source(true),
            KeyCode::Enter | KeyCode::Char(' ') => match editor.field {
                Sources => editor.open_source(false),
                LocalFile => {
                    editor.sources = None;
                    editor.field = Name;
                    editor.reset_cursor();
                }
                Refresh => open_vpn_import(app, client).await,
                _ => {}
            },
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::F(2) => editor.toggle_forwarding(),
        KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => editor.move_field(key),
        KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
            if editor.field == Forwarding =>
        {
            editor.toggle_forwarding()
        }
        KeyCode::Enter | KeyCode::Char(' ') if editor.field == Import => {
            vpn_import_submit(app, client).await
        }
        KeyCode::Enter => editor.move_field(KeyCode::Down),
        KeyCode::Left | KeyCode::Right if editor.active_value().is_none() => editor.move_field(key),
        other => {
            if let Some(mut input) = editor.active_editor() {
                input.handle_key(other);
            }
        }
    }
}

pub(crate) async fn load_vpn_data(app: &mut TuiApp, client: &ApiClient) {
    let selected = selected_name(app).map(str::to_owned);
    // The event loop cancels background reads when input arrives. Collect the
    // observations before replacing known state, so Enter can use the previous
    // snapshot when it interrupts a refresh. Completed failures still invalidate it.
    let config = client.request(&Request::GetVpnConfig).await;
    let profiles = client.request(&Request::VpnListProfiles).await;
    let status = if matches!(&config, Ok(Response::VpnConfig { enabled: true })) {
        Some(client.request(&Request::VpnStatus).await)
    } else {
        None
    };
    let chain = if app.screen == Screen::VpnProfile {
        Some(client.request(&Request::GetRouterConfig).await)
    } else {
        None
    };
    app.vpn.error = None;
    app.vpn.enabled = None;
    app.vpn.status_known = false;
    app.vpn.profiles_known = false;
    app.vpn.chain = None;
    match config {
        Ok(Response::VpnConfig { enabled }) => app.vpn.enabled = Some(enabled),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN availability unavailable: {result:?}"),
        ),
    }
    match profiles {
        Ok(Response::VpnProfiles { profiles }) => {
            app.vpn.profiles = profiles;
            app.vpn.profiles_known = true;
            app.vpn.selected_profile = selected
                .as_ref()
                .and_then(|name| app.vpn.profiles.iter().position(|p| &p.name == name))
                .unwrap_or(
                    app.vpn
                        .selected_profile
                        .min(app.vpn.profiles.len().saturating_sub(1)),
                );
        }
        Ok(Response::VpnError { detail }) => app.vpn.error = Some(detail),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN profile library unavailable: {result:?}"),
        ),
    }
    if let Some(status) = status {
        accept_vpn_status(app, status);
    }
    if let Some(chain) = chain {
        accept_vpn_chain_usage(app, chain);
    }
}

async fn load_vpn_chain_usage(app: &mut TuiApp, client: &ApiClient) {
    let result = client.request(&Request::GetRouterConfig).await;
    accept_vpn_chain_usage(app, result);
}

fn accept_vpn_chain_usage(app: &mut TuiApp, result: anyhow::Result<Response>) {
    app.vpn.chain = None;
    match result {
        Ok(Response::RouterConfig { config }) => app.vpn.chain = Some(config.vpn_chain),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN chain usage unavailable: {result:?}"),
        ),
    }
}

async fn refresh_vpn_status(app: &mut TuiApp, client: &ApiClient) {
    let result = client.request(&Request::VpnStatus).await;
    accept_vpn_status(app, result);
}

fn accept_vpn_status(app: &mut TuiApp, result: anyhow::Result<Response>) {
    app.vpn.status_known = false;
    match result {
        Ok(Response::VpnStatus { active }) => {
            app.vpn.active = active;
            app.vpn.status_known = true;
        }
        Ok(Response::VpnError { detail }) => app.vpn.error = Some(detail),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN connection status unavailable: {result:?}"),
        ),
    }
}

async fn vpn_activate_selected(app: &mut TuiApp, client: &ApiClient) {
    if !app.vpn.profiles_known || app.vpn.enabled.is_none() {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN availability and profile library before connecting",
        );
        return;
    }
    let Some(name) = selected_name(app).map(str::to_owned) else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };
    if !app.vpn.profiles.iter().any(|p| p.name == name) {
        app.push_message(
            LogLevel::Warn,
            "Profile is no longer in the library; return to the list",
        );
        return;
    }
    if app.vpn.enabled == Some(false) {
        if !set_vpn_enabled(app, client, true).await {
            return;
        }
        refresh_vpn_status(app, client).await;
    }
    if !app.vpn.status_known {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN connection status before connecting",
        );
        return;
    }
    if let Some(active) = &app.vpn.active {
        app.push_message(
            LogLevel::Warn,
            format!("Disconnect profile '{}' first", active.profile_name),
        );
        return;
    }

    app.vpn.status_known = false;
    match client.request(&Request::VpnActivate { name }).await {
        Ok(Response::RouterError { detail }) => {
            app.push_message(
                LogLevel::Error,
                super::router::describe_router_error(&detail),
            );
        }
        Ok(Response::RouterTransactionPending { token, plan }) => {
            super::router::open_pending(app, token, app.screen, Some(plan));
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(Response::VpnActivated { active }) => {
            app.vpn.error = None;
            app.push_message(
                LogLevel::Info,
                format!(
                    "VPN connected: {} (interface {})",
                    active.profile_name, active.interface
                ),
            );
            app.vpn.active = Some(active);
            app.vpn.status_known = true;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn vpn_deactivate(app: &mut TuiApp, client: &ApiClient) {
    if !app.vpn.status_known {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN connection status before disconnecting",
        );
        return;
    }
    app.vpn.status_known = false;
    match client.request(&Request::VpnDeactivate).await {
        Ok(Response::RouterError { detail }) => {
            app.push_message(
                LogLevel::Error,
                super::router::describe_router_error(&detail),
            );
        }
        Ok(Response::RouterTransactionPending { token, plan }) => {
            super::router::open_pending(app, token, app.screen, Some(plan));
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(Response::VpnDeactivated) => {
            app.vpn.error = None;
            app.push_message(LogLevel::Info, "VPN disconnected");
            app.vpn.active = None;
            app.vpn.status_known = true;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn vpn_delete_selected(app: &mut TuiApp) {
    if !app.vpn.profiles_known {
        app.push_message(LogLevel::Warn, "Refresh profile library before deleting");
        return;
    }
    let Some(name) = selected_name(app).map(str::to_owned) else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };

    if app.router.staged
        && app
            .router
            .proposed_router_config
            .vpn_chain
            .iter()
            .any(|hop| hop.profile_name == name)
    {
        app.push_message(
            LogLevel::Warn,
            "Profile is used by the unapplied Route draft; remove it from the draft first",
        );
        return;
    }
    app.vpn.delete_confirmation = Some(name);
}

async fn vpn_delete_profile(app: &mut TuiApp, client: &ApiClient, name: String) {
    match client.request(&Request::VpnDeleteProfile { name }).await {
        Ok(Response::VpnProfileDeleted { name }) => {
            app.push_message(LogLevel::Info, format!("Deleted profile {name}"));
            load_vpn_data(app, client).await;
            enter_list(app);
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn vpn_import_submit(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.vpn_import else {
        enter_list(app);
        return;
    };
    if editor
        .sources
        .as_ref()
        .is_some_and(|(_, names)| names.is_empty())
    {
        return;
    }
    let forwarding = if !editor.forwarding_enabled {
        None
    } else {
        let (Ok(ip), Ok(port)) = (
            editor.forward_ip.trim().parse::<std::net::IpAddr>(),
            editor.forward_port.trim().parse::<u16>(),
        ) else {
            app.push_message(
                LogLevel::Warn,
                "Enter a valid forwarding IP, port and password",
            );
            return;
        };
        if port == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || editor.forward_password.is_empty()
            || editor.forward_password.contains('\0')
        {
            app.push_message(
                LogLevel::Warn,
                "Enter a valid forwarding IP, nonzero port and password",
            );
            return;
        }
        Some(traffic_masq_protocol::WgObfsForwarding {
            ip,
            port,
            password: editor.forward_password.clone(),
        })
    };
    let source = editor.source_name.clone().or_else(|| {
        editor
            .sources
            .as_ref()
            .and_then(|(_, names)| names.get(editor.selected_source).cloned())
    });
    if let Some(name) = source {
        match client
            .request(&Request::VpnImportFromSource { name, forwarding })
            .await
        {
            Ok(Response::VpnProfileImported { name }) => {
                app.push_message(LogLevel::Info, format!("Imported profile {name}"));
                app.vpn_import = None;
                enter_list(app);
                load_vpn_data(app, client).await;
            }
            Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
            Ok(Response::VpnError { detail }) => {
                app.push_message(LogLevel::Error, describe_vpn_error(&detail))
            }
            Ok(response) => app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            ),
            Err(error) => app.push_message(LogLevel::Error, error.to_string()),
        }
        return;
    }
    let name = editor.name.trim().to_string();
    let path = editor.path.trim().to_string();
    if name.is_empty() || (editor.manual.is_none() && path.is_empty()) {
        app.push_message(
            LogLevel::Warn,
            "Both profile name and file path are required",
        );
        return;
    }

    let mut contents = if let Some(manual) = &editor.manual {
        match manual.contents() {
            Ok(contents) => contents,
            Err(message) => {
                app.push_message(LogLevel::Warn, message);
                return;
            }
        }
    } else {
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => {
                app.push_message(LogLevel::Error, format!("Failed to read {path}: {error}"));
                return;
            }
        }
    };
    let result = client
        .request(&Request::VpnImportProfile {
            name,
            contents: contents.clone(),
            forwarding,
        })
        .await;
    contents.zeroize();

    match result {
        Ok(Response::VpnProfileImported { name }) => {
            app.push_message(LogLevel::Info, format!("Imported profile {name}"));
            app.vpn_import = None;
            enter_list(app);
            load_vpn_data(app, client).await;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn describe_vpn_error(detail: &VpnErrorDetail) -> String {
    match detail {
        VpnErrorDetail::VpnDisabled => "VPN is disabled; enable it in VPN settings".to_string(),
        VpnErrorDetail::NotFound { name } => format!("Profile '{name}' not found"),
        VpnErrorDetail::InvalidProfile { message } => format!("Invalid profile: {message}"),
        VpnErrorDetail::AlreadyActive => {
            "A VPN tunnel is already active; disconnect before activating another profile"
                .to_string()
        }
        VpnErrorDetail::NotActive => "No VPN tunnel is currently active".to_string(),
        VpnErrorDetail::ProfileInUse { name } => {
            format!("Profile '{name}' is in use; disconnect or remove it from the router VPN chain first")
        }
        VpnErrorDetail::ForeignInterfaceConflict => {
            "tm-wg0 is occupied by an interface this daemon does not own; remove it manually"
                .to_string()
        }
        VpnErrorDetail::Other { message } => message.clone(),
    }
}

#[cfg(test)]
mod tests;
