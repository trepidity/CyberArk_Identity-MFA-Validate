# SAML Assertion Comparison Tool — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a side-by-side SAML assertion comparison feature to seahorse with 4 toggleable diff modes (XML, hex, c14n, validation) for debugging signature validation failures.

**Architecture:** Two new screens (`CompareInput`, `CompareView`) added to the existing ratatui TUI. A new `saml/diff.rs` module implements LCS-based line diff, character sub-diff, and byte diff with no external crates. Rendering and input handling for the compare screens live in `tui/compare.rs`.

**Tech Stack:** Rust, ratatui 0.29, crossterm 0.28, existing saml modules (decoder, parser, c14n, validator)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/saml/diff.rs` | Create | LCS line diff, character sub-diff, byte diff engine |
| `src/tui/compare.rs` | Create | Render + input handling for CompareInput and CompareView screens |
| `src/saml/mod.rs` | Modify | Add `pub mod diff;` |
| `src/tui/app.rs` | Modify | Add `CompareInput`/`CompareView` to Screen enum, add ComparePane/CompareMode types, add compare fields to App |
| `src/tui/mod.rs` | Modify | Add `pub mod compare;` |
| `src/tui/ui.rs` | Modify | Add dispatch to compare render functions, add 4th menu item |
| `src/tui/input.rs` | Modify | Add dispatch to compare input handler, update env_select bounds |
| `src/main.rs` | Modify | Reset compare state when returning to EnvSelect |

---

### Task 1: Diff Engine — Data Types and LCS Line Diff

**Files:**
- Create: `seahorse/src/saml/diff.rs`
- Modify: `seahorse/src/saml/mod.rs`

- [ ] **Step 1: Create diff.rs with data structures**

Create `seahorse/src/saml/diff.rs`:

```rust
/// Diff engine for SAML assertion comparison.
/// LCS-based line diff with character-level sub-diff and byte-level comparison.

#[derive(Debug, Clone)]
pub enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
    Changed {
        left: String,
        right: String,
        left_spans: Vec<(usize, usize)>,
        right_spans: Vec<(usize, usize)>,
    },
}

#[derive(Debug, Clone)]
pub struct DiffResult {
    pub lines: Vec<DiffLine>,
    pub left_total: usize,
    pub right_total: usize,
    pub diff_count: usize,
}

#[derive(Debug, Clone)]
pub struct ByteDiffRow {
    pub offset: usize,
    pub left_bytes: Vec<u8>,
    pub right_bytes: Vec<u8>,
    pub diffs: Vec<usize>,
}
```

- [ ] **Step 2: Add `pub mod diff;` to saml/mod.rs**

In `seahorse/src/saml/mod.rs`, add `pub mod diff;` after the existing module declarations.

- [ ] **Step 3: Implement LCS line diff**

Add to `seahorse/src/saml/diff.rs`:

```rust
pub fn diff_lines(left: &str, right: &str) -> DiffResult {
    let left_lines: Vec<&str> = left.lines().collect();
    let right_lines: Vec<&str> = right.lines().collect();
    let m = left_lines.len();
    let n = right_lines.len();

    // Build LCS table
    let mut table = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if left_lines[i - 1] == right_lines[j - 1] {
                table[i][j] = table[i - 1][j - 1] + 1;
            } else {
                table[i][j] = table[i - 1][j].max(table[i][j - 1]);
            }
        }
    }

    // Backtrack to produce diff
    let mut lines = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && left_lines[i - 1] == right_lines[j - 1] {
            lines.push(DiffLine::Same(left_lines[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            lines.push(DiffLine::Added(right_lines[j - 1].to_string()));
            j -= 1;
        } else {
            lines.push(DiffLine::Removed(left_lines[i - 1].to_string()));
            i -= 1;
        }
    }
    lines.reverse();

    // Post-process: pair adjacent Removed+Added into Changed
    let lines = pair_changes(lines);
    let diff_count = lines.iter().filter(|l| !matches!(l, DiffLine::Same(_))).count();

    DiffResult {
        left_total: m,
        right_total: n,
        diff_count,
        lines,
    }
}

fn pair_changes(input: Vec<DiffLine>) -> Vec<DiffLine> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if i + 1 < input.len() {
            if let (DiffLine::Removed(ref left), DiffLine::Added(ref right)) =
                (&input[i], &input[i + 1])
            {
                let (left_spans, right_spans) = char_diff_spans(left, right);
                result.push(DiffLine::Changed {
                    left: left.clone(),
                    right: right.clone(),
                    left_spans,
                    right_spans,
                });
                i += 2;
                continue;
            }
        }
        result.push(input[i].clone());
        i += 1;
    }
    result
}
```

- [ ] **Step 4: Implement character-level sub-diff**

Add to `seahorse/src/saml/diff.rs`:

```rust
fn char_diff_spans(left: &str, right: &str) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let left_chars: Vec<char> = left.chars().collect();
    let right_chars: Vec<char> = right.chars().collect();
    let m = left_chars.len();
    let n = right_chars.len();

    // LCS on characters
    let mut table = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if left_chars[i - 1] == right_chars[j - 1] {
                table[i][j] = table[i - 1][j - 1] + 1;
            } else {
                table[i][j] = table[i - 1][j].max(table[i][j - 1]);
            }
        }
    }

    // Find which chars are NOT in LCS (those are the diffs)
    let mut left_diff = vec![true; m];
    let mut right_diff = vec![true; n];
    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if left_chars[i - 1] == right_chars[j - 1] {
            left_diff[i - 1] = false;
            right_diff[j - 1] = false;
            i -= 1;
            j -= 1;
        } else if table[i - 1][j] >= table[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }

    (collapse_spans(&left_diff), collapse_spans(&right_diff))
}

fn collapse_spans(diffs: &[bool]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < diffs.len() {
        if diffs[i] {
            let start = i;
            while i < diffs.len() && diffs[i] {
                i += 1;
            }
            spans.push((start, i));
        } else {
            i += 1;
        }
    }
    spans
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles with no errors (warnings about dead code are OK at this stage)

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/saml/diff.rs seahorse/src/saml/mod.rs
git commit -m "feat: add diff engine with LCS line diff and character sub-diff"
```

---

### Task 2: Diff Engine — Byte Diff and Filtered Output

**Files:**
- Modify: `seahorse/src/saml/diff.rs`

- [ ] **Step 1: Implement byte diff**

Add to `seahorse/src/saml/diff.rs`:

```rust
pub fn diff_bytes(left: &[u8], right: &[u8]) -> Vec<ByteDiffRow> {
    let max_len = left.len().max(right.len());
    let row_count = (max_len + 15) / 16;
    let mut rows = Vec::with_capacity(row_count);

    for row_idx in 0..row_count {
        let offset = row_idx * 16;
        let left_end = (offset + 16).min(left.len());
        let right_end = (offset + 16).min(right.len());

        let left_chunk = if offset < left.len() {
            left[offset..left_end].to_vec()
        } else {
            Vec::new()
        };
        let right_chunk = if offset < right.len() {
            right[offset..right_end].to_vec()
        } else {
            Vec::new()
        };

        let max_chunk = left_chunk.len().max(right_chunk.len());
        let mut diffs = Vec::new();
        for i in 0..max_chunk {
            let lb = left_chunk.get(i);
            let rb = right_chunk.get(i);
            if lb != rb {
                diffs.push(i);
            }
        }

        rows.push(ByteDiffRow {
            offset,
            left_bytes: left_chunk,
            right_bytes: right_chunk,
            diffs,
        });
    }
    rows
}
```

- [ ] **Step 2: Implement filtered diff output (diffs-only with context)**

Add to `seahorse/src/saml/diff.rs`:

```rust
pub fn filter_diff_lines(result: &DiffResult, context: usize) -> Vec<(usize, &DiffLine)> {
    let mut visible = vec![false; result.lines.len()];

    // Mark diff lines and their context
    for (i, line) in result.lines.iter().enumerate() {
        if !matches!(line, DiffLine::Same(_)) {
            let start = i.saturating_sub(context);
            let end = (i + context + 1).min(result.lines.len());
            for j in start..end {
                visible[j] = true;
            }
        }
    }

    result
        .lines
        .iter()
        .enumerate()
        .filter(|(i, _)| visible[*i])
        .collect()
}

pub fn filter_byte_diff(rows: &[ByteDiffRow]) -> Vec<(usize, &ByteDiffRow)> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| !row.diffs.is_empty())
        .collect()
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles with no errors

- [ ] **Step 4: Commit**

```bash
git add seahorse/src/saml/diff.rs
git commit -m "feat: add byte diff and filtered diff output to diff engine"
```

---

### Task 3: App State — Screen Enum, ComparePane, CompareMode

**Files:**
- Modify: `seahorse/src/tui/app.rs`

- [ ] **Step 1: Add CompareInput and CompareView to Screen enum**

In `seahorse/src/tui/app.rs`, add two variants to the `Screen` enum (after `SamlView`):

```rust
    CompareInput,
    CompareView,
```

- [ ] **Step 2: Add CompareMode enum and ComparePane struct**

Add before the `App` struct in `seahorse/src/tui/app.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompareMode {
    Xml,
    Hex,
    C14n,
    Validation,
}

#[derive(Debug, Clone)]
pub struct ComparePane {
    pub input_mode: SamlInputMode,
    pub paste_buffer: String,
    pub file_path: String,
    pub raw_bytes: Option<Vec<u8>>,
    pub decoded_xml: Option<String>,
    pub decode_status: Option<String>,
}

impl Default for ComparePane {
    fn default() -> Self {
        Self {
            input_mode: SamlInputMode::Paste,
            paste_buffer: String::new(),
            file_path: String::new(),
            raw_bytes: None,
            decoded_xml: None,
            decode_status: None,
        }
    }
}
```

- [ ] **Step 3: Add compare fields to App struct**

Add these fields to the `App` struct (after the existing `idp_cert_input_active` field):

```rust
    // Compare mode
    pub compare_active_pane: usize,
    pub compare_panes: [ComparePane; 2],
    pub compare_mode: CompareMode,
    pub compare_diff_only: bool,
    pub compare_scroll_offset: u16,
    pub compare_h_scroll_offset: u16,
    pub compare_diff_result: Option<crate::saml::diff::DiffResult>,
    pub compare_byte_diff: Option<Vec<crate::saml::diff::ByteDiffRow>>,
    pub compare_validation: Option<(crate::saml::validator::ValidationReport, crate::saml::validator::ValidationReport)>,
```

- [ ] **Step 4: Update App::new() with default values**

In the `App::new()` function, add initializers for the new fields:

```rust
            compare_active_pane: 0,
            compare_panes: [ComparePane::default(), ComparePane::default()],
            compare_mode: CompareMode::Xml,
            compare_diff_only: false,
            compare_scroll_offset: 0,
            compare_h_scroll_offset: 0,
            compare_diff_result: None,
            compare_byte_diff: None,
            compare_validation: None,
```

- [ ] **Step 5: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles (warnings about unused variants are OK)

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/tui/app.rs
git commit -m "feat: add CompareInput/CompareView screens, ComparePane, CompareMode to app state"
```

---

### Task 4: CompareInput Screen — Rendering

**Files:**
- Create: `seahorse/src/tui/compare.rs`
- Modify: `seahorse/src/tui/ui.rs`

- [ ] **Step 1: Create compare.rs with CompareInput rendering**

Create `seahorse/src/tui/compare.rs`:

```rust
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::app::{App, CompareMode, SamlInputMode};
use crate::saml::diff::{DiffLine, DiffResult, ByteDiffRow};

pub fn render_compare_input(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(frame.area());

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[0]);

    for (idx, pane_area) in panes.iter().enumerate() {
        let is_active = app.compare_active_pane == idx;
        let label = if idx == 0 { "Assertion A" } else { "Assertion B" };
        let border_color = if is_active { Color::Cyan } else { Color::DarkGray };

        let block = Block::default()
            .title(format!(" {} ", label))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(*pane_area);
        frame.render_widget(block, *pane_area);

        let pane = &app.compare_panes[idx];
        let mut lines = Vec::new();

        // Mode indicator
        let mode_str = match pane.input_mode {
            SamlInputMode::Paste => "[Paste Mode]",
            SamlInputMode::File => "[File Mode]",
        };
        lines.push(Line::from(Span::styled(
            mode_str,
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(""));

        // Content
        match pane.input_mode {
            SamlInputMode::Paste => {
                if pane.paste_buffer.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "Paste SAML assertion here...",
                        Style::default().fg(Color::DarkGray),
                    )));
                } else {
                    let preview: String = pane.paste_buffer.chars().take(200).collect();
                    for line in preview.lines() {
                        lines.push(Line::from(line.to_string()));
                    }
                    if pane.paste_buffer.len() > 200 {
                        lines.push(Line::from(Span::styled(
                            format!("... ({} bytes total)", pane.paste_buffer.len()),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
            }
            SamlInputMode::File => {
                if pane.file_path.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "Enter file path or press F3 to browse...",
                        Style::default().fg(Color::DarkGray),
                    )));
                } else {
                    lines.push(Line::from(pane.file_path.clone()));
                }
            }
        }

        // Status
        if let Some(ref status) = pane.decode_status {
            lines.push(Line::from(""));
            let color = if pane.decoded_xml.is_some() {
                Color::Green
            } else {
                Color::Red
            };
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(color),
            )));
        }

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner);
    }

    // Status bar
    let both_decoded =
        app.compare_panes[0].decoded_xml.is_some() && app.compare_panes[1].decoded_xml.is_some();
    let hint = if both_decoded {
        " Tab: switch pane | m: paste/file | F3: browse | Enter: decode | F5: compare | q: quit "
    } else {
        " Tab: switch pane | m: paste/file | F3: browse | Enter: decode | q: quit "
    };
    let bar = Paragraph::new(Line::from(Span::styled(
        hint,
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(bar, outer[1]);
}
```

- [ ] **Step 2: Add module declaration and render dispatch**

In `seahorse/src/tui/mod.rs`, add `pub mod compare;` after the existing module declarations.

In `seahorse/src/tui/ui.rs`, add `use crate::tui::compare;` at the top, then in the `render()` function's match block, add:

```rust
        Screen::CompareInput => compare::render_compare_input(frame, app),
        Screen::CompareView => compare::render_compare_view(frame, app),
```

Note: `render_compare_view` will be implemented in Task 6. For now add a stub in `compare.rs`:

```rust
pub fn render_compare_view(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let block = Block::default()
        .title(" Compare View (TODO) ")
        .borders(Borders::ALL);
    frame.render_widget(block, area);
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add seahorse/src/tui/compare.rs seahorse/src/tui/ui.rs
git commit -m "feat: add CompareInput screen rendering"
```

---

### Task 5: CompareInput Screen — Input Handling and Menu Integration

**Files:**
- Modify: `seahorse/src/tui/compare.rs`
- Modify: `seahorse/src/tui/input.rs`
- Modify: `seahorse/src/tui/ui.rs` (env_select menu item)

- [ ] **Step 1: Add input handling functions to compare.rs**

Add to `seahorse/src/tui/compare.rs`:

```rust
use crossterm::event::KeyCode;
use crate::saml::decoder::decode_saml_input;

/// Called from input.rs with KeyCode (not Event). Paste events are handled
/// separately in input.rs's paste block, matching the existing SamlInput pattern.
pub fn handle_compare_input(app: &mut App, key_code: KeyCode) {
    match key_code {
        KeyCode::Tab => {
            app.compare_active_pane = 1 - app.compare_active_pane;
        }
        KeyCode::Char('m') => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            pane.input_mode = match pane.input_mode {
                SamlInputMode::Paste => SamlInputMode::File,
                SamlInputMode::File => SamlInputMode::Paste,
            };
        }
        KeyCode::Char('q') => {
            app.running = false;
        }
        KeyCode::Esc => {
            app.screen = crate::tui::app::Screen::EnvSelect;
            // Reset compare state
            app.compare_panes = [
                crate::tui::app::ComparePane::default(),
                crate::tui::app::ComparePane::default(),
            ];
            app.compare_active_pane = 0;
        }
        KeyCode::F(3) => {
            // File browse — reuse pick_open_xml_dialog from input.rs
            // Will be wired via a public function
        }
        KeyCode::Enter => {
            decode_active_pane(app);
        }
        KeyCode::F(5) => {
            // Launch comparison if both decoded
            if app.compare_panes[0].decoded_xml.is_some()
                && app.compare_panes[1].decoded_xml.is_some()
            {
                compute_comparison(app);
                app.screen = crate::tui::app::Screen::CompareView;
            }
        }
        KeyCode::Backspace => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            match pane.input_mode {
                SamlInputMode::Paste => { pane.paste_buffer.pop(); }
                SamlInputMode::File => { pane.file_path.pop(); }
            }
        }
        KeyCode::Char(c) => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            match pane.input_mode {
                SamlInputMode::Paste => pane.paste_buffer.push(c),
                SamlInputMode::File => pane.file_path.push(c),
            }
        }
        _ => {}
    }
}

fn decode_active_pane(app: &mut App) {
    let pane = &mut app.compare_panes[app.compare_active_pane];
    let input = match pane.input_mode {
        SamlInputMode::Paste => pane.paste_buffer.clone(),
        SamlInputMode::File => {
            let path = crate::tui::input::expand_tilde(&pane.file_path);
            match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(e) => {
                    pane.decode_status = Some(format!("File error: {}", e));
                    return;
                }
            }
        }
    };

    if input.trim().is_empty() {
        pane.decode_status = Some("No input provided".to_string());
        return;
    }

    match decode_saml_input(&input) {
        Ok(result) => {
            let byte_len = result.xml.len();
            pane.raw_bytes = Some(result.xml.as_bytes().to_vec());
            pane.decoded_xml = Some(result.xml);
            pane.decode_status = Some(format!("✓ Decoded ({} bytes, {:?})", byte_len, result.document_type));
        }
        Err(e) => {
            pane.decode_status = Some(format!("Decode error: {}", e));
        }
    }
}

pub fn compute_comparison(app: &mut App) {
    let left_xml = app.compare_panes[0].decoded_xml.as_ref().unwrap();
    let right_xml = app.compare_panes[1].decoded_xml.as_ref().unwrap();

    // Mode 1: XML diff (pretty-printed)
    let left_pretty = crate::saml::parser::pretty_print_xml(left_xml);
    let right_pretty = crate::saml::parser::pretty_print_xml(right_xml);
    app.compare_diff_result = Some(crate::saml::diff::diff_lines(&left_pretty, &right_pretty));

    // Mode 2: Byte diff
    let left_bytes = app.compare_panes[0].raw_bytes.as_ref().unwrap();
    let right_bytes = app.compare_panes[1].raw_bytes.as_ref().unwrap();
    app.compare_byte_diff = Some(crate::saml::diff::diff_bytes(left_bytes, right_bytes));

    // Mode 4: Validation comparison
    let left_report = crate::saml::validator::validate_assertion(left_xml, app.idp_trust_store.as_ref());
    let right_report = crate::saml::validator::validate_assertion(right_xml, app.idp_trust_store.as_ref());
    app.compare_validation = Some((left_report, right_report));

    // Reset view state
    app.compare_scroll_offset = 0;
    app.compare_h_scroll_offset = 0;
    app.compare_mode = crate::tui::app::CompareMode::Xml;
    app.compare_diff_only = false;
}
```

- [ ] **Step 2: Make `expand_tilde` public in input.rs**

In `seahorse/src/tui/input.rs`, change `fn expand_tilde` to `pub fn expand_tilde`, `fn pick_open_xml_dialog` to `pub fn pick_open_xml_dialog`, and `fn open_idp_cert_dialog` to `pub fn open_idp_cert_dialog`.

- [ ] **Step 3: Update env_select bounds and add Compare menu item**

In `seahorse/src/tui/input.rs`, in `handle_env_select()`:
- Change the Down key bound from `app.env_selection < 2` to `app.env_selection < 3`
- Refactor the `Enter` handler to use a match:
  ```rust
  KeyCode::Enter => match app.env_selection {
      2 => app.screen = Screen::SamlInput,
      3 => app.screen = Screen::CompareInput,
      _ => {
          app.environment = Some(app.get_selected_env());
          app.screen = Screen::FlowSelect;
      }
  }
  ```

In `seahorse/src/tui/ui.rs`, in `render_env_select()`, add a 4th menu item:
```rust
"  Compare SAML Assertions"
```
and update the items list accordingly.

- [ ] **Step 4: Wire compare input handling in input.rs**

In `seahorse/src/tui/input.rs`, in `handle_input()`:
- In the existing paste event block (lines 11-16), add `CompareInput` handling alongside `SamlInput`:
  ```rust
  Screen::CompareInput => {
      let pane = &mut app.compare_panes[app.compare_active_pane];
      if pane.input_mode == SamlInputMode::Paste {
          pane.paste_buffer.push_str(&text);
      }
  }
  ```
- Add dispatch in the screen match: `Screen::CompareInput => compare::handle_compare_input(app, key.code),`
- Add `Screen::CompareView => compare::handle_compare_view(app, key.code),`

Add `use crate::tui::compare;` at the top of input.rs.

- [ ] **Step 5: Verify it compiles and the menu shows 4 items**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/tui/compare.rs seahorse/src/tui/input.rs seahorse/src/tui/ui.rs
git commit -m "feat: wire CompareInput screen with input handling and menu integration"
```

---

### Task 6: CompareView — XML Diff Rendering (Mode 1)

**Files:**
- Modify: `seahorse/src/tui/compare.rs`

- [ ] **Step 1: Replace render_compare_view stub with full implementation**

Replace the stub `render_compare_view` in `seahorse/src/tui/compare.rs`:

```rust
pub fn render_compare_view(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)])
        .split(frame.area());

    // Mode selector bar
    render_mode_bar(frame, app, outer[0]);

    match app.compare_mode {
        CompareMode::Xml => render_xml_diff(frame, app, outer[1]),
        CompareMode::Hex => render_hex_diff(frame, app, outer[1]),
        CompareMode::C14n => render_c14n_diff(frame, app, outer[1]),
        CompareMode::Validation => render_validation_diff(frame, app, outer[1]),
    }

    // Bottom status bar
    let diff_count = match app.compare_mode {
        CompareMode::Xml => {
            app.compare_diff_result.as_ref().map(|d| d.diff_count).unwrap_or(0)
        }
        CompareMode::C14n => {
            app.compare_c14n_diff.as_ref().map(|d| d.diff_count).unwrap_or(0)
        }
        CompareMode::Hex => {
            app.compare_byte_diff.as_ref().map(|rows| rows.iter().filter(|r| !r.diffs.is_empty()).count()).unwrap_or(0)
        }
        CompareMode::Validation => 0,
    };
    let filter_str = if app.compare_diff_only { " [DIFFS ONLY]" } else { "" };
    let status = format!(
        " {} differences | ↑↓: scroll | ←→: h-scroll | d: toggle filter{} | Esc: back ",
        diff_count, filter_str
    );
    let bar = Paragraph::new(Line::from(Span::styled(status, Style::default().fg(Color::DarkGray))));
    frame.render_widget(bar, outer[2]);
}

fn render_mode_bar(frame: &mut Frame, app: &App, area: Rect) {
    let modes = [
        (CompareMode::Xml, "1:XML"),
        (CompareMode::Hex, "2:Hex"),
        (CompareMode::C14n, "3:C14N"),
        (CompareMode::Validation, "4:Valid"),
    ];
    let spans: Vec<Span> = modes
        .iter()
        .enumerate()
        .flat_map(|(i, (mode, label))| {
            let style = if *mode == app.compare_mode {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let mut v = vec![Span::styled(*label, style)];
            if i < 3 {
                v.push(Span::raw("  "));
            }
            v
        })
        .collect();
    let line = Line::from(spans);
    let bar = Paragraph::new(line);
    frame.render_widget(bar, area);
}

fn render_xml_diff(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(diff) = &app.compare_diff_result {
        render_line_diff(frame, app, area, diff, "Assertion A", "Assertion B");
    }
}

/// Shared renderer for XML diff (Mode 1) and C14N diff (Mode 3).
/// Takes the DiffResult to render and pane titles.
fn render_line_diff(frame: &mut Frame, app: &App, area: Rect, diff: &DiffResult, left_title: &str, right_title: &str) {

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let lines_to_render: Vec<(usize, &DiffLine)> = if app.compare_diff_only {
        crate::saml::diff::filter_diff_lines(diff, 2)
    } else {
        diff.lines.iter().enumerate().collect()
    };

    let mut left_lines = Vec::new();
    let mut right_lines = Vec::new();
    let mut left_num = 0usize;
    let mut right_num = 0usize;

    for (_i, diff_line) in &lines_to_render {
        match diff_line {
            DiffLine::Same(text) => {
                left_num += 1;
                right_num += 1;
                let prefix = format!("{:4} ", left_num);
                left_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                    Span::styled(text.clone(), Style::default().fg(Color::DarkGray)),
                ]));
                let prefix = format!("{:4} ", right_num);
                right_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                    Span::styled(text.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            }
            DiffLine::Removed(text) => {
                left_num += 1;
                let prefix = format!("{:4} ", left_num);
                left_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Red)),
                    Span::styled(text.clone(), Style::default().fg(Color::Red)),
                ]));
                right_lines.push(Line::from(Span::raw("")));
            }
            DiffLine::Added(text) => {
                right_num += 1;
                left_lines.push(Line::from(Span::raw("")));
                let prefix = format!("{:4} ", right_num);
                right_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Green)),
                    Span::styled(text.clone(), Style::default().fg(Color::Green)),
                ]));
            }
            DiffLine::Changed { left, right, left_spans, right_spans } => {
                left_num += 1;
                right_num += 1;
                left_lines.push(build_highlighted_line(left_num, left, left_spans, Color::Red));
                right_lines.push(build_highlighted_line(right_num, right, right_spans, Color::Green));
            }
        }
    }

    let left_block = Block::default()
        .title(format!(" {} ", left_title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let right_block = Block::default()
        .title(format!(" {} ", right_title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let left_para = Paragraph::new(left_lines)
        .block(left_block)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));
    let right_para = Paragraph::new(right_lines)
        .block(right_block)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));

    frame.render_widget(left_para, panes[0]);
    frame.render_widget(right_para, panes[1]);
}

fn build_highlighted_line(line_num: usize, text: &str, spans: &[(usize, usize)], highlight_color: Color) -> Line<'static> {
    let prefix = format!("{:4} ", line_num);
    let chars: Vec<char> = text.chars().collect();
    let mut result: Vec<Span<'static>> = vec![
        Span::styled(prefix, Style::default().fg(highlight_color)),
    ];

    let mut pos = 0;
    for &(start, end) in spans {
        if pos < start {
            let normal: String = chars[pos..start].iter().collect();
            result.push(Span::styled(normal, Style::default().fg(Color::White)));
        }
        let highlighted: String = chars[start..end].iter().collect();
        result.push(Span::styled(
            highlighted,
            Style::default().fg(Color::Black).bg(highlight_color),
        ));
        pos = end;
    }
    if pos < chars.len() {
        let rest: String = chars[pos..].iter().collect();
        result.push(Span::styled(rest, Style::default().fg(Color::White)));
    }

    Line::from(result)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add seahorse/src/tui/compare.rs
git commit -m "feat: add XML diff rendering for CompareView (Mode 1)"
```

---

### Task 7: CompareView — Hex Diff Rendering (Mode 2)

**Files:**
- Modify: `seahorse/src/tui/compare.rs`

- [ ] **Step 1: Implement render_hex_diff**

Add to `seahorse/src/tui/compare.rs`:

```rust
fn render_hex_diff(frame: &mut Frame, app: &App, area: Rect) {
    let rows = match &app.compare_byte_diff {
        Some(r) => r,
        None => return,
    };

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let rows_to_render: Vec<(usize, &ByteDiffRow)> = if app.compare_diff_only {
        crate::saml::diff::filter_byte_diff(rows)
    } else {
        rows.iter().enumerate().collect()
    };

    let mut left_lines = Vec::new();
    let mut right_lines = Vec::new();

    for (_i, row) in &rows_to_render {
        left_lines.push(build_hex_line(row.offset, &row.left_bytes, &row.diffs));
        right_lines.push(build_hex_line(row.offset, &row.right_bytes, &row.diffs));
    }

    let left_block = Block::default()
        .title(" Assertion A (hex) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let right_block = Block::default()
        .title(" Assertion B (hex) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let left_para = Paragraph::new(left_lines)
        .block(left_block)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));
    let right_para = Paragraph::new(right_lines)
        .block(right_block)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));

    frame.render_widget(left_para, panes[0]);
    frame.render_widget(right_para, panes[1]);
}

fn build_hex_line(offset: usize, bytes: &[u8], diffs: &[usize]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();

    // Offset
    spans.push(Span::styled(
        format!("{:08x}  ", offset),
        Style::default().fg(Color::DarkGray),
    ));

    // Hex bytes
    for i in 0..16 {
        if i == 8 {
            spans.push(Span::raw(" "));
        }
        if i < bytes.len() {
            let is_diff = diffs.contains(&i);
            let style = if is_diff {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            spans.push(Span::styled(format!("{:02x} ", bytes[i]), style));
        } else {
            spans.push(Span::raw("   "));
        }
    }

    spans.push(Span::raw(" |"));

    // ASCII
    for i in 0..16 {
        if i < bytes.len() {
            let ch = if bytes[i].is_ascii_graphic() || bytes[i] == b' ' {
                bytes[i] as char
            } else {
                '.'
            };
            let is_diff = diffs.contains(&i);
            let style = if is_diff {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            spans.push(Span::styled(ch.to_string(), style));
        } else {
            spans.push(Span::raw(" "));
        }
    }

    spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));

    Line::from(spans)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add seahorse/src/tui/compare.rs
git commit -m "feat: add hex/byte diff rendering for CompareView (Mode 2)"
```

---

### Task 8: CompareView — C14N Diff (Mode 3) and Validation Comparison (Mode 4)

**Files:**
- Modify: `seahorse/src/tui/compare.rs`

- [ ] **Step 1: Implement C14N diff computation and rendering**

The C14N diff needs to be computed on demand (not pre-computed) since it requires running canonicalization. Add a field to App to cache the c14n diff result.

In `seahorse/src/tui/app.rs`, add after `compare_byte_diff`:

```rust
    pub compare_c14n_diff: Option<crate::saml::diff::DiffResult>,
```

Initialize it as `None` in `App::new()`, and set it in `compute_comparison`:

Add to the end of `compute_comparison()` in `compare.rs`:

```rust
    // Mode 3: C14N diff
    let left_c14n = compute_c14n_text(left_xml);
    let right_c14n = compute_c14n_text(right_xml);
    app.compare_c14n_diff = Some(crate::saml::diff::diff_lines(&left_c14n, &right_c14n));
```

Add helper function:

```rust
fn compute_c14n_text(xml: &str) -> String {
    // Remove signature, then canonicalize
    let without_sig = crate::saml::c14n::remove_signature_element(xml)
        .unwrap_or_else(|_| xml.to_string());

    // Extract inclusive namespace prefixes from SignedInfo if available
    let prefixes = extract_inclusive_prefixes(xml);
    let prefix_refs: Vec<&str> = prefixes.iter().map(|s| s.as_str()).collect();

    match crate::saml::c14n::canonicalize_exclusive(&without_sig, &prefix_refs) {
        Ok(bytes) => {
            let raw = String::from_utf8_lossy(&bytes).to_string();
            crate::saml::parser::pretty_print_xml(&raw)
        }
        Err(_) => "(canonicalization failed)".to_string(),
    }
}

fn extract_inclusive_prefixes(xml: &str) -> Vec<String> {
    // Look for InclusiveNamespaces PrefixList="..." in the XML
    let mut prefixes = Vec::new();
    if let Some(start) = xml.find("PrefixList=\"") {
        let rest = &xml[start + 12..];
        if let Some(end) = rest.find('"') {
            let list = &rest[..end];
            for prefix in list.split_whitespace() {
                prefixes.push(prefix.to_string());
            }
        }
    }
    prefixes
}
```

For `render_c14n_diff`, reuse the shared `render_line_diff` with the c14n diff result:

```rust
fn render_c14n_diff(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(diff) = &app.compare_c14n_diff {
        render_line_diff(frame, app, area, diff, "Assertion A (c14n)", "Assertion B (c14n)");
    }
}
```

- [ ] **Step 2: Implement render_validation_diff (Mode 4)**

Add to `seahorse/src/tui/compare.rs`:

```rust
fn render_validation_diff(frame: &mut Frame, app: &App, area: Rect) {
    let (left_report, right_report) = match &app.compare_validation {
        Some(r) => r,
        None => return,
    };

    let block = Block::default()
        .title(" Validation Comparison ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    // Header
    lines.push(Line::from(vec![
        Span::styled(format!("{:<20}", "Check"), Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<20}", "Assertion A"), Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<20}", "Assertion B"), Style::default().add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(Span::styled(
        "─".repeat(60),
        Style::default().fg(Color::DarkGray),
    )));

    // Check rows
    let max_checks = left_report.checks.len().max(right_report.checks.len());
    for i in 0..max_checks {
        let left_check = left_report.checks.get(i);
        let right_check = right_report.checks.get(i);

        let name = left_check
            .or(right_check)
            .map(|c| c.name.clone())
            .unwrap_or_default();

        let (left_text, left_color) = check_display(left_check);
        let (right_text, right_color) = check_display(right_check);

        let differs = left_check.map(|c| c.passed) != right_check.map(|c| c.passed);
        let row_bg = if differs { Color::DarkGray } else { Color::Reset };

        lines.push(Line::from(vec![
            Span::styled(format!("{:<20}", name), Style::default().fg(Color::White).bg(row_bg)),
            Span::styled(format!("{:<20}", left_text), Style::default().fg(left_color).bg(row_bg)),
            Span::styled(format!("{:<20}", right_text), Style::default().fg(right_color).bg(row_bg)),
        ]));
    }

    // Separator
    lines.push(Line::from(Span::styled(
        "─".repeat(60),
        Style::default().fg(Color::DarkGray),
    )));

    // Footer with algorithm/cert/digest info
    lines.push(Line::from(vec![
        Span::styled("A: ", Style::default().fg(Color::Cyan)),
        Span::raw(format!(
            "{} | {} | Digest: {}",
            short_algo(&left_report.algorithm),
            if left_report.cert_subject.is_empty() { "no cert" } else { &left_report.cert_subject },
            extract_digest_value(app.compare_panes[0].decoded_xml.as_deref().unwrap_or("")),
        )),
    ]));
    lines.push(Line::from(vec![
        Span::styled("B: ", Style::default().fg(Color::Cyan)),
        Span::raw(format!(
            "{} | {} | Digest: {}",
            short_algo(&right_report.algorithm),
            if right_report.cert_subject.is_empty() { "no cert" } else { &right_report.cert_subject },
            extract_digest_value(app.compare_panes[1].decoded_xml.as_deref().unwrap_or("")),
        )),
    ]));

    let para = Paragraph::new(lines).scroll((app.compare_scroll_offset, 0));
    frame.render_widget(para, inner);
}

fn check_display(check: Option<&crate::saml::validator::ValidationCheck>) -> (String, Color) {
    match check {
        Some(c) if c.passed => ("✓ Pass".to_string(), Color::Green),
        Some(c) => {
            if c.detail.contains("skipped") || c.detail.contains("Skipped") || c.detail.contains("No ") {
                ("— Skipped".to_string(), Color::DarkGray)
            } else {
                ("✗ FAIL".to_string(), Color::Red)
            }
        }
        None => ("—".to_string(), Color::DarkGray),
    }
}

fn short_algo(algo: &str) -> &str {
    if algo.contains("sha256") || algo.contains("sha-256") {
        "SHA-256"
    } else if algo.contains("sha1") || algo.contains("sha-1") {
        "SHA-1"
    } else if algo.is_empty() {
        "unknown"
    } else {
        algo
    }
}

fn extract_digest_value(xml: &str) -> String {
    // Quick extraction of DigestValue from XML
    if let Some(start) = xml.find("<DigestValue>").or_else(|| xml.find("<ds:DigestValue>")) {
        let rest = &xml[start..];
        if let Some(tag_end) = rest.find('>') {
            let after = &rest[tag_end + 1..];
            if let Some(close) = after.find('<') {
                let value = &after[..close];
                if value.len() > 12 {
                    return format!("{}...", &value[..12]);
                }
                return value.to_string();
            }
        }
    }
    "none".to_string()
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add seahorse/src/tui/compare.rs seahorse/src/tui/app.rs
git commit -m "feat: add C14N diff (Mode 3) and validation comparison (Mode 4)"
```

---

### Task 9: CompareView — Input Handling (Mode Switching, Scrolling, IDP Cert)

**Files:**
- Modify: `seahorse/src/tui/compare.rs`
- Modify: `seahorse/src/tui/input.rs`

- [ ] **Step 1: Add CompareView input handler**

Add to `seahorse/src/tui/compare.rs`:

```rust
pub fn handle_compare_view(app: &mut App, key_code: KeyCode) {
    match key_code {
        // Mode switching
        KeyCode::Char('1') => {
            app.compare_mode = CompareMode::Xml;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('2') => {
            app.compare_mode = CompareMode::Hex;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('3') => {
            app.compare_mode = CompareMode::C14n;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('4') => {
            app.compare_mode = CompareMode::Validation;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        // Diff-only toggle
        KeyCode::Char('d') => {
            app.compare_diff_only = !app.compare_diff_only;
            app.compare_scroll_offset = 0;
        }
        // Scrolling
        KeyCode::Up => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_sub(1);
        }
        KeyCode::Down => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_add(1);
        }
        KeyCode::Left => {
            app.compare_h_scroll_offset = app.compare_h_scroll_offset.saturating_sub(2);
        }
        KeyCode::Right => {
            app.compare_h_scroll_offset = app.compare_h_scroll_offset.saturating_add(2);
        }
        KeyCode::PageUp => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_add(20);
        }
        // IDP cert loading (for Mode 4 re-validation)
        // 'i' opens file dialog (matching existing Result/SamlView screens)
        // 'I' activates text path input
        KeyCode::Char('i') => {
            crate::tui::input::open_idp_cert_dialog(app);
            // Re-validate both assertions after cert load
            if let (Some(left_xml), Some(right_xml)) = (
                app.compare_panes[0].decoded_xml.clone(),
                app.compare_panes[1].decoded_xml.clone(),
            ) {
                let left_report = crate::saml::validator::validate_assertion(&left_xml, app.idp_trust_store.as_ref());
                let right_report = crate::saml::validator::validate_assertion(&right_xml, app.idp_trust_store.as_ref());
                app.compare_validation = Some((left_report, right_report));
            }
        }
        KeyCode::Char('I') => {
            app.idp_cert_input_active = true;
            app.idp_cert_input.clear();
        }
        // Navigation
        KeyCode::Esc => {
            app.screen = crate::tui::app::Screen::CompareInput;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('q') => {
            app.running = false;
        }
        _ => {}
    }
}
```

- [ ] **Step 2: Wire CompareView input in input.rs**

In `seahorse/src/tui/input.rs`, update the screen dispatch to handle `CompareView`:

```rust
Screen::CompareView => compare::handle_compare_view(app, &key),
```

Also update the IDP cert revalidation handler (the existing `idp_cert_input_active` block that runs on Enter) to also recompute comparison validation when on CompareView screen. After the existing revalidation logic, add:

```rust
if app.screen == Screen::CompareView {
    if let (Some(left_xml), Some(right_xml)) = (
        app.compare_panes[0].decoded_xml.as_ref(),
        app.compare_panes[1].decoded_xml.as_ref(),
    ) {
        let left_report = crate::saml::validator::validate_assertion(left_xml, app.idp_trust_store.as_ref());
        let right_report = crate::saml::validator::validate_assertion(right_xml, app.idp_trust_store.as_ref());
        app.compare_validation = Some((left_report, right_report));
    }
}
```

- [ ] **Step 3: Wire F3 file browse in CompareInput**

In the `handle_compare_input` function's `F(3)` match arm, add:

```rust
KeyCode::F(3) => {
    if let Some(path) = crate::tui::input::pick_open_xml_dialog() {
        let pane = &mut app.compare_panes[app.compare_active_pane];
        pane.input_mode = SamlInputMode::File;
        pane.file_path = path.to_string_lossy().to_string();
    }
}
```

Make `pick_open_xml_dialog` public in `input.rs`.

- [ ] **Step 4: Update main.rs to reset compare state**

In `seahorse/src/main.rs`, in the section that resets state when returning to EnvSelect (look for where config/environment are cleared), add:

```rust
app.compare_panes = [ComparePane::default(), ComparePane::default()];
app.compare_active_pane = 0;
app.compare_diff_result = None;
app.compare_byte_diff = None;
app.compare_c14n_diff = None;
app.compare_validation = None;
```

- [ ] **Step 5: Verify it compiles**

Run: `cd seahorse && cargo check 2>&1 | tail -5`
Expected: compiles

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/tui/compare.rs seahorse/src/tui/input.rs seahorse/src/main.rs
git commit -m "feat: add CompareView input handling with mode switching, scrolling, IDP cert"
```

---

### Task 10: Manual Testing and Polish

**Files:**
- Possibly modify: `seahorse/src/tui/compare.rs` (fixes)

- [ ] **Step 1: Build the application**

Run: `cd seahorse && cargo build 2>&1 | tail -10`
Expected: successful build with no errors

- [ ] **Step 2: Test with sample file**

Run the app and test the comparison flow:
1. Launch: `cd seahorse && cargo run`
2. Select "Compare SAML Assertions" from main menu
3. In left pane: press `m` to switch to File mode, enter `../sample_files/assertion_response.xml`, press Enter
4. Tab to right pane, paste or load a second assertion
5. Press F5 to compare
6. Test mode switching: `1`, `2`, `3`, `4`
7. Test `d` toggle
8. Test scrolling: Up/Down, Left/Right, PageUp/PageDown
9. Test Esc to go back, then q to quit

- [ ] **Step 3: Fix any rendering issues found during testing**

Address any layout, color, or scrolling issues discovered during manual testing.

- [ ] **Step 4: Commit final fixes**

```bash
git add -A
git commit -m "fix: polish CompareView rendering after manual testing"
```
