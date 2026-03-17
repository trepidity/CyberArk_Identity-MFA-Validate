# SAML Assertion Comparison Tool — Design Spec

## Purpose

Add a side-by-side SAML assertion comparison feature to seahorse for debugging signature validation failures. The tool reveals exactly why one assertion validates and another does not, down to individual bytes and invisible characters.

## Entry Point

New option on the main menu (EnvSelect screen): **"Compare SAML Assertions"** alongside existing PROD / TST / View SAML Assertion options.

## Screen Flow

```
EnvSelect → CompareInput → CompareView
```

- `CompareInput`: Load two assertions
- `CompareView`: Side-by-side diff with toggleable modes
- `Esc` navigates back at each step

## CompareInput Screen

Split pane layout with two input areas side by side.

### Layout

```
┌─ Assertion A ──────────────┐┌─ Assertion B ──────────────┐
│ [Paste] / [File]           ││ [Paste] / [File]           │
│                            ││                            │
│ (paste area or file path)  ││ (paste area or file path)  │
│                            ││                            │
│ ✓ Decoded (245 bytes)      ││ (waiting for input...)     │
└────────────────────────────┘└────────────────────────────┘
 Tab: switch pane | m: paste/file | Enter: decode | F5: compare
```

### Behavior

- `Tab` switches active pane (highlighted border on active side)
- Each pane supports paste or file input (toggle with `m`). Note: the single-assertion SamlInput screen uses `Tab` for this toggle, but here `Tab` is used for pane switching, so `m` (mode) is used instead.
- `Enter` decodes the active pane's input synchronously using `decoder::decode_saml_input()`. Unlike the SamlInput→Waiting trampoline pattern used elsewhere, decoding here is inline since it is fast and does not require async I/O.
- Bracketed paste (`Event::Paste`) is supported on the active pane, matching existing SamlInput behavior
- Decode status shown at bottom of each pane
- Once both are decoded, `F5` launches CompareView
- `Esc` returns to main menu
- `q` quits the application (consistent with all other screens)

## CompareView Screen

Side-by-side comparison with four toggleable modes.

### Layout (Modes 1–3)

```
┌─ Assertion A ──────────────┐┌─ Assertion B ──────────────┐
│  1: <saml2:Assertion ...   ││  1: <saml2:Assertion ...   │
│  2:   <saml2:Issuer>...    ││  2:   <saml2:Issuer>...    │
│  3:   <saml2:Subject>      ││  3:   <saml2:Subject>      │
│  4:     <NameID>JAJ0334    ││  4:     <NameID>jaj0334    │  ← highlighted
│  5:   </saml2:Subject>     ││  5:   </saml2:Subject>     │
└────────────────────────────┘└────────────────────────────┘
 Mode: [1:XML] 2:Hex 3:C14N 4:Valid | d: diffs only | ↑↓: scroll
```

### Layout (Mode 4 — Validation)

```
┌─ Check ─────────┬─ Assertion A ──┬─ Assertion B ──┐
│ Structure       │ ✓ Pass         │ ✓ Pass         │
│ Time Conditions │ ✓ Pass         │ ✗ FAIL         │  ← highlighted
│ Digest          │ ✓ Pass         │ ✗ FAIL         │  ← highlighted
│ Signature       │ ✓ Pass         │ ✗ FAIL         │  ← highlighted
│ IDP Cert Match  │ — Skipped      │ — Skipped      │
│ Chain Valid     │ — Skipped      │ — Skipped      │
├─────────────────┴────────────────┴────────────────┤
│ A: SHA-256 | CN=hyperdrive...  | Digest: a3f2... │
│ B: SHA-256 | CN=hyperdrive...  | Digest: 81bc... │
└───────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| `1` | XML character-level diff mode |
| `2` | Byte/hex view mode |
| `3` | Canonicalized (c14n) diff mode |
| `4` | Validation comparison mode |
| `d` | Toggle: show all vs differences only |
| `Up/Down` | Synchronized vertical scroll |
| `Left/Right` | Horizontal scroll (modes 1–3) |
| `Esc` | Back to CompareInput |
| `q` | Quit application |

### Comparison Modes

#### Mode 1 — XML Diff

- Pretty-prints both assertions via existing `parser::pretty_print_xml()`
- Line-by-line diff with character-level highlighting within changed lines
- Red for removed characters, green for added, dim for identical lines
- Aligned so matching lines sit at the same row
- Insertions/deletions shown with blank opposing line

#### Mode 2 — Byte/Hex View

- Raw bytes displayed as hex + ASCII side by side (like `xxd`)
- Each row: offset | hex bytes | ASCII representation
- 16 bytes per row
- Differing bytes highlighted in yellow
- Exposes: BOM markers (`EF BB BF`), `\r\n` vs `\n`, tabs vs spaces, zero-width spaces (`E2 80 8B`), non-breaking spaces (`C2 A0`), any non-printable or non-ASCII bytes

#### Mode 3 — Canonicalized Diff

- Runs both assertions through `c14n::canonicalize_exclusive()` with enveloped signature transform (`c14n::remove_signature_element()`)
- Extracts each assertion's own `InclusiveNamespaces PrefixList` from its SignedInfo and passes it to `canonicalize_exclusive()`, so the canonicalized output matches exactly what the signature algorithm operates on
- Diffs the canonicalized output using the same line+character diff as Mode 1
- This is the "truth" view: differences here are exactly what causes a digest mismatch

#### Mode 4 — Validation Comparison

- Runs `validator::validate_assertion()` on both assertions
- Uses `app.idp_trust_store` if available; supports `i` key to load an IDP certificate at runtime (same as Result/SamlView screens), which triggers re-validation of both assertions
- Table layout showing the 6-check results side by side: Structure, Time Conditions, Digest, Signature, IDP Cert Match, Chain Validation
- Color coding: green for pass, red for fail, gray for skipped
- Rows where results differ are highlighted
- Footer shows: algorithm, cert subject, and computed digest values for each assertion

### Diff-Only Filter (`d` toggle)

- **Default (off):** Show all content, differences highlighted with color
- **On:** Hide identical lines/rows, show only differences with 2–3 lines of surrounding context for orientation
- Status bar indicates filter state
- Applies to modes 1, 2, and 3. Mode 4 always shows all checks.

## Diff Engine — `saml/diff.rs`

New module containing all comparison logic.

### Line Diff

- LCS-based (longest common subsequence) diff algorithm
- No external crate — SAML assertions are typically <200 lines, so a simple O(n*m) implementation is sufficient
- Produces: `Same(line)`, `Added(line)`, `Removed(line)`, `Changed(old, new)`
- For `Changed` pairs, runs secondary character-level diff to identify exactly which characters differ within the line, producing highlight spans

### Byte Diff

- Chunks both inputs into 16-byte rows
- Compares row by row, flags differing byte positions
- Renders as: `offset | hex bytes (differing highlighted) | ASCII`

### Data Structures

```rust
enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
    Changed {
        left: String,
        right: String,
        left_spans: Vec<(usize, usize)>,  // character (not byte) offset ranges of differences
        right_spans: Vec<(usize, usize)>,  // for safe ratatui Span slicing with UTF-8
    },
}

struct DiffResult {
    lines: Vec<DiffLine>,
    left_total: usize,
    right_total: usize,
    diff_count: usize,
}

struct ByteDiffRow {
    offset: usize,
    left_bytes: Vec<u8>,
    right_bytes: Vec<u8>,
    diffs: Vec<usize>,  // indices of differing bytes
}
```

## New Files

| File | Purpose |
|------|---------|
| `src/saml/diff.rs` | Diff engine: LCS line diff, character sub-diff, byte diff |
| `src/tui/compare.rs` | CompareInput and CompareView rendering + input handling |

## Modified Files

| File | Change |
|------|--------|
| `src/tui/app.rs` | Add `CompareInput` and `CompareView` to `Screen` enum; add comparison state fields to `App` |
| `src/tui/ui.rs` | Add `render_compare_input()` and `render_compare_view()` dispatch |
| `src/tui/input.rs` | Add input handling for compare screens; update `handle_env_select()` bounds check (currently `< 2`) to `< 3` and add `env_selection == 3` branch for CompareInput |
| `src/saml/mod.rs` | Add `pub mod diff;` |

## App State Additions

```rust
// In App struct
compare_active_pane: usize,          // 0 = left, 1 = right
compare_inputs: [ComparePane; 2],     // input state for each pane
compare_mode: CompareMode,            // XML, Hex, C14N, Validation
compare_diff_only: bool,              // d toggle
compare_scroll_offset: u16,              // matches ratatui Paragraph::scroll() API
compare_h_scroll_offset: u16,
compare_diff_result: Option<DiffResult>,
compare_byte_diff: Option<Vec<ByteDiffRow>>,
compare_validation: Option<(ValidationReport, ValidationReport)>,

struct ComparePane {
    input_mode: SamlInputMode,  // Paste or File
    paste_buffer: String,
    file_path: String,
    raw_xml: Option<Vec<u8>>,       // raw decoded bytes (for Mode 2 hex view)
    decoded_xml: Option<String>,    // decoded XML string (for Modes 1, 3, 4)
    decode_status: Option<String>,
}

enum CompareMode { Xml, Hex, C14n, Validation }
```

## No External Dependencies

All diff logic is implemented in-project. The LCS algorithm and byte comparison are straightforward for the data sizes involved (SAML assertions are typically 2–5 KB, <200 lines). The O(n*m) LCS matrix for 200-line documents is ~40K entries — trivial. If inputs exceed 1,000 lines (e.g., a large unformatted Response), the diff should still complete quickly but may use ~4 MB of memory.
