# Tauri SAML Comparison — Design Spec

## Purpose

Port the TUI SAML assertion comparison feature to the Tauri desktop GUI. Adds a 5th screen ("Compare") with side-by-side diff rendering across 5 tabs (XML, Hex, C14N, Validation, All), reusing the existing `saml::diff` engine from the seahorse library.

## Entry Point

New "Compare SAML Assertions" button on the Home screen (`screen-home`), alongside the existing "View SAML Assertion" button.

## Screen Flow

```
Home → Compare (input phase) → Compare (results phase)
         ↑ Back                    ↑ Back
```

## Compare Screen — Input Phase

Side-by-side panels for loading two assertions.

### Layout

Two panels (Assertion A / Assertion B), each containing:
- "Open File" and "Paste from Clipboard" buttons
- Textarea for pasting SAML data
- Decode status indicator (document type + byte count, or error)
- When both are decoded, a "Compare" button appears centered below the panels

### Behavior

- "Open File" uses `tauri-plugin-dialog` file picker (reusing existing `openFileDialog` pattern from `app.js`)
- "Paste from Clipboard" reads from `tauri-plugin-clipboard-manager` (reusing existing `clipboardRead` pattern)
- Textarea accepts direct paste/typing
- Each panel decodes independently via the existing `decode_saml` command for validation of input format
- "Compare" button calls the new `compare_saml` Tauri command
- Back button returns to Home screen

## Compare Screen — Results Phase

Replaces the input panels with diff results.

### Layout

- Back button (returns to input phase, preserving loaded assertions)
- Tab bar: **XML Diff** | **Hex / Bytes** | **Canonicalized** | **Validation** | **All**
- Toolbar: "Diffs Only" toggle button + diff count display
- IDP cert buttons: "Load IDP Cert" and "Load Chain Cert" (reuse existing `load_idp_cert` / `load_chain_cert` commands, trigger re-validation via `compare_revalidate`)
- Content area below tabs

### Tab: XML Diff

- Side-by-side `<pre>` blocks with synchronized scrolling
- Line numbers on each side, tracked independently
- `Same` lines: dimmed gray text
- `Removed` lines: red text on left, blank on right
- `Added` lines: blank on left, green text on right
- `Changed` lines: character-level highlighting using span offsets — differing characters get red/green background
- "Diffs Only" mode hides identical lines, shows only differences with 2 lines of surrounding context

### Tab: Hex / Bytes

- Side-by-side hex dump panels with synchronized scrolling
- Each row: 8-char offset | 16 hex bytes (space after byte 8) | ASCII column
- Differing bytes highlighted with yellow background
- Monospace font throughout
- "Diffs Only" mode shows only rows with differences

### Tab: Canonicalized (C14N)

- Same rendering as XML Diff tab, but operates on canonicalized XML
- Backend runs `c14n::remove_signature_element()` + `c14n::canonicalize_exclusive()` with each assertion's own `InclusiveNamespaces PrefixList`, then pretty-prints the result
- Differences here are exactly what causes a digest mismatch

### Tab: Validation

- Table with 3 columns: Check | Assertion A | Assertion B
- Green checkmark for pass, red X for fail, gray dash for skipped
- Rows where A and B differ get a highlighted background
- Footer: algorithm (SHA-256/SHA-1), cert subject, digest value (truncated) for each assertion
- Not affected by "Diffs Only" toggle (always shows all checks)

### Tab: All

- Summary cards at top: diff count, Assertion A validation status, Assertion B validation status
- Collapsible sections below:
  1. Validation table
  2. XML Diff (side-by-side)
  3. Hex / Bytes (side-by-side)
  4. C14N Diff (side-by-side)
- Sections default to expanded, can be collapsed by clicking the header
- "Diffs Only" toggle applies to the diff sections

## Tauri Commands

### `compare_saml`

```
compare_saml(state, input_a: String, input_b: String) -> Result<CompareResult, String>
```

1. Decodes both inputs via `decoder::decode_saml_input()`
2. Computes XML diff: pretty-prints both, runs `diff::diff_lines()`
3. Computes byte diff: `diff::diff_bytes()` on raw bytes
4. Computes C14N diff: removes signatures, canonicalizes with each assertion's prefix list, pretty-prints, runs `diff::diff_lines()`
5. Validates both: `validator::validate_assertion()` with current `AppState.idp_trust_store`
6. Returns `CompareResult` with all results serialized

### `compare_revalidate`

```
compare_revalidate(state, xml_a: String, xml_b: String) -> Result<CompareRevalidateResult, String>
```

Re-runs validation on both assertions using the current `AppState.idp_trust_store`. Called after IDP cert loading to refresh the Validation tab without recomputing diffs.

Returns updated `ValidationReport` for each assertion.

## Data Transfer Objects

```rust
#[derive(Serialize)]
pub struct CompareResult {
    pub decode_a: DecodeInfo,
    pub decode_b: DecodeInfo,
    pub xml_diff: DiffResultInfo,
    pub hex_diff: Vec<ByteDiffRowInfo>,
    pub c14n_diff: DiffResultInfo,
    pub validation_a: ValidationReport,
    pub validation_b: ValidationReport,
}

#[derive(Serialize)]
pub struct DecodeInfo {
    pub doc_type: String,
    pub byte_count: usize,
}

#[derive(Serialize)]
pub struct DiffResultInfo {
    pub lines: Vec<DiffLineInfo>,
    pub left_total: usize,
    pub right_total: usize,
    pub diff_count: usize,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum DiffLineInfo {
    Same { text: String },
    Added { text: String },
    Removed { text: String },
    Changed {
        left: String,
        right: String,
        left_spans: Vec<(usize, usize)>,
        right_spans: Vec<(usize, usize)>,
    },
}

#[derive(Serialize)]
pub struct ByteDiffRowInfo {
    pub offset: usize,
    pub left_bytes: Vec<u8>,
    pub right_bytes: Vec<u8>,
    pub diffs: Vec<usize>,
}

#[derive(Serialize)]
pub struct CompareRevalidateResult {
    pub validation_a: ValidationReport,
    pub validation_b: ValidationReport,
}
```

`ValidationReport` from `seahorse::saml::validator` already derives `Serialize` — use it directly in the DTOs (no wrapper needed). Drop the `Dto` suffix from DTO types for consistency with existing `ConfigInfo`, `DecodedSaml` naming.

## Input Handling

**Non-assertion inputs:** If an input decodes as a `Response`, auto-extract the embedded assertion via `parser::extract_assertion_from_response()` before comparing. If an input is an `AuthnRequest`, show an error — comparison only works with assertions or responses containing assertions.

**Single decode failure:** If one input fails to decode, return an error immediately. Both must decode successfully before comparison proceeds.

**Hex diff byte source:** "Raw bytes" means `decoded_xml.as_bytes()` — the UTF-8 bytes of the decoded XML string.

## Implementation Notes

**C14N PrefixList extraction:** The `extract_signature_data()` function in `validator.rs` is private. The `compare_saml` command should extract the PrefixList using a simple string scan for `PrefixList="..."` in each assertion's XML (matching the approach used in the TUI's `compare.rs::extract_inclusive_prefixes()`).

**Async with spawn_blocking:** The `compare_saml` command should be `async` and use `tokio::task::spawn_blocking` for the CPU-intensive diff computation, preventing UI freezes on large assertions.

**DecodeInfo fields:** `doc_type` is derived from `SamlDocumentType` via `format!("{:?}", result.document_type)` (produces `"Assertion"`, `"Response"`, `"AuthnRequest"`). `byte_count` is `result.xml.as_bytes().len()`.

**Diffs Only filtering:** Performed in JavaScript on the frontend using the full results returned by the backend. The `DiffResult.lines` array contains all lines; JS filters to non-`Same` entries plus 2 lines of context.

**Empty diff:** When `diff_count` is 0, the "Diffs Only" view shows a centered message: "No differences found."

**Back button:** Returns to input phase, preserving both textareas and decode status indicators as-is.

**JSON serialization shapes:** `Vec<(usize, usize)>` serializes as `[[0, 5], [8, 12]]` — JS accesses as `span[0]` / `span[1]`. `Vec<u8>` serializes as `[72, 101, 108]` — array of numbers.

## Frontend Patterns

**Screen registration:** Add `compare: document.getElementById('screen-compare')` to the screens map in `app.js`.

**Init function:** Add `initCompare()` called from `init()`, matching existing `initHome()`, `initAuth()`, `initViewer()`, `initResult()` pattern.

**Keyboard:** Escape key returns to previous screen (matching existing behavior). No additional keyboard shortcuts needed.

## New Files

| File | Purpose |
|------|---------|
| None | No new Rust files — commands added to existing `commands.rs` |

## Modified Files

| File | Change |
|------|--------|
| `src-tauri/src/commands.rs` | Add `compare_saml`, `compare_revalidate` commands + DTO structs |
| `src-tauri/src/lib.rs` | Register new commands in `invoke_handler` |
| `ui/index.html` | Add Compare screen HTML, add Compare button to Home screen |
| `ui/app.js` | Add compare screen logic: input handling, tab switching, diff rendering, synchronized scrolling |
| `ui/styles.css` | Add styles for compare screen: split panes, diff highlighting, hex view, tab bar, collapsible sections |

## Frontend State Additions

```javascript
// In state object
compareInputA: null,      // raw input string
compareInputB: null,      // raw input string
compareResult: null,      // CompareResult from backend
compareDecodedA: null,    // decoded XML for revalidation
compareDecodedB: null,    // decoded XML for revalidation
compareActiveTab: 'xml',  // xml | hex | c14n | validation | all
compareDiffsOnly: false,  // toggle filter
```

## Synchronized Scrolling

For side-by-side panels (XML, Hex, C14N), both panels scroll together:

```javascript
leftPane.onscroll = () => { rightPane.scrollTop = leftPane.scrollTop; };
rightPane.onscroll = () => { leftPane.scrollTop = rightPane.scrollTop; };
```

## No External Dependencies

All diff computation uses the existing `saml::diff` module. Frontend rendering uses vanilla JS/HTML/CSS matching the existing app.js patterns. No new npm packages or Rust crates.
