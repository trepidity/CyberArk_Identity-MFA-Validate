# Tauri SAML Comparison — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the SAML assertion comparison feature to the Tauri desktop GUI with 5 tabs (XML Diff, Hex/Bytes, C14N, Validation, All) and side-by-side diff rendering.

**Architecture:** Two new Tauri commands (`compare_saml`, `compare_revalidate`) call the existing `saml::diff` engine and return serialized DTOs. The frontend adds a 5th screen with input phase (two panels) and results phase (tabbed diff views). All diff computation in Rust; JS renders only.

**Tech Stack:** Rust (Tauri v2, seahorse library), vanilla JS/HTML/CSS, existing `saml::diff`, `saml::c14n`, `saml::validator` modules.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `seahorse/src-tauri/src/commands.rs` | Modify | Add `compare_saml`, `compare_revalidate` commands + DTO structs |
| `seahorse/src-tauri/src/lib.rs` | Modify | Register new commands in `invoke_handler` |
| `seahorse/ui/index.html` | Modify | Add Compare screen HTML + Compare button on Home |
| `seahorse/ui/app.js` | Modify | Add compare logic: input handling, tab switching, diff rendering |
| `seahorse/ui/styles.css` | Modify | Add compare screen styles |

---

### Task 1: Tauri Commands — DTOs and `compare_saml`

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`
- Modify: `seahorse/src-tauri/src/lib.rs`

- [ ] **Step 1: Add DTO structs to commands.rs**

Add after the existing `CertInfoDto` struct (around line 57) in `seahorse/src-tauri/src/commands.rs`:

```rust
// --- Compare DTOs ---

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
pub struct CompareResult {
    pub decode_a: DecodeInfo,
    pub decode_b: DecodeInfo,
    pub xml_diff: DiffResultInfo,
    pub hex_diff: Vec<ByteDiffRowInfo>,
    pub c14n_diff: DiffResultInfo,
    pub validation_a: seahorse::saml::validator::ValidationReport,
    pub validation_b: seahorse::saml::validator::ValidationReport,
}

#[derive(Serialize)]
pub struct CompareRevalidateResult {
    pub validation_a: seahorse::saml::validator::ValidationReport,
    pub validation_b: seahorse::saml::validator::ValidationReport,
}
```

- [ ] **Step 2: Add conversion helpers**

Add helper functions to convert from `saml::diff` types to the DTOs:

```rust
fn convert_diff_result(dr: &seahorse::saml::diff::DiffResult) -> DiffResultInfo {
    DiffResultInfo {
        lines: dr.lines.iter().map(convert_diff_line).collect(),
        left_total: dr.left_total,
        right_total: dr.right_total,
        diff_count: dr.diff_count,
    }
}

fn convert_diff_line(dl: &seahorse::saml::diff::DiffLine) -> DiffLineInfo {
    match dl {
        seahorse::saml::diff::DiffLine::Same(text) => DiffLineInfo::Same { text: text.clone() },
        seahorse::saml::diff::DiffLine::Added(text) => DiffLineInfo::Added { text: text.clone() },
        seahorse::saml::diff::DiffLine::Removed(text) => DiffLineInfo::Removed { text: text.clone() },
        seahorse::saml::diff::DiffLine::Changed { left, right, left_spans, right_spans } => {
            DiffLineInfo::Changed {
                left: left.clone(),
                right: right.clone(),
                left_spans: left_spans.clone(),
                right_spans: right_spans.clone(),
            }
        }
    }
}

fn convert_byte_diff(rows: &[seahorse::saml::diff::ByteDiffRow]) -> Vec<ByteDiffRowInfo> {
    rows.iter().map(|r| ByteDiffRowInfo {
        offset: r.offset,
        left_bytes: r.left_bytes.clone(),
        right_bytes: r.right_bytes.clone(),
        diffs: r.diffs.clone(),
    }).collect()
}

fn extract_inclusive_prefixes(xml: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    if let Some(start) = xml.find("PrefixList=\"") {
        let rest = &xml[start + 12..];
        if let Some(end) = rest.find('"') {
            for prefix in rest[..end].split_whitespace() {
                prefixes.push(prefix.to_string());
            }
        }
    }
    prefixes
}

fn extract_assertion_xml(decoded_xml: &str, doc_type: &seahorse::saml::decoder::SamlDocumentType) -> Result<String, String> {
    match doc_type {
        seahorse::saml::decoder::SamlDocumentType::Assertion => Ok(decoded_xml.to_string()),
        seahorse::saml::decoder::SamlDocumentType::Response => {
            seahorse::saml::parser::extract_assertion_from_response(decoded_xml)
                .map_err(|e| format!("Failed to extract assertion from Response: {}", e))
        }
        seahorse::saml::decoder::SamlDocumentType::AuthnRequest => {
            Err("Cannot compare AuthnRequest documents — only Assertions and Responses are supported".to_string())
        }
    }
}
```

- [ ] **Step 3: Implement `compare_saml` command**

Add the async command:

```rust
#[tauri::command]
pub async fn compare_saml(
    state: State<'_, Mutex<AppState>>,
    input_a: String,
    input_b: String,
) -> Result<CompareResult, String> {
    // Decode both inputs
    let result_a = seahorse::saml::decoder::decode_saml_input(&input_a)
        .map_err(|e| format!("Failed to decode Assertion A: {}", e))?;
    let result_b = seahorse::saml::decoder::decode_saml_input(&input_b)
        .map_err(|e| format!("Failed to decode Assertion B: {}", e))?;

    let decode_a = DecodeInfo {
        doc_type: format!("{:?}", result_a.document_type),
        byte_count: result_a.xml.as_bytes().len(),
    };
    let decode_b = DecodeInfo {
        doc_type: format!("{:?}", result_b.document_type),
        byte_count: result_b.xml.as_bytes().len(),
    };

    // Extract assertion XML (auto-extract from Response if needed)
    let xml_a = extract_assertion_xml(&result_a.xml, &result_a.document_type)?;
    let xml_b = extract_assertion_xml(&result_b.xml, &result_b.document_type)?;

    // Run all comparisons in a blocking task to avoid freezing UI
    let trust_store_ref = {
        let guard = state.lock().unwrap();
        guard.idp_trust_store.clone()
    };

    let compare_result = tokio::task::spawn_blocking(move || {
        // Mode 1: XML diff (pretty-printed)
        let pretty_a = seahorse::saml::parser::pretty_print_xml(&xml_a);
        let pretty_b = seahorse::saml::parser::pretty_print_xml(&xml_b);
        let xml_diff = seahorse::saml::diff::diff_lines(&pretty_a, &pretty_b);

        // Mode 2: Byte diff
        let hex_diff = seahorse::saml::diff::diff_bytes(xml_a.as_bytes(), xml_b.as_bytes());

        // Mode 3: C14N diff
        let c14n_a = compute_c14n_text(&xml_a);
        let c14n_b = compute_c14n_text(&xml_b);
        let c14n_diff = seahorse::saml::diff::diff_lines(&c14n_a, &c14n_b);

        // Mode 4: Validation
        let validation_a = seahorse::saml::validator::validate_assertion(&xml_a, trust_store_ref.as_ref());
        let validation_b = seahorse::saml::validator::validate_assertion(&xml_b, trust_store_ref.as_ref());

        CompareResult {
            decode_a,
            decode_b,
            xml_diff: convert_diff_result(&xml_diff),
            hex_diff: convert_byte_diff(&hex_diff),
            c14n_diff: convert_diff_result(&c14n_diff),
            validation_a,
            validation_b,
        }
    })
    .await
    .map_err(|e| format!("Comparison task failed: {}", e))?;

    Ok(compare_result)
}

fn compute_c14n_text(xml: &str) -> String {
    let without_sig = seahorse::saml::c14n::remove_signature_element(xml)
        .unwrap_or_else(|_| xml.to_string());
    let prefixes = extract_inclusive_prefixes(xml);
    let prefix_refs: Vec<&str> = prefixes.iter().map(|s| s.as_str()).collect();
    match seahorse::saml::c14n::canonicalize_exclusive(&without_sig, &prefix_refs) {
        Ok(bytes) => {
            let raw = String::from_utf8_lossy(&bytes).to_string();
            seahorse::saml::parser::pretty_print_xml(&raw)
        }
        Err(_) => "(canonicalization failed)".to_string(),
    }
}
```

- [ ] **Step 4: Implement `compare_revalidate` command**

```rust
#[tauri::command]
pub fn compare_revalidate(
    state: State<'_, Mutex<AppState>>,
    xml_a: String,
    xml_b: String,
) -> Result<CompareRevalidateResult, String> {
    let guard = state.lock().unwrap();
    let trust_store = guard.idp_trust_store.as_ref();
    Ok(CompareRevalidateResult {
        validation_a: seahorse::saml::validator::validate_assertion(&xml_a, trust_store),
        validation_b: seahorse::saml::validator::validate_assertion(&xml_b, trust_store),
    })
}
```

- [ ] **Step 5: Register commands in lib.rs**

In `seahorse/src-tauri/src/lib.rs`, add to the `generate_handler!` macro:

```rust
            commands::compare_saml,
            commands::compare_revalidate,
```

- [ ] **Step 6: Verify it compiles**

Run: `cd seahorse/src-tauri && cargo check 2>&1 | tail -10`
Expected: compiles (frontend not wired yet)

- [ ] **Step 7: Commit**

```bash
git add seahorse/src-tauri/src/commands.rs seahorse/src-tauri/src/lib.rs
git commit -m "feat: add compare_saml and compare_revalidate Tauri commands"
```

---

### Task 2: HTML — Compare Screen and Home Button

**Files:**
- Modify: `seahorse/ui/index.html`

- [ ] **Step 1: Add Compare button to Home screen**

In `seahorse/ui/index.html`, after the existing "View SAML Assertion" button (line 46), add:

```html
      <button id="btn-compare" class="btn btn-neutral">Compare SAML Assertions</button>
```

- [ ] **Step 2: Add Compare screen HTML**

Add after the closing `</section>` of screen-viewer (before the `<script>` tag, around line 178):

```html
  <!-- Screen 5: Compare -->
  <section id="screen-compare" class="screen">
    <div class="screen-content">
      <header class="screen-header">
        <button id="compare-back" class="btn-back" aria-label="Back">&larr; Back</button>
        <h2 class="screen-title">Compare SAML Assertions</h2>
      </header>

      <!-- Input Phase -->
      <div id="compare-input-phase">
        <div class="compare-panels">
          <div class="compare-panel" id="compare-panel-a">
            <h3 class="panel-title">Assertion A</h3>
            <div class="compare-panel-actions">
              <button id="btn-open-file-a" class="btn btn-action btn-sm">Open File</button>
              <button id="btn-paste-a" class="btn btn-action btn-sm">Paste from Clipboard</button>
            </div>
            <textarea id="compare-input-a" class="saml-textarea" placeholder="Paste SAML data here..." rows="10"></textarea>
            <div id="compare-status-a" class="compare-status"></div>
          </div>
          <div class="compare-panel" id="compare-panel-b">
            <h3 class="panel-title">Assertion B</h3>
            <div class="compare-panel-actions">
              <button id="btn-open-file-b" class="btn btn-action btn-sm">Open File</button>
              <button id="btn-paste-b" class="btn btn-action btn-sm">Paste from Clipboard</button>
            </div>
            <textarea id="compare-input-b" class="saml-textarea" placeholder="Paste SAML data here..." rows="10"></textarea>
            <div id="compare-status-b" class="compare-status"></div>
          </div>
        </div>
        <button id="btn-compare-go" class="btn btn-primary btn-full">Compare</button>
        <div id="compare-spinner" class="viewer-spinner hidden">
          <div class="spinner"></div>
          <span>Comparing...</span>
        </div>
      </div>

      <!-- Results Phase -->
      <div id="compare-results-phase" class="hidden">
        <div class="compare-toolbar">
          <div class="compare-tab-bar">
            <button class="compare-tab active" data-ctab="xml">XML Diff</button>
            <button class="compare-tab" data-ctab="hex">Hex / Bytes</button>
            <button class="compare-tab" data-ctab="c14n">Canonicalized</button>
            <button class="compare-tab" data-ctab="validation">Validation</button>
            <button class="compare-tab" data-ctab="all">All</button>
          </div>
          <div class="compare-toolbar-right">
            <button id="btn-diffs-only" class="btn btn-action btn-sm">Diffs Only</button>
            <span id="compare-diff-count" class="compare-diff-count"></span>
            <button id="btn-load-idp-compare" class="btn btn-action btn-sm">Load IDP Cert</button>
            <button id="btn-load-chain-compare" class="btn btn-action btn-sm">Load Chain Cert</button>
          </div>
        </div>

        <div id="compare-content" class="compare-content">
          <!-- Tab content rendered by JS -->
        </div>
      </div>
    </div>
  </section>
```

- [ ] **Step 3: Commit**

```bash
git add seahorse/ui/index.html
git commit -m "feat: add Compare screen HTML and Home button"
```

---

### Task 3: CSS — Compare Screen Styles

**Files:**
- Modify: `seahorse/ui/styles.css`

- [ ] **Step 1: Add compare screen styles**

Append to the end of `seahorse/ui/styles.css`:

```css
/* ---- Compare Screen ---- */

.compare-panels {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
}

.compare-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.compare-panel-actions {
  display: flex;
  gap: 8px;
}

.btn-sm {
  padding: 4px 12px;
  font-size: 12px;
}

.compare-status {
  font-size: 12px;
  min-height: 20px;
}

.compare-status.success { color: var(--green); }
.compare-status.error { color: var(--red); }

/* Compare toolbar */
.compare-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.compare-tab-bar {
  display: flex;
  gap: 0;
  border-bottom: 2px solid var(--bg-border);
}

.compare-tab {
  padding: 8px 16px;
  font-size: 13px;
  color: var(--text-dim);
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  margin-bottom: -2px;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s;
}

.compare-tab:hover { color: var(--text-secondary); }

.compare-tab.active {
  color: var(--blue);
  border-bottom-color: var(--blue);
  font-weight: 600;
}

.compare-toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.compare-diff-count {
  font-size: 12px;
  color: var(--text-secondary);
}

#btn-diffs-only.active {
  background: var(--blue);
  color: white;
}

/* Compare content area */
.compare-content {
  min-height: 400px;
}

/* Side-by-side diff panes */
.diff-split {
  display: flex;
  gap: 2px;
}

.diff-pane {
  flex: 1;
  background: var(--bg-deepest);
  border: 1px solid var(--bg-border);
  border-radius: 4px;
  overflow: auto;
  max-height: 60vh;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  padding: 8px 0;
}

.diff-pane-title {
  font-size: 11px;
  color: var(--text-secondary);
  font-weight: 600;
  padding: 4px 12px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--bg-border);
  position: sticky;
  top: 0;
  z-index: 1;
}

/* Diff lines */
.diff-line {
  padding: 0 12px;
  white-space: pre;
  min-height: 1.6em;
}

.diff-line-num {
  display: inline-block;
  width: 32px;
  text-align: right;
  margin-right: 8px;
  color: var(--text-dim);
  user-select: none;
}

.diff-line.same { color: var(--text-dim); }
.diff-line.removed { color: var(--red); }
.diff-line.added { color: var(--green); }
.diff-line.changed-left { color: var(--text-primary); }
.diff-line.changed-right { color: var(--text-primary); }
.diff-line.blank { visibility: hidden; }

.diff-highlight-red {
  background: rgba(239, 68, 68, 0.3);
  color: #fca5a5;
  border-radius: 2px;
}

.diff-highlight-green {
  background: rgba(34, 197, 94, 0.3);
  color: #86efac;
  border-radius: 2px;
}

/* Hex diff */
.hex-offset { color: var(--text-dim); }
.hex-byte { color: var(--text-secondary); }
.hex-diff {
  background: rgba(234, 179, 8, 0.3);
  color: #fde047;
  border-radius: 2px;
}
.hex-ascii { color: var(--text-dim); }

/* Validation comparison table */
.val-compare-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.val-compare-table th {
  text-align: left;
  padding: 8px 12px;
  color: var(--text-secondary);
  font-weight: 600;
  border-bottom: 1px solid var(--bg-border);
}

.val-compare-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--bg-card);
}

.val-compare-table .diff-row { background: rgba(239, 68, 68, 0.08); }
.val-compare-table .pass { color: var(--green); }
.val-compare-table .fail { color: var(--red); }
.val-compare-table .skip { color: var(--text-dim); }

.val-footer {
  margin-top: 12px;
  font-size: 12px;
  color: var(--text-secondary);
}

/* All tab summary cards */
.compare-summary-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

.compare-summary-card {
  flex: 1;
  background: var(--bg-deepest);
  border: 1px solid var(--bg-border);
  border-radius: 6px;
  padding: 12px 16px;
}

.compare-summary-card h4 {
  font-size: 11px;
  color: var(--text-dim);
  text-transform: uppercase;
  margin: 0 0 4px;
}

.compare-summary-card .value {
  font-size: 18px;
  font-weight: 600;
}

/* Collapsible sections */
.compare-section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  cursor: pointer;
  color: var(--text-secondary);
  font-weight: 600;
  font-size: 13px;
  border-bottom: 1px solid var(--bg-border);
  user-select: none;
}

.compare-section-header .arrow {
  transition: transform 0.2s;
  font-size: 10px;
}

.compare-section-header.collapsed .arrow {
  transform: rotate(-90deg);
}

.compare-section-body.collapsed {
  display: none;
}

.compare-no-diffs {
  text-align: center;
  color: var(--text-dim);
  padding: 40px 0;
  font-size: 14px;
}
```

- [ ] **Step 2: Commit**

```bash
git add seahorse/ui/styles.css
git commit -m "feat: add compare screen CSS styles"
```

---

### Task 4: JavaScript — Compare Screen Logic (Input Phase)

**Files:**
- Modify: `seahorse/ui/app.js`

- [ ] **Step 1: Add compare state and screen registration**

In `seahorse/ui/app.js`, add to the `state` object (around line 22):

```javascript
    compareInputA: null,
    compareInputB: null,
    compareResult: null,
    compareXmlA: null,       // raw decoded XML for revalidation
    compareXmlB: null,
    compareActiveTab: 'xml',
    compareDiffsOnly: false,
```

Add to the `screens` object (around line 34):

```javascript
    compare: $('#screen-compare'),
```

- [ ] **Step 2: Add `initCompare()` function**

Add before the `init()` function:

```javascript
  // ---- Compare Screen ----

  function initCompare() {
    // Home button
    $('#btn-compare').addEventListener('click', () => showScreen('compare'));

    // Back button
    $('#compare-back').addEventListener('click', () => {
      if (!$('#compare-results-phase').classList.contains('hidden')) {
        // Back from results to input
        $('#compare-results-phase').classList.add('hidden');
        $('#compare-input-phase').classList.remove('hidden');
      } else {
        showScreen('home');
      }
    });

    // Open file buttons
    $('#btn-open-file-a').addEventListener('click', () => loadCompareFile('a'));
    $('#btn-open-file-b').addEventListener('click', () => loadCompareFile('b'));

    // Paste buttons
    $('#btn-paste-a').addEventListener('click', () => pasteCompare('a'));
    $('#btn-paste-b').addEventListener('click', () => pasteCompare('b'));

    // Compare button
    $('#btn-compare-go').addEventListener('click', runComparison);

    // Tab switching
    $$('.compare-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        $$('.compare-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.compareActiveTab = tab.dataset.ctab;
        renderCompareTab();
      });
    });

    // Diffs only toggle
    $('#btn-diffs-only').addEventListener('click', () => {
      state.compareDiffsOnly = !state.compareDiffsOnly;
      $('#btn-diffs-only').classList.toggle('active', state.compareDiffsOnly);
      renderCompareTab();
    });

    // IDP cert buttons
    $('#btn-load-idp-compare').addEventListener('click', async () => {
      await loadIdpCert();
      await revalidateComparison();
    });
    $('#btn-load-chain-compare').addEventListener('click', async () => {
      await loadChainCert();
      await revalidateComparison();
    });
  }

  async function loadCompareFile(side) {
    try {
      const selected = await openFileDialog([
        { name: 'SAML', extensions: ['xml', 'saml', 'txt', '*'] }
      ]);
      if (!selected) return;
      const filePath = typeof selected === 'string' ? selected : selected.path;
      const response = await fetch(window.__TAURI__.core.convertFileSrc(filePath));
      const text = await response.text();
      $(`#compare-input-${side}`).value = text;
      setCompareStatus(side, 'Loaded from file', 'success');
    } catch (e) {
      showError('Failed to open file: ' + e);
    }
  }

  async function pasteCompare(side) {
    try {
      const text = await clipboardRead();
      $(`#compare-input-${side}`).value = text;
      setCompareStatus(side, 'Pasted from clipboard', 'success');
    } catch (e) {
      showError('Failed to read clipboard: ' + e);
    }
  }

  function setCompareStatus(side, message, type) {
    const el = $(`#compare-status-${side}`);
    el.textContent = message;
    el.className = 'compare-status ' + (type || '');
  }

  async function runComparison() {
    const inputA = $('#compare-input-a').value.trim();
    const inputB = $('#compare-input-b').value.trim();

    if (!inputA) { showError('Assertion A is empty'); return; }
    if (!inputB) { showError('Assertion B is empty'); return; }

    $('#compare-spinner').classList.remove('hidden');
    $('#btn-compare-go').disabled = true;

    try {
      const result = await invoke('compare_saml', { inputA, inputB });
      state.compareResult = result;
      state.compareInputA = inputA;
      state.compareInputB = inputB;
      state.compareXmlA = null; // will be set if needed for revalidation
      state.compareXmlB = null;

      // Switch to results phase
      $('#compare-input-phase').classList.add('hidden');
      $('#compare-results-phase').classList.remove('hidden');

      // Update diff count
      $('#compare-diff-count').textContent = result.xml_diff.diff_count + ' differences';

      // Reset tab to XML
      state.compareActiveTab = 'xml';
      $$('.compare-tab').forEach(t => t.classList.remove('active'));
      $('.compare-tab[data-ctab="xml"]').classList.add('active');

      renderCompareTab();
    } catch (e) {
      showError('' + e);
    } finally {
      $('#compare-spinner').classList.add('hidden');
      $('#btn-compare-go').disabled = false;
    }
  }

  async function revalidateComparison() {
    if (!state.compareInputA || !state.compareInputB) return;
    try {
      const result = await invoke('compare_revalidate', {
        xmlA: state.compareInputA,
        xmlB: state.compareInputB,
      });
      state.compareResult.validation_a = result.validation_a;
      state.compareResult.validation_b = result.validation_b;
      if (state.compareActiveTab === 'validation' || state.compareActiveTab === 'all') {
        renderCompareTab();
      }
      showStatus('Re-validated with updated certificates');
    } catch (e) {
      showError('Re-validation failed: ' + e);
    }
  }
```

- [ ] **Step 3: Wire `initCompare()` into `init()`**

In the `init()` function, add after `initResult();`:

```javascript
    initCompare();
```

- [ ] **Step 4: Add shared IDP cert helpers**

Add `loadIdpCert` and `loadChainCert` helper functions that are reusable (if they don't already exist as standalone functions — check the existing code and extract if needed). The existing viewer has inline handlers; extract them to shared functions:

```javascript
  async function loadIdpCert() {
    const selected = await openFileDialog([
      { name: 'Certificate', extensions: ['pem', 'cer', 'crt', '*'] }
    ]);
    if (!selected) return;
    const filePath = typeof selected === 'string' ? selected : selected.path;
    const result = await invoke('load_idp_cert', { path: filePath });
    state.idpCertInfo = result;
    showStatus('IDP cert loaded: ' + result.cn);
  }

  async function loadChainCert() {
    const selected = await openFileDialog([
      { name: 'Certificate', extensions: ['pem', 'cer', 'crt', '*'] }
    ]);
    if (!selected) return;
    const filePath = typeof selected === 'string' ? selected : selected.path;
    const result = await invoke('load_chain_cert', { path: filePath });
    state.idpCertInfo = result;
    showStatus('Chain cert loaded (' + result.chain_count + ' certs)');
  }
```

Note: If the existing viewer already has these as inline handlers, refactor the viewer to call these shared functions too.

- [ ] **Step 5: Verify it compiles/loads**

Run: `cd seahorse && cargo tauri dev` — verify the Compare button appears on Home and navigating to the Compare screen works (results rendering will be Task 5).

- [ ] **Step 6: Commit**

```bash
git add seahorse/ui/app.js
git commit -m "feat: add compare screen JS logic — input phase, file/paste, comparison trigger"
```

---

### Task 5: JavaScript — Diff Rendering (All 5 Tabs)

**Files:**
- Modify: `seahorse/ui/app.js`

- [ ] **Step 1: Add `renderCompareTab()` dispatcher**

```javascript
  function renderCompareTab() {
    const container = $('#compare-content');
    const result = state.compareResult;
    if (!result) return;

    switch (state.compareActiveTab) {
      case 'xml':
        container.innerHTML = renderLineDiff(result.xml_diff, 'Assertion A', 'Assertion B');
        syncDiffScroll(container);
        break;
      case 'hex':
        container.innerHTML = renderHexDiff(result.hex_diff);
        syncDiffScroll(container);
        break;
      case 'c14n':
        container.innerHTML = renderLineDiff(result.c14n_diff, 'Assertion A (c14n)', 'Assertion B (c14n)');
        syncDiffScroll(container);
        break;
      case 'validation':
        container.innerHTML = renderValidationDiff(result.validation_a, result.validation_b);
        break;
      case 'all':
        container.innerHTML = renderAllTab(result);
        setupCollapsible(container);
        syncDiffScroll(container);
        break;
    }

    // Update diff count display
    let count = 0;
    if (state.compareActiveTab === 'xml') count = result.xml_diff.diff_count;
    else if (state.compareActiveTab === 'c14n') count = result.c14n_diff.diff_count;
    else if (state.compareActiveTab === 'hex') count = result.hex_diff.filter(r => r.diffs.length > 0).length;
    $('#compare-diff-count').textContent = count + ' differences';
  }
```

- [ ] **Step 2: Add `renderLineDiff()` — for XML and C14N tabs**

```javascript
  function renderLineDiff(diff, titleA, titleB) {
    const lines = filterDiffLines(diff.lines);
    if (state.compareDiffsOnly && lines.length === 0) {
      return '<div class="compare-no-diffs">No differences found</div>';
    }

    let leftHtml = '';
    let rightHtml = '';
    let leftNum = 0, rightNum = 0;

    for (const line of lines) {
      switch (line.type) {
        case 'Same':
          leftNum++; rightNum++;
          leftHtml += diffLineHtml(leftNum, escapeHtml(line.text), 'same');
          rightHtml += diffLineHtml(rightNum, escapeHtml(line.text), 'same');
          break;
        case 'Removed':
          leftNum++;
          leftHtml += diffLineHtml(leftNum, escapeHtml(line.text), 'removed');
          rightHtml += diffLineHtml('', '', 'blank');
          break;
        case 'Added':
          rightNum++;
          leftHtml += diffLineHtml('', '', 'blank');
          rightHtml += diffLineHtml(rightNum, escapeHtml(line.text), 'added');
          break;
        case 'Changed':
          leftNum++; rightNum++;
          leftHtml += diffLineHtml(leftNum, highlightSpans(line.left, line.left_spans, 'red'), 'changed-left');
          rightHtml += diffLineHtml(rightNum, highlightSpans(line.right, line.right_spans, 'green'), 'changed-right');
          break;
      }
    }

    return `<div class="diff-split">
      <div class="diff-pane" data-diff-pane="left">
        <div class="diff-pane-title">${titleA}</div>
        ${leftHtml}
      </div>
      <div class="diff-pane" data-diff-pane="right">
        <div class="diff-pane-title">${titleB}</div>
        ${rightHtml}
      </div>
    </div>`;
  }

  function diffLineHtml(num, content, cls) {
    return `<div class="diff-line ${cls}"><span class="diff-line-num">${num}</span>${content}</div>`;
  }

  function highlightSpans(text, spans, color) {
    if (!spans || spans.length === 0) return escapeHtml(text);
    const chars = [...text]; // spread to handle unicode
    let result = '';
    let pos = 0;
    for (const [start, end] of spans) {
      if (pos < start) result += escapeHtml(chars.slice(pos, start).join(''));
      result += `<span class="diff-highlight-${color}">${escapeHtml(chars.slice(start, end).join(''))}</span>`;
      pos = end;
    }
    if (pos < chars.length) result += escapeHtml(chars.slice(pos).join(''));
    return result;
  }

  function filterDiffLines(lines) {
    if (!state.compareDiffsOnly) return lines;
    const context = 2;
    const visible = new Array(lines.length).fill(false);
    lines.forEach((line, i) => {
      if (line.type !== 'Same') {
        for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j++) {
          visible[j] = true;
        }
      }
    });
    return lines.filter((_, i) => visible[i]);
  }
```

- [ ] **Step 3: Add `renderHexDiff()`**

```javascript
  function renderHexDiff(rows) {
    const filtered = state.compareDiffsOnly ? rows.filter(r => r.diffs.length > 0) : rows;
    if (state.compareDiffsOnly && filtered.length === 0) {
      return '<div class="compare-no-diffs">No differences found</div>';
    }

    let leftHtml = '';
    let rightHtml = '';

    for (const row of filtered) {
      leftHtml += hexRowHtml(row.offset, row.left_bytes, row.diffs);
      rightHtml += hexRowHtml(row.offset, row.right_bytes, row.diffs);
    }

    return `<div class="diff-split">
      <div class="diff-pane" data-diff-pane="left">
        <div class="diff-pane-title">Assertion A (hex)</div>
        ${leftHtml}
      </div>
      <div class="diff-pane" data-diff-pane="right">
        <div class="diff-pane-title">Assertion B (hex)</div>
        ${rightHtml}
      </div>
    </div>`;
  }

  function hexRowHtml(offset, bytes, diffs) {
    let hex = `<span class="hex-offset">${offset.toString(16).padStart(8, '0')}</span>  `;
    for (let i = 0; i < 16; i++) {
      if (i === 8) hex += ' ';
      if (i < bytes.length) {
        const cls = diffs.includes(i) ? 'hex-diff' : 'hex-byte';
        hex += `<span class="${cls}">${bytes[i].toString(16).padStart(2, '0')}</span> `;
      } else {
        hex += '   ';
      }
    }
    hex += ' |';
    for (let i = 0; i < 16; i++) {
      if (i < bytes.length) {
        const ch = (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
        const cls = diffs.includes(i) ? 'hex-diff' : 'hex-ascii';
        hex += `<span class="${cls}">${escapeHtml(ch)}</span>`;
      } else {
        hex += ' ';
      }
    }
    hex += '|';
    return `<div class="diff-line">${hex}</div>`;
  }
```

- [ ] **Step 4: Add `renderValidationDiff()`**

```javascript
  function renderValidationDiff(valA, valB) {
    const maxChecks = Math.max(valA.checks.length, valB.checks.length);
    let rows = '';

    for (let i = 0; i < maxChecks; i++) {
      const ca = valA.checks[i];
      const cb = valB.checks[i];
      const name = (ca || cb).name;
      const [textA, clsA] = checkDisplay(ca);
      const [textB, clsB] = checkDisplay(cb);
      const differs = ca && cb && ca.passed !== cb.passed;
      rows += `<tr class="${differs ? 'diff-row' : ''}">
        <td>${name}</td>
        <td class="${clsA}">${textA}</td>
        <td class="${clsB}">${textB}</td>
      </tr>`;
    }

    const algoA = shortAlgo(valA.algorithm);
    const algoB = shortAlgo(valB.algorithm);

    return `<table class="val-compare-table">
      <thead><tr><th>Check</th><th>Assertion A</th><th>Assertion B</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="val-footer">
      <div>A: ${algoA} | ${valA.cert_subject || 'no cert'}</div>
      <div>B: ${algoB} | ${valB.cert_subject || 'no cert'}</div>
    </div>`;
  }

  function checkDisplay(check) {
    if (!check) return ['—', 'skip'];
    if (check.passed) return ['&#10003; Pass', 'pass'];
    if (check.detail.includes('kipped') || check.detail.includes('No ')) return ['— Skipped', 'skip'];
    return ['&#10007; FAIL', 'fail'];
  }

  function shortAlgo(algo) {
    if (!algo) return 'unknown';
    if (algo.includes('sha256') || algo.includes('sha-256')) return 'SHA-256';
    if (algo.includes('sha1') || algo.includes('sha-1')) return 'SHA-1';
    return algo;
  }
```

- [ ] **Step 5: Add `renderAllTab()` and collapsible sections**

```javascript
  function renderAllTab(result) {
    const summaryA = result.validation_a.summary;
    const summaryB = result.validation_b.summary;

    let html = `<div class="compare-summary-row">
      <div class="compare-summary-card">
        <h4>Differences</h4>
        <div class="value" style="color: ${result.xml_diff.diff_count > 0 ? 'var(--red)' : 'var(--green)'}">${result.xml_diff.diff_count} found</div>
      </div>
      <div class="compare-summary-card">
        <h4>Assertion A</h4>
        <div class="value" style="color: ${summaryA === 'Failed' ? 'var(--red)' : 'var(--green)'}">${summaryA}</div>
      </div>
      <div class="compare-summary-card">
        <h4>Assertion B</h4>
        <div class="value" style="color: ${summaryB === 'Failed' ? 'var(--red)' : 'var(--green)'}">${summaryB}</div>
      </div>
    </div>`;

    html += sectionBlock('Validation', renderValidationDiff(result.validation_a, result.validation_b));
    html += sectionBlock('XML Diff', renderLineDiff(result.xml_diff, 'Assertion A', 'Assertion B'));
    html += sectionBlock('Hex / Bytes', renderHexDiff(result.hex_diff));
    html += sectionBlock('Canonicalized', renderLineDiff(result.c14n_diff, 'Assertion A (c14n)', 'Assertion B (c14n)'));

    return html;
  }

  function sectionBlock(title, content) {
    return `<div class="compare-section">
      <div class="compare-section-header" onclick="this.classList.toggle('collapsed');this.nextElementSibling.classList.toggle('collapsed')">
        <span class="arrow">&#9660;</span> ${title}
      </div>
      <div class="compare-section-body">${content}</div>
    </div>`;
  }

  function setupCollapsible(container) {
    // Already handled by inline onclick — no extra setup needed
  }
```

- [ ] **Step 6: Add `syncDiffScroll()`**

```javascript
  function syncDiffScroll(container) {
    const panes = container.querySelectorAll('.diff-pane');
    if (panes.length < 2) return;

    // For each pair of adjacent panes, sync scrolling
    for (let i = 0; i < panes.length; i += 2) {
      const left = panes[i];
      const right = panes[i + 1];
      if (!left || !right) continue;

      let syncing = false;
      left.addEventListener('scroll', () => {
        if (syncing) return;
        syncing = true;
        right.scrollTop = left.scrollTop;
        right.scrollLeft = left.scrollLeft;
        syncing = false;
      });
      right.addEventListener('scroll', () => {
        if (syncing) return;
        syncing = true;
        left.scrollTop = right.scrollTop;
        left.scrollLeft = right.scrollLeft;
        syncing = false;
      });
    }
  }
```

- [ ] **Step 7: Commit**

```bash
git add seahorse/ui/app.js
git commit -m "feat: add compare diff rendering — XML, hex, C14N, validation, and All tabs"
```

---

### Task 6: Build, Test, and Polish

**Files:**
- Possibly modify: all UI files for fixes

- [ ] **Step 1: Build the Tauri app**

Run: `cd seahorse && cargo tauri dev`
Expected: app launches, Home screen shows "Compare SAML Assertions" button

- [ ] **Step 2: Test the comparison flow**

1. Click "Compare SAML Assertions"
2. In left panel: click "Open File", select `sample_files/assertion_response.xml`
3. In right panel: paste a modified version (or the same file)
4. Click "Compare"
5. Verify: XML Diff tab shows side-by-side diff
6. Switch to Hex tab — verify hex dump renders
7. Switch to C14N tab — verify canonicalized diff
8. Switch to Validation tab — verify check table
9. Switch to All tab — verify summary + collapsible sections
10. Toggle "Diffs Only" — verify filtering works
11. Click Back — verify return to input phase with data preserved

- [ ] **Step 3: Fix any rendering issues**

Address layout, color, scrolling, or data issues found during testing.

- [ ] **Step 4: Commit fixes**

```bash
git add -A
git commit -m "fix: polish Tauri compare screen after manual testing"
```
