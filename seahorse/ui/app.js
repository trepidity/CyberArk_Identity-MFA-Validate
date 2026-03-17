// ============================================
// Seahorse - SAML Validation Tool
// Frontend Application
// ============================================

(function () {
  'use strict';

  // ---- State ----

  const state = {
    currentScreen: 'home',
    previousScreen: null,
    environment: null,    // 'PROD' or 'TST'
    authFlow: 'browser',  // 'browser' or 'rest'
    configInfo: null,
    lastResult: null,      // last DecodedSaml result
    lastRawXml: null,
    lastPrettyXml: null,
    idpCertInfo: null,
    unlistenProgress: null,
    // Compare screen state
    compareInputA: null,
    compareInputB: null,
    compareResult: null,
    compareXmlA: null,
    compareXmlB: null,
    compareActiveTab: 'xml',
    compareDiffsOnly: false,
  };

  // ---- DOM Refs ----

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const screens = {
    home:    $('#screen-home'),
    auth:    $('#screen-auth'),
    result:  $('#screen-result'),
    viewer:  $('#screen-viewer'),
    compare: $('#screen-compare'),
  };

  // ---- Screen Navigation ----

  function showScreen(name, opts) {
    state.previousScreen = state.currentScreen;
    state.currentScreen = name;

    Object.values(screens).forEach(s => s.classList.remove('active'));
    if (screens[name]) {
      screens[name].classList.add('active');
    }
  }

  // ---- Error / Status Toasts ----

  let statusTimer = null;

  function showError(msg) {
    const toast = $('#error-toast');
    $('#error-message').textContent = msg;
    toast.classList.remove('hidden');
  }

  function hideError() {
    $('#error-toast').classList.add('hidden');
  }

  function showStatus(msg) {
    const toast = $('#status-toast');
    $('#status-message').textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(statusTimer);
    statusTimer = setTimeout(() => toast.classList.add('hidden'), 3000);
  }

  // ---- Tauri IPC Helpers ----

  async function invoke(cmd, args) {
    if (!window.__TAURI__) {
      throw new Error('Tauri API not available');
    }
    return window.__TAURI__.core.invoke(cmd, args);
  }

  async function openFileDialog(filters) {
    if (!window.__TAURI__) throw new Error('Tauri API not available');
    const { open } = window.__TAURI__.dialog;
    return open({ filters });
  }

  async function saveFileDialog(defaultPath) {
    if (!window.__TAURI__) throw new Error('Tauri API not available');
    const { save } = window.__TAURI__.dialog;
    return save({ defaultPath });
  }

  async function clipboardWrite(text) {
    if (!window.__TAURI__) throw new Error('Tauri API not available');
    return window.__TAURI__.clipboardManager.writeText(text);
  }

  async function clipboardRead() {
    if (!window.__TAURI__) throw new Error('Tauri API not available');
    return window.__TAURI__.clipboardManager.readText();
  }

  // ---- Home Screen ----

  function initHome() {
    $('#btn-prod').addEventListener('click', () => loadEnvironment('PROD'));
    $('#btn-tst').addEventListener('click', () => loadEnvironment('TST'));
    $('#btn-viewer').addEventListener('click', () => {
      showScreen('viewer');
    });
    $('#btn-compare').addEventListener('click', () => {
      showScreen('compare');
    });
  }

  async function loadEnvironment(env) {
    state.environment = env;
    try {
      const config = await invoke('load_config', { environment: env });
      state.configInfo = config;

      // Set up auth screen
      $('#auth-env-label').textContent = env;
      showScreen('auth');
    } catch (e) {
      showError(String(e));
    }
  }

  // ---- Auth Screen ----

  function initAuth() {
    $('#auth-back').addEventListener('click', () => {
      cleanupAuthProgress();
      showScreen('home');
    });

    // Tab switching
    $$('.tab-bar .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const flow = tab.dataset.tab;
        state.authFlow = flow;

        $$('.tab-bar .tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        if (flow === 'rest') {
          $('#rest-fields').classList.remove('hidden');
        } else {
          $('#rest-fields').classList.add('hidden');
        }
      });
    });

    $('#btn-authenticate').addEventListener('click', startAuthentication);
  }

  async function startAuthentication() {
    const username = $('#auth-username').value.trim();
    if (!username) {
      showError('Username is required');
      return;
    }

    const signed = document.querySelector('input[name="signing"]:checked').value === 'signed';

    // Show progress area
    const progress = $('#auth-progress');
    progress.classList.remove('hidden');
    const stepsEl = $('#auth-steps');
    stepsEl.innerHTML = '';

    addProgressStep('Initializing...');

    // Listen for auth-progress events
    try {
      if (window.__TAURI__) {
        state.unlistenProgress = await window.__TAURI__.event.listen('auth-progress', (event) => {
          const { step, message } = event.payload;
          addProgressStep(message || step);
        });
      }
    } catch (e) {
      // Progress events are optional
    }

    // Disable button during auth
    $('#btn-authenticate').disabled = true;

    try {
      if (state.authFlow === 'rest') {
        const password = $('#auth-password').value;
        const otp = $('#auth-otp').value.trim();

        if (!password) {
          showError('Password is required for REST API flow');
          return;
        }
        if (!otp) {
          showError('OTP code is required for REST API flow');
          return;
        }

        addProgressStep('Starting REST authentication...');

        const result = await invoke('run_rest_flow', {
          username, password, otp, signed
        });

        handleAuthResult(result);
      } else {
        addProgressStep('Opening browser...');

        const result = await invoke('run_browser_flow', {
          username, signed
        });

        handleAuthResult(result);
      }
    } catch (e) {
      addProgressStep('Error: ' + String(e), true);
      showError(String(e));
    } finally {
      $('#btn-authenticate').disabled = false;
      cleanupAuthProgress();
    }
  }

  function addProgressStep(message, isError) {
    const li = document.createElement('li');
    const icon = document.createElement('span');
    icon.className = 'step-icon ' + (isError ? 'error' : 'done');
    icon.textContent = isError ? '!' : '\u2713';
    li.appendChild(icon);
    li.appendChild(document.createTextNode(message));
    $('#auth-steps').appendChild(li);
  }

  function cleanupAuthProgress() {
    if (state.unlistenProgress) {
      state.unlistenProgress();
      state.unlistenProgress = null;
    }
  }

  function handleAuthResult(result) {
    // The auth result should be a DecodedSaml
    state.lastResult = result;
    renderResult(result, 'auth');
    showScreen('result');
  }

  // ---- SAML Viewer Screen ----

  function initViewer() {
    $('#viewer-back').addEventListener('click', () => {
      showScreen('home');
    });

    $('#btn-open-file').addEventListener('click', openSamlFile);
    $('#btn-paste-clipboard').addEventListener('click', pasteFromClipboard);
    $('#btn-load-idp-viewer').addEventListener('click', loadIdpCert);
    $('#btn-load-chain-viewer').addEventListener('click', loadChainCert);
    $('#btn-decode').addEventListener('click', decodeAndValidate);
  }

  async function openSamlFile() {
    try {
      const file = await openFileDialog([
        { name: 'SAML/XML', extensions: ['xml', 'saml', 'txt', 'b64'] },
        { name: 'All Files', extensions: ['*'] },
      ]);

      if (!file) return; // cancelled

      // Read the file contents via Tauri fs plugin or just pass the path
      // For SAML viewer, we read the file and put it in the textarea
      // Use the file path -- Tauri v2 open() returns a string path
      const filePath = typeof file === 'string' ? file : file.path;
      if (!filePath) return;

      try {
        const text = await invoke('read_file', { path: filePath });
        $('#saml-input').value = text;
        showStatus('File loaded');
      } catch (e) {
        showError('Could not read file: ' + String(e));
      }
    } catch (e) {
      showError(String(e));
    }
  }

  function convertFileSrc(path) {
    // Tauri v2 asset protocol
    if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.convertFileSrc) {
      return window.__TAURI__.core.convertFileSrc(path);
    }
    // Fallback for Tauri v2
    return 'asset://localhost/' + encodeURIComponent(path);
  }

  async function pasteFromClipboard() {
    try {
      const text = await clipboardRead();
      if (text) {
        $('#saml-input').value = text;
        showStatus('Pasted from clipboard');
      } else {
        showStatus('Clipboard is empty');
      }
    } catch (e) {
      showError('Failed to read clipboard: ' + String(e));
    }
  }

  async function decodeAndValidate() {
    const input = $('#saml-input').value.trim();
    if (!input) {
      showError('No SAML data to decode. Paste or open a file first.');
      return;
    }

    const spinner = $('#viewer-spinner');
    spinner.classList.remove('hidden');
    $('#btn-decode').disabled = true;

    try {
      const result = await invoke('decode_saml', { input });
      state.lastResult = result;
      renderResult(result, 'viewer');
      showScreen('result');
    } catch (e) {
      showError(String(e));
    } finally {
      spinner.classList.add('hidden');
      $('#btn-decode').disabled = false;
    }
  }

  // ---- Load IDP Cert ----

  async function loadIdpCert() {
    try {
      const file = await openFileDialog([
        { name: 'Certificates', extensions: ['pem', 'crt', 'cer', 'der'] },
        { name: 'All Files', extensions: ['*'] },
      ]);

      if (!file) return;

      const filePath = typeof file === 'string' ? file : file.path;
      if (!filePath) return;

      const certInfo = await invoke('load_idp_cert', { path: filePath });
      state.idpCertInfo = certInfo;
      showStatus('IDP cert loaded: ' + certInfo.cn);

      // If we're on the result screen with existing data, re-validate
      if (state.currentScreen === 'result' && state.lastRawXml) {
        await revalidateCurrentResult();
      }
    } catch (e) {
      showError(String(e));
    }
  }

  async function loadChainCert() {
    try {
      const file = await openFileDialog([
        { name: 'Certificates', extensions: ['pem', 'crt', 'cer'] },
        { name: 'All Files', extensions: ['*'] },
      ]);
      if (!file) return;
      const filePath = typeof file === 'string' ? file : file.path;
      if (!filePath) return;

      const certInfo = await invoke('load_chain_cert', { path: filePath });
      state.idpCertInfo = certInfo;
      showStatus('Chain loaded: ' + certInfo.chain_count + ' chain cert(s)');

      if (state.currentScreen === 'result' && state.lastRawXml) {
        await revalidateCurrentResult();
      }
    } catch (e) {
      showError(String(e));
    }
  }

  async function revalidateCurrentResult() {
    if (!state.lastRawXml) return;

    try {
      const result = await invoke('decode_saml', { input: state.lastRawXml });
      state.lastResult = result;
      renderResult(result, state.previousScreen || 'viewer');
    } catch (e) {
      showError('Re-validation failed: ' + String(e));
    }
  }

  // ---- Result Screen ----

  function initResult() {
    $('#result-back').addEventListener('click', () => {
      const back = state.previousScreen || 'home';
      showScreen(back);
    });

    $('#btn-copy-xml').addEventListener('click', copyXml);
    $('#btn-save-xml').addEventListener('click', saveXml);
    $('#btn-load-idp-result').addEventListener('click', loadIdpCert);
    $('#btn-load-chain-result').addEventListener('click', loadChainCert);
  }

  async function copyXml() {
    const xml = state.lastPrettyXml || state.lastRawXml;
    if (!xml) {
      showStatus('No XML to copy');
      return;
    }

    try {
      await clipboardWrite(xml);
      showStatus('Copied to clipboard');
    } catch (e) {
      showError('Failed to copy: ' + String(e));
    }
  }

  async function saveXml() {
    if (!state.lastRawXml) {
      showStatus('No XML to save');
      return;
    }

    try {
      const path = await saveFileDialog('assertion.xml');
      if (!path) return;

      await invoke('save_raw_xml', { path });
      showStatus('Saved to ' + path);
    } catch (e) {
      showError('Failed to save: ' + String(e));
    }
  }

  // ---- Render Result ----

  function renderResult(result, fromScreen) {
    state.previousScreen = fromScreen;
    const detailsEl = $('#assertion-details');
    const attrsPanel = $('#attributes-panel');
    const attrsList = $('#attributes-list');
    const validationPanel = $('#validation-panel');
    const summaryEl = $('#validation-summary');
    const checksEl = $('#validation-checks');
    const metaEl = $('#validation-meta');
    const xmlCode = $('#xml-code');

    // Clear previous
    detailsEl.innerHTML = '';
    attrsList.innerHTML = '';
    summaryEl.innerHTML = '';
    checksEl.innerHTML = '';
    metaEl.innerHTML = '';
    xmlCode.innerHTML = '';
    attrsPanel.classList.add('hidden');
    validationPanel.classList.add('hidden');

    const type = result.type;

    if (type === 'AuthnRequest') {
      renderAuthnRequest(result, detailsEl, xmlCode);
    } else if (type === 'Response') {
      renderResponse(result, detailsEl, attrsList, attrsPanel, xmlCode);
      if (result.validation) {
        validationPanel.classList.remove('hidden');
        renderValidation(result.validation, summaryEl, checksEl, metaEl);
      }
      state.lastRawXml = result.raw_xml || null;
      state.lastPrettyXml = result.pretty_xml || null;
    } else if (type === 'Assertion') {
      renderAssertion(result, detailsEl, attrsList, attrsPanel, xmlCode);
      if (result.validation) {
        validationPanel.classList.remove('hidden');
        renderValidation(result.validation, summaryEl, checksEl, metaEl);
      }
      state.lastRawXml = result.raw_xml || null;
      state.lastPrettyXml = result.pretty_xml || null;
    }
  }

  function renderAuthnRequest(result, detailsEl, xmlCode) {
    const d = result.details;
    const pairs = [
      ['ID', d.id],
      ['Issuer', d.issuer],
      ['Issue Instant', d.issue_instant],
      ['Destination', d.destination],
      ['ACS URL', d.acs_url],
      ['Binding', d.protocol_binding],
      ['NameID Policy', d.name_id_policy],
      ['Force Authn', d.force_authn],
      ['Is Passive', d.is_passive],
    ];
    renderDetailPairs(detailsEl, pairs);
    xmlCode.innerHTML = highlightXml(result.pretty_xml);
    state.lastRawXml = result.pretty_xml;
    state.lastPrettyXml = result.pretty_xml;
  }

  function renderResponse(result, detailsEl, attrsList, attrsPanel, xmlCode) {
    // Response-level details
    const r = result.response || {};
    const a = result.assertion || {};

    const pairs = [
      ['Type', 'SAML Response'],
      ['Response ID', r.id],
      ['Status', r.status],
      ['Issuer', a.issuer || r.issuer],
      ['Subject', a.subject],
      ['Audience', a.audience],
      ['Assertion ID', a.assertion_id],
      ['Issue Instant', a.issue_instant || r.issue_instant],
      ['Not Before', a.not_before],
      ['Not After', a.not_after],
      ['Destination', r.destination],
      ['InResponseTo', r.in_response_to],
    ];
    renderDetailPairs(detailsEl, pairs);

    if (result.attributes && result.attributes.length > 0) {
      attrsPanel.classList.remove('hidden');
      renderAttributes(attrsList, result.attributes);
    }

    xmlCode.innerHTML = highlightXml(result.pretty_xml);
  }

  function renderAssertion(result, detailsEl, attrsList, attrsPanel, xmlCode) {
    const d = result.details;
    const pairs = [
      ['Type', 'SAML Assertion'],
      ['Issuer', d.issuer],
      ['Subject', d.subject],
      ['Audience', d.audience],
      ['Assertion ID', d.assertion_id],
      ['Issue Instant', d.issue_instant],
      ['Not Before', d.not_before],
      ['Not After', d.not_after],
      ['Auth Context', d.authn_context],
      ['Has Signature', d.has_signature],
    ];
    renderDetailPairs(detailsEl, pairs);

    if (result.attributes && result.attributes.length > 0) {
      attrsPanel.classList.remove('hidden');
      renderAttributes(attrsList, result.attributes);
    }

    xmlCode.innerHTML = highlightXml(result.pretty_xml);
  }

  function renderDetailPairs(container, pairs) {
    pairs.forEach(([label, value]) => {
      if (value === null || value === undefined || value === '') return;

      const dt = document.createElement('dt');
      dt.textContent = label;
      container.appendChild(dt);

      const dd = document.createElement('dd');
      dd.textContent = String(value);
      container.appendChild(dd);
    });
  }

  function renderAttributes(container, attributes) {
    attributes.forEach(attr => {
      const dt = document.createElement('dt');
      dt.textContent = attr.name;
      container.appendChild(dt);

      const dd = document.createElement('dd');
      dd.textContent = attr.values.join(', ');
      container.appendChild(dd);
    });
  }

  // ---- Validation Rendering ----

  function renderValidation(report, summaryEl, checksEl, metaEl) {
    // Summary
    const summaryKey = (report.summary || '').toLowerCase();
    const summaryMessages = {
      trusted:  'Trusted -- Signature verified against configured IDP certificate',
      valid:    'Valid -- Signature cryptographically valid (no IDP cert configured)',
      partial:  'Partial -- Validation incomplete, see details',
      failed:   'Failed -- Signature verification FAILED',
      unsigned: 'Unsigned -- No signature present in assertion',
    };

    summaryEl.className = 'validation-summary ' + summaryKey;
    summaryEl.textContent = summaryMessages[summaryKey] || report.summary;

    // Checks
    (report.checks || []).forEach(check => {
      const li = document.createElement('li');

      const icon = document.createElement('span');
      icon.className = 'check-icon ' + (check.passed ? 'pass' : 'fail');
      icon.textContent = check.passed ? '\u2713' : '\u2717';
      li.appendChild(icon);

      const body = document.createElement('span');
      body.className = 'check-body';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'check-name';
      nameSpan.textContent = check.name;
      body.appendChild(nameSpan);

      const detailSpan = document.createElement('span');
      detailSpan.className = 'check-detail';
      detailSpan.textContent = ' \u2014 ' + check.detail;
      body.appendChild(detailSpan);

      if (check.diagnostic) {
        const diag = document.createElement('span');
        diag.className = 'check-diagnostic';
        diag.textContent = check.diagnostic;
        body.appendChild(diag);
      }

      li.appendChild(body);
      checksEl.appendChild(li);
    });

    // Metadata
    const metaItems = [];
    if (report.algorithm) {
      metaItems.push('Algorithm: ' + report.algorithm);
    }
    if (report.cert_subject) {
      metaItems.push('Signer: ' + report.cert_subject);
    }
    if (report.cert_not_after) {
      metaItems.push('Expires: ' + report.cert_not_after);
    }
    metaItems.push('IDP Cert: ' + (report.idp_cert_loaded ? 'Loaded' : 'Not loaded'));

    metaEl.innerHTML = metaItems.map(m => '<span>' + escapeHtml(m) + '</span>').join('');
  }

  // ---- XML Syntax Highlighting ----

  function highlightXml(xml) {
    if (!xml) return '';

    // Escape HTML entities
    let escaped = escapeHtml(xml);

    // Highlight XML syntax using regex replacements
    // Order matters: we process from most specific to least specific

    // Processing instructions: <?...?>
    escaped = escaped.replace(
      /(&lt;\?)([\s\S]*?)(\?&gt;)/g,
      '<span class="xml-bracket">$1</span><span class="xml-tag">$2</span><span class="xml-bracket">$3</span>'
    );

    // Closing tags: </tagname>
    escaped = escaped.replace(
      /(&lt;\/)([\w:.-]+)(&gt;)/g,
      '<span class="xml-bracket">$1</span><span class="xml-tag">$2</span><span class="xml-bracket">$3</span>'
    );

    // Self-closing tags and opening tags with attributes
    // We need to handle attributes inside tags
    escaped = escaped.replace(
      /(&lt;)([\w:.-]+)((?:\s+[\s\S]*?)?)(\/?&gt;)/g,
      function (match, open, tagName, attrs, close) {
        let result = '<span class="xml-bracket">' + open + '</span>';
        result += '<span class="xml-tag">' + tagName + '</span>';

        if (attrs) {
          // Highlight attributes within this section
          attrs = attrs.replace(
            /([\w:.-]+)(=)(&quot;)(.*?)(&quot;)/g,
            '<span class="xml-attr">$1</span>$2<span class="xml-value">$3$4$5</span>'
          );
          // Also handle single-quoted values (rare in XML but possible)
          attrs = attrs.replace(
            /([\w:.-]+)(=)(&#39;)(.*?)(&#39;)/g,
            '<span class="xml-attr">$1</span>$2<span class="xml-value">$3$4$5</span>'
          );
          result += attrs;
        }

        result += '<span class="xml-bracket">' + close + '</span>';
        return result;
      }
    );

    return escaped;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ---- Compare Screen ----

  function initCompare() {
    // Back button: if results visible → go back to input; else → home
    $('#compare-back').addEventListener('click', () => {
      const resultsPhase = $('#compare-results-phase');
      if (!resultsPhase.classList.contains('hidden')) {
        resultsPhase.classList.add('hidden');
        $('#compare-input-phase').classList.remove('hidden');
      } else {
        showScreen('home');
      }
    });

    // File / clipboard load for each side
    $('#btn-open-file-a').addEventListener('click', () => loadCompareFile('a'));
    $('#btn-open-file-b').addEventListener('click', () => loadCompareFile('b'));
    $('#btn-paste-a').addEventListener('click', () => pasteCompare('a'));
    $('#btn-paste-b').addEventListener('click', () => pasteCompare('b'));

    // Run comparison
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

    // Diffs-only toggle
    $('#btn-diffs-only').addEventListener('click', () => {
      state.compareDiffsOnly = !state.compareDiffsOnly;
      $('#btn-diffs-only').classList.toggle('active', state.compareDiffsOnly);
      renderCompareTab();
    });

    // Load IDP / Chain cert for compare screen
    $('#btn-load-idp-compare').addEventListener('click', async () => {
      await loadIdpCert();
      if (state.compareResult) {
        await revalidateComparison();
      }
    });

    $('#btn-load-chain-compare').addEventListener('click', async () => {
      await loadChainCert();
      if (state.compareResult) {
        await revalidateComparison();
      }
    });
  }

  async function loadCompareFile(side) {
    try {
      const file = await openFileDialog([
        { name: 'SAML/XML', extensions: ['xml', 'saml', 'txt', 'b64'] },
        { name: 'All Files', extensions: ['*'] },
      ]);
      if (!file) return;
      const filePath = typeof file === 'string' ? file : file.path;
      if (!filePath) return;

      try {
        const text = await invoke('read_file', { path: filePath });
        $('#compare-input-' + side).value = text;
        setCompareStatus(side, 'File loaded', 'success');
      } catch (e) {
        showError('Could not read file: ' + String(e));
      }
    } catch (e) {
      showError(String(e));
    }
  }

  async function pasteCompare(side) {
    try {
      const text = await clipboardRead();
      if (text) {
        $('#compare-input-' + side).value = text;
        setCompareStatus(side, 'Pasted from clipboard', 'success');
      } else {
        setCompareStatus(side, 'Clipboard is empty', 'error');
      }
    } catch (e) {
      showError('Failed to read clipboard: ' + String(e));
    }
  }

  function setCompareStatus(side, msg, type) {
    const el = $('#compare-status-' + side);
    el.textContent = msg;
    el.className = 'compare-status' + (type ? ' ' + type : '');
  }

  async function runComparison() {
    const inputA = $('#compare-input-a').value.trim();
    const inputB = $('#compare-input-b').value.trim();

    if (!inputA) {
      showError('Assertion A is required');
      return;
    }
    if (!inputB) {
      showError('Assertion B is required');
      return;
    }

    const spinner = $('#compare-spinner');
    spinner.classList.remove('hidden');
    $('#btn-compare-go').disabled = true;

    try {
      const result = await invoke('compare_saml', { inputA, inputB });
      state.compareResult = result;
      state.compareInputA = inputA;
      state.compareInputB = inputB;

      // Switch to results phase
      $('#compare-input-phase').classList.add('hidden');
      $('#compare-results-phase').classList.remove('hidden');

      // Reset to XML tab
      state.compareActiveTab = 'xml';
      state.compareDiffsOnly = false;
      $('#btn-diffs-only').classList.remove('active');
      $$('.compare-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.ctab === 'xml');
      });

      renderCompareTab();
    } catch (e) {
      showError(String(e));
    } finally {
      spinner.classList.add('hidden');
      $('#btn-compare-go').disabled = false;
    }
  }

  async function revalidateComparison() {
    if (!state.compareInputA || !state.compareInputB) return;

    try {
      const result = await invoke('compare_saml', {
        inputA: state.compareInputA,
        inputB: state.compareInputB,
      });
      state.compareResult = result;
      renderCompareTab();
    } catch (e) {
      showError('Re-validation failed: ' + String(e));
    }
  }

  // ---- Compare Rendering ----

  function renderCompareTab() {
    const result = state.compareResult;
    if (!result) return;

    const content = $('#compare-content');

    // Update diff count display
    const xmlCount = result.xml_diff.diff_count;
    const hexDiffRows = result.hex_diff.filter(r => r.diffs.length > 0).length;
    const c14nCount = result.c14n_diff.diff_count;
    $('#compare-diff-count').textContent =
      xmlCount + ' XML diff' + (xmlCount !== 1 ? 's' : '') +
      ', ' + hexDiffRows + ' hex row' + (hexDiffRows !== 1 ? 's' : '');

    switch (state.compareActiveTab) {
      case 'xml':
        content.innerHTML = renderLineDiff(result.xml_diff, 'Assertion A', 'Assertion B');
        break;
      case 'hex':
        content.innerHTML = renderHexDiff(result.hex_diff);
        break;
      case 'c14n':
        content.innerHTML = renderLineDiff(result.c14n_diff, 'C14N A', 'C14N B');
        break;
      case 'validation':
        content.innerHTML = renderValidationDiff(result.validation_a, result.validation_b);
        break;
      case 'all':
        content.innerHTML = renderAllTab(result);
        // Wire up collapsible section headers after inserting HTML
        content.querySelectorAll('.compare-section-header').forEach(header => {
          header.addEventListener('click', () => {
            header.classList.toggle('collapsed');
            const body = header.nextElementSibling;
            if (body) body.classList.toggle('collapsed');
          });
        });
        break;
      default:
        content.innerHTML = '';
    }

    syncDiffScroll(content);
  }

  function renderLineDiff(diff, titleA, titleB) {
    const lines = diff.lines;

    // Build filtered line list: [{ lineIdx, lineObj, side }] for each pane
    // We need left pane (A) and right pane (B) to be aligned.
    // Strategy: process each DiffLine into one row per pane.
    // Same → show on both sides
    // Removed → show on left, blank on right
    // Added → blank on left, show on right
    // Changed → show left on left pane, right on right pane

    let filteredLines = lines;
    if (state.compareDiffsOnly) {
      // Keep diff lines + 2 lines of context
      const include = new Array(lines.length).fill(false);
      lines.forEach((line, i) => {
        if (line.type !== 'Same') {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          for (let k = start; k < end; k++) include[k] = true;
        }
      });
      filteredLines = lines.filter((_, i) => include[i]);
    }

    if (filteredLines.length === 0 || (state.compareDiffsOnly && diff.diff_count === 0)) {
      return '<div class="compare-no-diffs">No differences found</div>';
    }

    let leftRows = '';
    let rightRows = '';
    let leftLineNum = 0;
    let rightLineNum = 0;

    filteredLines.forEach(line => {
      const type = line.type;
      if (type === 'Same') {
        leftLineNum++;
        rightLineNum++;
        const escaped = escapeHtml(line.text);
        leftRows  += diffLineHtml(leftLineNum,  escaped, 'same');
        rightRows += diffLineHtml(rightLineNum, escaped, 'same');
      } else if (type === 'Removed') {
        leftLineNum++;
        const escaped = escapeHtml(line.text);
        leftRows  += diffLineHtml(leftLineNum, escaped, 'removed');
        rightRows += diffLineHtml(null, '', 'blank');
      } else if (type === 'Added') {
        rightLineNum++;
        const escaped = escapeHtml(line.text);
        leftRows  += diffLineHtml(null, '', 'blank');
        rightRows += diffLineHtml(rightLineNum, escaped, 'added');
      } else if (type === 'Changed') {
        leftLineNum++;
        rightLineNum++;
        const leftHtml  = highlightSpans(line.left,  line.left_spans,  'red');
        const rightHtml = highlightSpans(line.right, line.right_spans, 'green');
        leftRows  += diffLineHtml(leftLineNum,  leftHtml,  'removed');
        rightRows += diffLineHtml(rightLineNum, rightHtml, 'added');
      }
    });

    return (
      '<div class="diff-split">' +
        '<div class="diff-pane">' +
          '<div class="diff-pane-title">' + escapeHtml(titleA) + '</div>' +
          leftRows +
        '</div>' +
        '<div class="diff-pane">' +
          '<div class="diff-pane-title">' + escapeHtml(titleB) + '</div>' +
          rightRows +
        '</div>' +
      '</div>'
    );
  }

  function diffLineHtml(lineNum, contentHtml, cssClass) {
    const numStr = lineNum !== null
      ? '<span class="diff-line-num">' + lineNum + '</span>'
      : '<span class="diff-line-num"></span>';
    return '<div class="diff-line ' + cssClass + '">' + numStr + contentHtml + '</div>';
  }

  function highlightSpans(text, spans, color) {
    if (!spans || spans.length === 0) return escapeHtml(text);

    const chars = [...text]; // Unicode-safe spread
    let html = '';
    let pos = 0;

    spans.forEach(([start, end]) => {
      // Before span: plain text
      if (pos < start) {
        html += escapeHtml(chars.slice(pos, start).join(''));
      }
      // Span: highlighted
      html += '<span class="diff-highlight-' + color + '">' +
        escapeHtml(chars.slice(start, end).join('')) +
        '</span>';
      pos = end;
    });

    // Remainder
    if (pos < chars.length) {
      html += escapeHtml(chars.slice(pos).join(''));
    }

    return html;
  }

  function renderHexDiff(rows) {
    let filteredRows = rows;
    if (state.compareDiffsOnly) {
      filteredRows = rows.filter(r => r.diffs.length > 0);
    }

    if (filteredRows.length === 0) {
      return '<div class="compare-no-diffs">No differences found</div>';
    }

    let leftRows = '';
    let rightRows = '';

    filteredRows.forEach(row => {
      const offsetHex = row.offset.toString(16).padStart(8, '0');
      const offsetHtml = '<span class="hex-offset">' + offsetHex + '</span>  ';

      leftRows  += '<div class="diff-line">' + offsetHtml + hexBytesHtml(row.left_bytes,  row.diffs) + '  ' + hexAsciiHtml(row.left_bytes,  row.diffs) + '</div>';
      rightRows += '<div class="diff-line">' + offsetHtml + hexBytesHtml(row.right_bytes, row.diffs) + '  ' + hexAsciiHtml(row.right_bytes, row.diffs) + '</div>';
    });

    return (
      '<div class="diff-split">' +
        '<div class="diff-pane">' +
          '<div class="diff-pane-title">Bytes A</div>' +
          leftRows +
        '</div>' +
        '<div class="diff-pane">' +
          '<div class="diff-pane-title">Bytes B</div>' +
          rightRows +
        '</div>' +
      '</div>'
    );
  }

  function hexBytesHtml(bytes, diffIndices) {
    const diffSet = new Set(diffIndices);
    let html = '';
    for (let i = 0; i < 16; i++) {
      if (i === 8) html += ' '; // gap after first 8 bytes
      if (i < bytes.length) {
        const hex = bytes[i].toString(16).padStart(2, '0');
        if (diffSet.has(i)) {
          html += '<span class="hex-diff">' + hex + '</span> ';
        } else {
          html += '<span class="hex-byte">' + hex + '</span> ';
        }
      } else {
        html += '   '; // 3 chars placeholder (2 hex + 1 space)
      }
    }
    return html;
  }

  function hexAsciiHtml(bytes, diffIndices) {
    const diffSet = new Set(diffIndices);
    let html = '<span class="hex-ascii">|';
    for (let i = 0; i < 16; i++) {
      if (i < bytes.length) {
        const b = bytes[i];
        const ch = (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
        if (diffSet.has(i)) {
          html += '<span class="hex-diff">' + escapeHtml(ch) + '</span>';
        } else {
          html += escapeHtml(ch);
        }
      } else {
        html += ' ';
      }
    }
    html += '|</span>';
    return html;
  }

  function renderValidationDiff(valA, valB) {
    const checksA = valA.checks || [];
    const checksB = valB.checks || [];

    // Align checks by name
    const allNames = [];
    const seenNames = new Set();
    checksA.forEach(c => { if (!seenNames.has(c.name)) { seenNames.add(c.name); allNames.push(c.name); } });
    checksB.forEach(c => { if (!seenNames.has(c.name)) { seenNames.add(c.name); allNames.push(c.name); } });

    const mapA = Object.fromEntries(checksA.map(c => [c.name, c]));
    const mapB = Object.fromEntries(checksB.map(c => [c.name, c]));

    let rows = '';
    allNames.forEach(name => {
      const cA = mapA[name] || null;
      const cB = mapB[name] || null;
      const { text: textA, cls: clsA } = checkDisplay(cA);
      const { text: textB, cls: clsB } = checkDisplay(cB);
      const differs = cA && cB && cA.passed !== cB.passed;
      const rowClass = differs ? ' class="diff-row"' : '';
      rows += '<tr' + rowClass + '>' +
        '<td>' + escapeHtml(name) + '</td>' +
        '<td class="' + clsA + '">' + escapeHtml(textA) + '</td>' +
        '<td class="' + clsB + '">' + escapeHtml(textB) + '</td>' +
        '</tr>';
    });

    // Summary rows
    const sumA = (valA.summary || '').toLowerCase();
    const sumB = (valB.summary || '').toLowerCase();
    const sumDiffers = sumA !== sumB;
    const sumRowClass = sumDiffers ? ' class="diff-row"' : '';

    const html =
      '<table class="val-compare-table">' +
        '<thead><tr>' +
          '<th>Check</th>' +
          '<th>Assertion A</th>' +
          '<th>Assertion B</th>' +
        '</tr></thead>' +
        '<tbody>' +
        '<tr' + sumRowClass + '>' +
          '<td><strong>Summary</strong></td>' +
          '<td class="' + summaryClass(sumA) + '">' + escapeHtml(valA.summary || '') + '</td>' +
          '<td class="' + summaryClass(sumB) + '">' + escapeHtml(valB.summary || '') + '</td>' +
        '</tr>' +
        rows +
        '</tbody>' +
      '</table>' +
      '<div class="val-footer">' +
        '<span>A: ' + escapeHtml(valA.algorithm || '—') + ' | ' + escapeHtml(valA.cert_subject || 'no cert') + '</span>' +
        '&nbsp;&nbsp;' +
        '<span>B: ' + escapeHtml(valB.algorithm || '—') + ' | ' + escapeHtml(valB.cert_subject || 'no cert') + '</span>' +
      '</div>';

    return html;
  }

  function checkDisplay(check) {
    if (!check) return { text: '—', cls: 'skip' };
    return {
      text: (check.passed ? '\u2713 ' : '\u2717 ') + check.detail,
      cls: check.passed ? 'pass' : 'fail',
    };
  }

  function summaryClass(summary) {
    if (summary === 'trusted' || summary === 'valid') return 'pass';
    if (summary === 'failed') return 'fail';
    return 'skip';
  }

  function renderAllTab(result) {
    const xmlCount   = result.xml_diff.diff_count;
    const hexDiffRows = result.hex_diff.filter(r => r.diffs.length > 0).length;
    const c14nCount  = result.c14n_diff.diff_count;
    const sumA = (result.validation_a.summary || '').toLowerCase();
    const sumB = (result.validation_b.summary || '').toLowerCase();

    const summaryCards =
      '<div class="compare-summary-row">' +
        '<div class="compare-summary-card">' +
          '<div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px">XML Diffs</div>' +
          '<div style="font-size:1.25rem;font-weight:700;color:' + (xmlCount > 0 ? 'var(--red)' : 'var(--green)') + '">' + xmlCount + '</div>' +
        '</div>' +
        '<div class="compare-summary-card">' +
          '<div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px">Hex Rows Differ</div>' +
          '<div style="font-size:1.25rem;font-weight:700;color:' + (hexDiffRows > 0 ? 'var(--yellow)' : 'var(--green)') + '">' + hexDiffRows + '</div>' +
        '</div>' +
        '<div class="compare-summary-card">' +
          '<div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px">C14N Diffs</div>' +
          '<div style="font-size:1.25rem;font-weight:700;color:' + (c14nCount > 0 ? 'var(--red)' : 'var(--green)') + '">' + c14nCount + '</div>' +
        '</div>' +
        '<div class="compare-summary-card">' +
          '<div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px">Validation A</div>' +
          '<div style="font-size:1rem;font-weight:600;color:' + summaryColor(sumA) + '">' + escapeHtml(result.validation_a.summary || '—') + '</div>' +
        '</div>' +
        '<div class="compare-summary-card">' +
          '<div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px">Validation B</div>' +
          '<div style="font-size:1rem;font-weight:600;color:' + summaryColor(sumB) + '">' + escapeHtml(result.validation_b.summary || '—') + '</div>' +
        '</div>' +
      '</div>';

    const sections =
      sectionBlock('Validation', renderValidationDiff(result.validation_a, result.validation_b)) +
      sectionBlock('XML Diff', renderLineDiff(result.xml_diff, 'Assertion A', 'Assertion B')) +
      sectionBlock('Hex / Bytes', renderHexDiff(result.hex_diff)) +
      sectionBlock('Canonicalized', renderLineDiff(result.c14n_diff, 'C14N A', 'C14N B'));

    return summaryCards + sections;
  }

  function summaryColor(summary) {
    if (summary === 'trusted' || summary === 'valid') return 'var(--green)';
    if (summary === 'failed') return 'var(--red)';
    return 'var(--text-secondary)';
  }

  function sectionBlock(title, contentHtml) {
    return (
      '<div style="margin-bottom:16px">' +
        '<div class="compare-section-header">' +
          '<span class="arrow">\u25bc</span>' +
          '<span>' + escapeHtml(title) + '</span>' +
        '</div>' +
        '<div class="compare-section-body">' +
          contentHtml +
        '</div>' +
      '</div>'
    );
  }

  function syncDiffScroll(container) {
    const panes = Array.from((container || document).querySelectorAll('.diff-split .diff-pane'));
    // Process each diff-split independently
    const splits = Array.from((container || document).querySelectorAll('.diff-split'));
    splits.forEach(split => {
      const splitPanes = Array.from(split.querySelectorAll('.diff-pane'));
      if (splitPanes.length < 2) return;
      splitPanes.forEach((pane, idx) => {
        // Remove old listeners by cloning, then re-attach
        pane.onscroll = null;
      });

      let syncing = false;
      splitPanes.forEach((pane, idx) => {
        pane.addEventListener('scroll', () => {
          if (syncing) return;
          syncing = true;
          splitPanes.forEach((other, otherIdx) => {
            if (otherIdx !== idx) {
              other.scrollTop  = pane.scrollTop;
              other.scrollLeft = pane.scrollLeft;
            }
          });
          syncing = false;
        });
      });
    });

    // Suppress unused variable warning
    void panes;
  }

  // ---- Initialization ----

  function init() {
    initHome();
    initAuth();
    initViewer();
    initResult();
    initCompare();

    // Error toast dismiss
    $('#error-dismiss').addEventListener('click', hideError);

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        hideError();
      }
      // Enter key triggers Authenticate on the auth screen
      if (e.key === 'Enter' && state.currentScreen === 'auth') {
        const btn = $('#btn-authenticate');
        if (btn && !btn.disabled) {
          e.preventDefault();
          btn.click();
        }
      }
    });

    showScreen('home');
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
