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
  };

  // ---- DOM Refs ----

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const screens = {
    home:   $('#screen-home'),
    auth:   $('#screen-auth'),
    result: $('#screen-result'),
    viewer: $('#screen-viewer'),
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

        // REST flow - call authenticate command (future implementation)
        const result = await invoke('rest_authenticate', {
          username, password, otp, signed
        });

        handleAuthResult(result);
      } else {
        addProgressStep('Opening browser...');

        // Browser flow (future implementation)
        const result = await invoke('browser_authenticate', {
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

      // Read file via a shell command or use fs plugin
      // Since we have the decode_saml command that takes raw input,
      // we can read the file and pass it through
      try {
        // Try using the fetch API with a Tauri asset protocol
        // Actually, for simplicity, just invoke decode with the file path
        // The backend decode_saml can handle file content
        const response = await fetch(convertFileSrc(filePath));
        const text = await response.text();
        $('#saml-input').value = text;
        showStatus('File loaded');
      } catch (e) {
        // Fallback: try to decode directly -- the input might be a path
        // Read via invoke if available
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

  // ---- Initialization ----

  function init() {
    initHome();
    initAuth();
    initViewer();
    initResult();

    // Error toast dismiss
    $('#error-dismiss').addEventListener('click', hideError);

    // Keyboard shortcut: Escape to dismiss error
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        hideError();
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
