# View SAML Assertion Feature

## Overview

Add a standalone "View SAML Assertion" option to seahorse's main menu that decodes, pretty-prints, and displays critical details from pasted or file-loaded SAML AuthnRequests and Responses.

## Menu Integration

- Third option on the EnvSelect screen: `PROD`, `TST`, `View SAML Assertion`
- Standalone flow — no environment, config, or authentication required
- `env_selection` upper bound changes from `< 1` to `< 2` in `handle_env_select`
- Enter handler branches: selection 0/1 → FlowSelect (existing), selection 2 → SamlInput (new)

## New Screens

### SamlInput

Two input modes, toggled with Tab:

- **Paste mode**: multi-line text area. User pastes SAML data (XML, base64, URL-encoded, full URL). F5 submits. Enter inserts newline. Enable crossterm bracketed paste mode (`EnableBracketedPaste`) so large pastes arrive as a single `Event::Paste(String)` rather than thousands of char events.
- **File mode**: single-line path input. Enter submits. `~` is expanded to home directory. Relative paths resolve against cwd.
- **Esc** returns to EnvSelect (main menu).
- Input size limit: 1MB. Show error if exceeded.

### SamlView

Reuses the Result screen layout pattern:

1. **Message Type** — auto-detected: "SAML AuthnRequest", "SAML Response", or "SAML Assertion"
2. **Details panel** — key fields based on detected type:
   - *AuthnRequest*: ID, IssueInstant, Issuer, Destination, AssertionConsumerServiceURL, ProtocolBinding, NameIDPolicy, ForceAuthn (omit if absent), IsPassive (omit if absent)
   - *Response*: ID, IssueInstant, Issuer, Destination, InResponseTo, Status
   - *Assertion (within Response or standalone)*: Issuer, Subject (NameID), Audience, NotBefore/NotAfter, AuthnInstant, SessionIndex, AuthnContextClassRef
3. **Attributes panel** (if AttributeStatement present) — list of Name = Value(s). Multi-valued attributes shown comma-separated.
4. **Signature Info** (if Signature element present) — algorithm, certificate subject, expiry
5. **Formatted XML** — pretty-printed with indentation, scrollable
6. **Help bar** — `c`/Ctrl+C: copy XML, Up/Down: scroll, `r`: new input, Esc: back to main menu, q: quit

## Data Model

New structs to keep AuthnRequest and Response/Assertion details separate:

```rust
enum SamlDocumentType {
    AuthnRequest,
    Response,
    Assertion, // standalone, not wrapped in Response
}

struct AuthnRequestDetails {
    id, issue_instant, issuer, destination,
    acs_url, protocol_binding, name_id_policy,
    force_authn, is_passive
}

struct ResponseDetails {
    id, issue_instant, issuer, destination,
    in_response_to, status
}

struct SamlAttribute {
    name: String,
    values: Vec<String>,
}

// Existing AssertionDetails extended with:
//   session_index, authn_instant fields

struct DecodedSaml {
    document_type: SamlDocumentType,
    authn_request: Option<AuthnRequestDetails>,
    response: Option<ResponseDetails>,
    assertion: Option<AssertionDetails>,
    attributes: Vec<SamlAttribute>,
    signature_validation: Option<SignatureValidation>,
    pretty_xml: String,
}
```

## Auto-Detect & Decode Pipeline

Applied in order, with fallback at each step:

1. **URL extraction**: if input contains `SAMLRequest=` or `SAMLResponse=`, extract the parameter value (split on `&` to handle query strings)
2. **URL-decode**: decode percent-encoded characters
3. **Base64-decode**: attempt decode; if it fails (e.g. input is raw XML), skip to step 5 with the original input as text
4. **Inflate**: try raw deflate decompression (RFC 1951); if it fails, use the base64-decoded bytes as-is
5. **UTF-8 conversion**: convert bytes to string
6. **XML validation**: check for valid XML; skip past `<?xml?>` declarations to find root element. If not valid XML, show error.
7. **Type detection**: inspect root element local name — `AuthnRequest` → AuthnRequest, `Response` → Response, `Assertion` → standalone Assertion

### Edge Cases

- **Encrypted assertions**: if `<EncryptedAssertion>` is found, show Response-level details with a note "Assertion is encrypted — details unavailable"
- **Multiple assertions**: parse the first assertion; display "N assertions found" in details header
- **Standalone Assertion**: display Assertion details panel without Response-level fields

## New Code

- `src/saml/decoder.rs` — decode pipeline (URL extract, URL-decode, base64, deflate, type detection)
- `src/saml/parser.rs` — extend with `extract_authn_request_details()`, `extract_response_details()`, `extract_attributes()`; add `session_index` and `authn_instant` to `AssertionDetails`
- `src/tui/app.rs` — new screen variants (`SamlInput`, `SamlView`), new state fields for input buffer, input mode, decoded result
- `src/tui/input.rs` — input handlers for new screens; enable/disable bracketed paste on screen transitions
- `src/tui/ui.rs` — renderers for new screens

## Dependencies

- `flate2` crate for deflate decompression (add as explicit dependency)
