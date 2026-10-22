# DAST accepted risks

Findings that ZAP reports on this API and that were reviewed and accepted. Anything rated
Medium or High always fails the pipeline, whatever is listed here.

## 40014-2 · Cross Site Scripting Weakness (Persistent in JSON Response) · Low

**Finding.** Text stored in an incident (`title`, `description`) is returned unchanged in the JSON
response of `GET /api/v1/incidents`.

**Why it is accepted.** This is a JSON API: it returns data, not HTML. Encoding belongs to the
layer that renders the data (OWASP: contextual output encoding at the sink), and HTML-escaping in
the API would corrupt the stored incident text for every non-browser consumer such as a SIEM.

**Compensating controls.** Responses are `application/json` with `X-Content-Type-Options: nosniff`
(browsers will not sniff them as HTML) and `Content-Security-Policy: default-src 'none'` (nothing
can execute even if a response is opened directly). Covered by
`test_stored_xss_payload_is_returned_as_inert_json`.

**Owner / review.** Re-assess if a web front end that renders incidents is added; it must encode
on output.
