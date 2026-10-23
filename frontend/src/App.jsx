import { useState } from "react";
import "./App.css";

const examples = [
  {
    label: "Suspicious-looking",
    url: "http://secure-account-verify.example.com/login",
  },
  { label: "IP address", url: "http://192.0.2.1/login" },
  { label: "Ordinary", url: "https://example.com/about" },
];

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyze(value = url) {
    setUrl(value);
    setError("");
    setResult(null);

    const submittedUrl = value.trim();

    if (!submittedUrl) {
      setError("Please enter a URL first.");
      return;
    }

    setLoading(true);

    try {
      const apiUrl = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

      const response = await fetch(`${apiUrl}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: submittedUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Unable to analyze this URL.",
        );
      }

      setResult({
        score: data.risk.score,
        level:
          data.risk.level === "high"
            ? "High"
            : data.risk.level === "medium"
              ? "Moderate"
              : "Low",
        host: data.analysis.hostname,
        https: data.analysis.https,
        path: data.analysis.path,
        length: data.analysis.url_length,
        indicators: data.analysis.indicators,
        reasons: data.risk.reasons,
      });
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot connect to LinkGuard API. Make sure the backend is running."
          : err.message,
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="site-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="LinkGuard home">
          <span className="brand-mark">
            <span />
          </span>
          <span>LinkGuard</span>
        </a>
        <a className="nav-link" href="#analysis">
          Check a link <span>↗</span>
        </a>
      </header>

      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">
              URL ANALYSIS <span>·</span> STRUCTURAL HEURISTICS
            </p>
            <h1>
              Think before
              <br />
              you click.
            </h1>
            <p className="intro">
              Paste a link from an email, text or chat. LinkGuard reads its
              structure and points out unusual details before you open it.
            </p>
            <p className="privacy-note">
              <span className="status-dot" />
              This demo analyses the URL as text and never opens the page.
            </p>
          </div>

          <form
            className="url-form"
            onSubmit={(event) => {
              event.preventDefault();
              analyze();
            }}
          >
            <label htmlFor="url-input">LINK TO ANALYZE</label>
            <div className="input-row">
              <span className="input-symbol">↗</span>
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/account/verify"
                autoComplete="url"
                spellCheck="false"
              />
              <button type="submit" disabled={loading}>
                {loading ? "Checking…" : "Analyze URL"}
                {!loading && <span>→</span>}
              </button>
            </div>
            <div className="example-row">
              <span>Try an example:</span>
              {examples.map((item) => (
                <button
                  className="example-button"
                  type="button"
                  key={item.label}
                  onClick={() => analyze(item.url)}
                >
                  {item.label}
                </button>
              ))}
            </div>
            {error && (
              <p className="error-message" role="alert">
                {error}
              </p>
            )}
          </form>
        </section>

        <section className="analysis-section" id="analysis">
          <div className="section-heading">
            <p className="eyebrow">ANALYSIS</p>
            <span className="section-index">
              {result ? "REPORT / 01" : "AWAITING INPUT"}
            </span>
          </div>

          {!result ? (
            <div className="empty-state">
              <div className="empty-icon">↳</div>
              <div>
                <h2>
                  {loading ? "Examining the URL…" : "Nothing analysed yet."}
                </h2>
                <p>
                  {loading
                    ? "Checking the URL structure and possible indicators."
                    : "Enter a link above. Your report will show a score, the indicators found, and the reasons behind it."}
                </p>
              </div>
              <span className="empty-count">— — —</span>
            </div>
          ) : (
            <div className="report">
              <div className="score-panel">
                <p className="eyebrow">STRUCTURAL RISK SCORE</p>
                <div className="score-line">
                  <span className="score-number">{result.score}</span>
                  <span className="score-max">/ 100</span>
                </div>
                <span className={`risk-label ${result.level.toLowerCase()}`}>
                  {result.level} risk
                </span>
                <div className="score-track">
                  <span style={{ width: `${result.score}%` }} />
                </div>
                <div className="score-scale">
                  <span>Low</span>
                  <span>Moderate</span>
                  <span>High</span>
                </div>
              </div>

              <div className="details-panel">
                <p className="eyebrow">URL DETAILS</p>
                <dl className="details-list">
                  <div>
                    <dt>Hostname</dt>
                    <dd>{result.host}</dd>
                  </div>
                  <div>
                    <dt>HTTPS</dt>
                    <dd>{result.https ? "Enabled" : "Not enabled"}</dd>
                  </div>
                  <div>
                    <dt>Path</dt>
                    <dd>{result.path}</dd>
                  </div>
                  <div>
                    <dt>Length</dt>
                    <dd>{result.length} characters</dd>
                  </div>
                </dl>
              </div>

              <div className="indicators-panel">
                <p className="eyebrow">WHY THIS SCORE</p>

                {result.reasons?.length > 0 ? (
                  <ul className="indicator-list">
                    {result.reasons.map((reason) => (
                      <li key={reason}>
                        <span>!</span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                ) : result.indicators.length > 0 ? (
                  <ul className="indicator-list">
                    {result.indicators.map((item) => (
                      <li key={item}>
                        <span>!</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="no-indicators">
                    No structural risk indicators were detected by the current
                    rules.
                  </p>
                )}
              </div>
            </div>
          )}

          <p className="disclaimer">
            <strong>A note on the score.</strong> This demo uses simple
            server-side structural rules. It does not check link reputation or
            page contents, and cannot prove a link is malicious or safe.
          </p>
        </section>

        <section className="method-section">
          <div className="method-intro">
            <p className="eyebrow">THE METHOD</p>
            <h2>
              Understand what
              <br />
              raises a flag.
            </h2>
            <p>
              Each finding points to a feature of the address itself, not a
              verdict about the website.
            </p>
          </div>
          <div className="method-list">
            <article>
              <span>01</span>
              <div>
                <h3>Connection</h3>
                <p>Whether the link uses HTTPS.</p>
              </div>
            </article>
            <article>
              <span>02</span>
              <div>
                <h3>Host type</h3>
                <p>IP addresses and unusual hostname structures.</p>
              </div>
            </article>
            <article>
              <span>03</span>
              <div>
                <h3>Address wording</h3>
                <p>Account-related terms and other structural signals.</p>
              </div>
            </article>
            <article>
              <span>04</span>
              <div>
                <h3>URL shape</h3>
                <p>Address length and embedded credentials.</p>
              </div>
            </article>
          </div>
        </section>
      </main>

      <footer className="footer">
        <a className="brand" href="#">
          <span className="brand-mark">
            <span />
          </span>
          <span>LinkGuard</span>
        </a>
        <span>URL structure analysis · Demo version</span>
      </footer>
    </div>
  );
}

export default App;
