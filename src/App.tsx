import { useState, useRef, useEffect, type FormEvent } from "react";
import { ShieldCheck, ShieldAlert, Loader2, Search, Globe, Lock, Activity, AlertTriangle } from "lucide-react";
import { type PredictionResponse } from "@/lib/detector";

export type { PredictionResponse };

type Status = "idle" | "loading" | "success" | "error";

const API_ENDPOINT = 'https://website-phishing-detector-3wbz.onrender.com/predict';

const SAMPLES = [
  "https://www.google.com",
  "http://secure-login-update.account-verify.tk/login",
  "https://github.com",
  "http://192.168.0.5/login.php?token=free-gift",
];

export default function App() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [error, setError] = useState<string>("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a URL to check.");
      setStatus("error");
      return;
    }
    if (!/^https?:\/\/.+/i.test(trimmed) && !/^[\w-]+(\.[\w-]+)+.*$/i.test(trimmed)) {
      setError("That doesn't look like a valid URL. Include http:// or https://");
      setStatus("error");
      return;
    }

    setStatus("loading");
    setResult(null);
    setError("");
    setShowAdvanced(false);

    try {
      const res = await fetch(`${API_ENDPOINT}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY ?? ""}`,
          apikey: `${import.meta.env.VITE_SUPABASE_ANON_KEY ?? ""}`,
        },
        body: JSON.stringify({ url: trimmed }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${res.status})`);
      }
      const data: PredictionResponse = await res.json();
      setResult(data);
      setStatus("success");
    } catch (err) {
      const msg = err instanceof TypeError
        ? "Network error: couldn't reach the detection service."
        : err instanceof Error ? err.message : "Something went wrong. Please try again.";
      setError(msg);
      setStatus("error");
    }
  }

  function reset() {
    setUrl("");
    setStatus("idle");
    setResult(null);
    setError("");
    inputRef.current?.focus();
  }

  const isPhishing = result?.prediction === "Phishing";

  return (
    <div className="min-h-screen bg-[#0a0f1f] text-slate-100 font-sans relative overflow-hidden">
      {/* ambient background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-40 -left-40 w-[32rem] h-[32rem] rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute top-1/3 -right-40 w-[32rem] h-[32rem] rounded-full bg-blue-600/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 w-[28rem] h-[28rem] rounded-full bg-emerald-500/5 blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.07) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
      </div>

      <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-4 py-12">
        <Header />

        <main className="w-full max-w-xl mt-10">
          {/* Card */}
          <div className="rounded-2xl border border-white/10 bg-white/[0.04] backdrop-blur-xl shadow-2xl shadow-black/40 overflow-hidden">
            <div className="px-6 pt-6 pb-7 sm:px-8">
              <form onSubmit={handleSubmit} className="space-y-4">
                <label htmlFor="url-input" className="text-sm font-medium text-slate-300">
                  Website URL
                </label>
                <div className="relative">
                  <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                  <input
                    id="url-input"
                    ref={inputRef}
                    type="text"
                    inputMode="url"
                    autoComplete="off"
                    spellCheck={false}
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    disabled={status === "loading"}
                    placeholder="https://example.com"
                    className="w-full pl-11 pr-4 py-3.5 rounded-xl bg-slate-900/70 border border-white/10 text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-400/60 focus:border-transparent transition disabled:opacity-60"
                  />
                </div>

                <button
                  type="submit"
                  disabled={status === "loading"}
                  className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl font-semibold text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 focus:outline-none focus:ring-2 focus:ring-cyan-300/70 focus:ring-offset-2 focus:ring-offset-[#0a0f1f] transition-all duration-200 disabled:opacity-70 disabled:cursor-not-allowed shadow-lg shadow-blue-600/20"
                >
                  {status === "loading" ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Analyzing…
                    </>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      Check URL
                    </>
                  )}
                </button>
              </form>

              {/* samples */}
              {status === "idle" && (
                <div className="mt-5">
                  <p className="text-xs text-slate-400 mb-2">Try a sample:</p>
                  <div className="flex flex-wrap gap-2">
                    {SAMPLES.map((s) => (
                      <button
                        key={s}
                        onClick={() => setUrl(s)}
                        className="text-xs px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10 hover:text-white transition truncate max-w-[16rem]"
                        title={s}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Result area */}
            {status === "loading" && <LoadingPanel />}

            {status === "error" && (
              <ErrorPanel message={error} onDismiss={reset} />
            )}

            {status === "success" && result && (
              <ResultPanel
                result={result}
                isPhishing={isPhishing}
                onReset={reset}
                showAdvanced={showAdvanced}
                onToggleAdvanced={() => setShowAdvanced((v) => !v)}
              />
            )}
          </div>

          <Footer />
        </main>
      </div>
    </div>
  );
}

function Header() {
  return (
    <header className="text-center max-w-xl">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-white/10 mb-5 shadow-lg">
        <Lock className="w-8 h-8 text-cyan-300" />
      </div>
      <h1 className="text-3xl sm:text-4xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">
        Phishing Website Detector
      </h1>
      <p className="mt-3 text-slate-400 text-base sm:text-lg">
        Enter a URL to check whether it's a legitimate site or a phishing attempt.
      </p>
    </header>
  );
}

function LoadingPanel() {
  const steps = [
    { icon: Globe, label: "Fetching URL characteristics" },
    { icon: Activity, label: "Extracting 30 security features" },
    { icon: ShieldCheck, label: "Running model analysis" },
  ];
  return (
    <div className="border-t border-white/10 px-6 py-8 sm:px-8 bg-slate-900/30 animate-[fadeIn_0.3s_ease-out]">
      <div className="flex flex-col items-center gap-6">
        <div className="relative">
          <div className="w-14 h-14 rounded-full border-4 border-white/10 border-t-cyan-400 animate-spin" />
          <ShieldCheck className="absolute inset-0 m-auto w-6 h-6 text-cyan-300" />
        </div>
        <div className="w-full space-y-3 max-w-sm">
          {steps.map((s, i) => (
            <div
              key={s.label}
              className="flex items-center gap-3 text-sm text-slate-300 animate-[fadeIn_0.4s_ease-out_both]"
              style={{ animationDelay: `${i * 0.2}s` }}
            >
              <s.icon className="w-4 h-4 text-cyan-400/80" />
              <span>{s.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ErrorPanel({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div className="border-t border-white/10 px-6 py-6 sm:px-8 bg-rose-950/20 animate-[fadeIn_0.3s_ease-out]">
      <div className="flex items-start gap-3">
        <div className="shrink-0 w-10 h-10 rounded-full bg-rose-500/15 flex items-center justify-center">
          <AlertTriangle className="w-5 h-5 text-rose-400" />
        </div>
        <div className="flex-1">
          <p className="font-semibold text-rose-300">Couldn't complete the check</p>
          <p className="text-sm text-slate-300 mt-1">{message}</p>
          <button
            onClick={onDismiss}
            className="mt-3 text-sm text-cyan-300 hover:text-cyan-200 underline underline-offset-2"
          >
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}

function ResultPanel({
  result,
  isPhishing,
  onReset,
  showAdvanced,
  onToggleAdvanced,
}: {
  result: PredictionResponse;
  isPhishing: boolean;
  onReset: () => void;
  showAdvanced: boolean;
  onToggleAdvanced: () => void;
}) {
  const { prediction, probabilities, confidence } = result;
  const accent = isPhishing
    ? { ring: "ring-rose-500/40", bg: "bg-rose-500/15", text: "text-rose-300", bar: "bg-rose-500", glow: "shadow-rose-500/20" }
    : { ring: "ring-emerald-500/40", bg: "bg-emerald-500/15", text: "text-emerald-300", bar: "bg-emerald-500", glow: "shadow-emerald-500/20" };

  return (
    <div className="border-t border-white/10 animate-[fadeInUp_0.45s_cubic-bezier(0.16,1,0.3,1)]">
      {/* Verdict */}
      <div className={`px-6 py-7 sm:px-8 ${isPhishing ? "bg-rose-950/25" : "bg-emerald-950/25"}`}>
        <div className="flex items-center gap-4">
          <div className={`shrink-0 w-16 h-16 rounded-2xl ${accent.bg} ring-2 ${accent.ring} flex items-center justify-center shadow-lg ${accent.glow}`}>
            {isPhishing ? (
              <ShieldAlert className={`w-8 h-8 ${accent.text}`} />
            ) : (
              <ShieldCheck className={`w-8 h-8 ${accent.text}`} />
            )}
          </div>
          <div className="min-w-0">
            <p className={`text-2xl font-bold ${accent.text}`}>
              {isPhishing ? "Phishing" : "Safe"}
            </p>
            <p className="text-sm text-slate-300 mt-0.5">
              This URL is predicted to be <span className="font-medium">{prediction.toLowerCase()}</span>.
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Model confidence: <span className="font-semibold text-slate-200">{(confidence * 100).toFixed(1)}%</span>
            </p>
          </div>
        </div>
      </div>

      {/* Probability bars */}
      <div className="px-6 py-6 sm:px-8 space-y-5">
        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-slate-300">Legitimate</span>
            <span className="font-semibold text-emerald-300">{(probabilities.legitimate * 100).toFixed(1)}%</span>
          </div>
          <div className="h-3 rounded-full bg-slate-800/80 overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-[width] duration-700 ease-out"
              style={{ width: `${probabilities.legitimate * 100}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-slate-300">Phishing</span>
            <span className="font-semibold text-rose-300">{(probabilities.phishing * 100).toFixed(1)}%</span>
          </div>
          <div className="h-3 rounded-full bg-slate-800/80 overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-rose-500 to-rose-400 transition-[width] duration-700 ease-out"
              style={{ width: `${probabilities.phishing * 100}%` }}
            />
          </div>
        </div>

        {/* Advanced features */}
        {result.features && (
          <div className="pt-2">
            <button
              onClick={onToggleAdvanced}
              className="text-sm text-slate-400 hover:text-slate-200 transition flex items-center gap-1"
            >
              <Activity className="w-4 h-4" />
              {showAdvanced ? "Hide" : "Show"} extracted features
            </button>
            {showAdvanced && (
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2 animate-[fadeIn_0.3s_ease-out]">
                {Object.entries(result.features).map(([k, v]) => (
                  <div
                    key={k}
                    className="rounded-lg bg-slate-900/60 border border-white/5 px-3 py-2 text-xs"
                  >
                    <p className="text-slate-400 truncate" title={k}>{prettyFeature(k)}</p>
                    <p className={`font-semibold mt-0.5 ${v === 1 ? "text-rose-300" : "text-emerald-300"}`}>
                      {v === 1 ? "suspicious" : "ok"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <button
          onClick={onReset}
          className="w-full mt-2 py-2.5 rounded-xl text-sm font-medium text-slate-300 bg-white/5 border border-white/10 hover:bg-white/10 hover:text-white transition"
        >
          Check another URL
        </button>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="mt-8 text-center text-xs text-slate-500 space-y-1">
      <p>Powered by a trained RandomForest model using 30 URL features.</p>
      <p className="flex items-center justify-center gap-1.5">
        <Lock className="w-3.5 h-3.5" />
        Results are estimates — always verify suspicious links manually.
      </p>
    </footer>
  );
}

const FEATURE_NAMES: Record<string, string> = {
  having_ip: "IP in address",
  long_url: "Long URL",
  short_url: "Short URL",
  symbol: "Symbol in URL",
  redirecting: "Redirecting //",
  prefix_suffix: "Dash in domain",
  sub_domains: "Many subdomains",
  tiny_url: "Tiny URL",
  https: "HTTPS enabled",
  domain_reg_len: "Short reg age",
  favicon: "Foreign favicon",
  non_std_port: "Non-std port",
  https_token: "HTTPS token",
  request_url: "Foreign request",
  url_anchor: "Anchor ratio",
  sfh: "Server form handler",
  submitting: "Submit to email",
  abnormal_sub: "Abnormal subdomain",
  redirect: "Many redirects",
  onmouseover: "Mouseover change",
  right_click: "Right-click disabled",
  popup: "Popup window",
  iframe: "Iframe redirect",
  age_of_domain: "Young domain",
  dns_record: "No DNS record",
  traffic: "Low traffic",
  page_rank: "Low page rank",
  google_index: "Not indexed",
  links_pointing: "Few backlinks",
  statistical: "Statistical report",
};

function prettyFeature(k: string): string {
  return FEATURE_NAMES[k] ?? k;
}
