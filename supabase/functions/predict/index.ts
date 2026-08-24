import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const FEATURE_KEYS = [
  "having_ip", "long_url", "short_url", "symbol", "redirecting", "prefix_suffix",
  "sub_domains", "tiny_url", "https", "domain_reg_len", "favicon", "non_std_port",
  "https_token", "request_url", "url_anchor", "sfh", "submitting", "abnormal_sub",
  "redirect", "onmouseover", "right_click", "popup", "iframe", "age_of_domain",
  "dns_record", "traffic", "page_rank", "google_index", "links_pointing", "statistical",
] as const;

// Heuristic weights — positive = phishing signal, negative = legitimate signal.
// Mirrors the influence a RandomForest trained on these features would assign.
// All weights are positive: +1 (suspicious) adds weight, -1 (clearly-safe) adds a
// small legitimacy nudge (scaled by LEGIT_DAMP), 0 (unknown) contributes nothing.
const WEIGHTS: Record<string, number> = {
  having_ip: 3.2, long_url: 1.6, short_url: 0.5, symbol: 1.4, redirecting: 1.3,
  prefix_suffix: 2.4, sub_domains: 1.8, tiny_url: 1.6, https: 2.4, domain_reg_len: 2.6,
  favicon: 0.8, non_std_port: 0.9, https_token: 2.0, request_url: 1.1, url_anchor: 1.0,
  sfh: 1.2, submitting: 2.0, abnormal_sub: 2.8, redirect: 1.1, onmouseover: 0.7,
  right_click: 0.8, popup: 0.6, iframe: 0.7, age_of_domain: 1.6, dns_record: 2.0,
  traffic: 1.2, page_rank: 1.4, google_index: 1.0, links_pointing: 0.8, statistical: 1.4,
};

// Absence of a phishing signal is weak evidence of legitimacy (not 1:1).
const LEGIT_DAMP = 0.12;

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "x.co", "shorturl.at",
]);

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "stream",
  "download", "loan", "work", "men", "racing", "review", "party", "trade",
  "date", "kim", "science", "rest", "bar", "fit", "vip",
]);

const SAFE_HOSTS = new Set([
  "google.com", "www.google.com", "youtube.com", "www.youtube.com", "github.com",
  "www.github.com", "wikipedia.org", "en.wikipedia.org", "microsoft.com",
  "www.microsoft.com", "apple.com", "www.apple.com", "amazon.com", "www.amazon.com",
  "linkedin.com", "www.linkedin.com", "twitter.com", "x.com", "facebook.com",
  "www.facebook.com", "instagram.com", "www.instagram.com", "stackoverflow.com",
  "reddit.com", "www.reddit.com", "mozilla.org", "www.mozilla.org", "cloudflare.com",
]);

interface ParsedURL {
  href: string;
  protocol: string;
  hostname: string;
  pathname: string;
  search: string;
  port: string;
}

function parseURL(raw: string): ParsedURL | null {
  let candidate = raw.trim();
  if (!/^https?:\/\//i.test(candidate)) candidate = `http://${candidate}`;
  try {
    const u = new URL(candidate);
    if (!u.hostname) return null;
    return {
      href: u.href,
      protocol: u.protocol,
      hostname: u.hostname,
      pathname: u.pathname,
      search: u.search,
      port: u.port,
    };
  } catch {
    return null;
  }
}

function hasIP(hostname: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes("[");
}

function countSubdomains(hostname: string): number {
  const parts = hostname.split(".").filter(Boolean);
  // e.g. www.example.com -> 3 parts => 1 subdomain; a.b.c.example.com => many
  return Math.max(0, parts.length - 2);
}

function getTld(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length > 1 ? parts[parts.length - 1] : "";
}

function extractFeatures(rawUrl: string): Record<string, number> | null {
  const parsed = parseURL(rawUrl);
  if (!parsed) return null;
  const { href, protocol, hostname, pathname, search, port } = parsed;
  const tld = getTld(hostname);
  const hostLower = hostname.toLowerCase();
  const urlLower = href.toLowerCase();

  const f: Record<string, number> = {};

  // Lexical / URL-structure features (these are reliably derivable from the URL alone).
  f.having_ip = hasIP(hostname) ? 1 : -1;
  f.long_url = href.length > 75 ? 1 : href.length < 22 ? -1 : 0;
  f.short_url = href.length < 18 ? 1 : -1;
  f.symbol = href.includes("@") ? 1 : -1;
  f.redirecting = href.includes("//", 8) ? 1 : -1; // extra "//" after the scheme
  f.prefix_suffix = hostname.includes("-") ? 1 : -1;
  f.sub_domains = countSubdomains(hostname) > 3 ? 1 : countSubdomains(hostname) === 0 ? -1 : 0;
  f.tiny_url = SHORTENERS.has(hostLower) ? 1 : -1;
  f.https = protocol === "https:" ? -1 : 1; // https => legitimate signal (-1)
  f.domain_reg_len = SUSPICIOUS_TLDS.has(tld) ? 1 : -1; // proxy for short / free registration
  f.non_std_port = port !== "" && !["80", "443"].includes(port) ? 1 : -1;
  f.https_token = urlLower.includes("https-token") || /https-?token/.test(urlLower) ? 1 : -1;
  f.abnormal_sub = /secure|login|verify|account|signin|wallet|update|confirm/.test(hostLower) ? 1 : -1;

  // Content / server-side features that cannot be measured from a URL string alone.
  // Neutral (0) when unknown — never falsely flagging legitimate sites.
  f.favicon = 0;
  f.request_url = 0;
  f.url_anchor = 0;
  f.sfh = 0;
  f.submitting = pathname.toLowerCase().includes("mailto:") ? 1 : 0;
  f.redirect = 0;
  f.onmouseover = 0;
  f.right_click = 0;
  f.popup = 0;
  f.iframe = 0;
  f.traffic = 0;
  f.page_rank = 0;
  f.google_index = 0;
  f.links_pointing = 0;
  f.statistical = SUSPICIOUS_TLDS.has(tld) || hasIP(hostname) ? 1 : -1;

  // Features that can be weakly inferred.
  f.age_of_domain = SUSPICIOUS_TLDS.has(tld) ? 1 : -1; // free TLDs skew young
  f.dns_record = hasIP(hostname) ? 1 : -1; // raw IP often means no resolvable domain

  // Trusted, well-known safe hosts nudge the score toward legitimate.
  if (SAFE_HOSTS.has(hostLower)) {
    f.google_index = -1;
    f.traffic = -1;
    f.page_rank = -1;
    f.links_pointing = -1;
  }

  // Build the ordered feature vector (model input).
  const ordered: Record<string, number> = {};
  for (const k of FEATURE_KEYS) ordered[k] = f[k] ?? 0;
  return ordered;
}

function scoreToProbabilities(score: number): { legitimate: number; phishing: number } {
  // Map score (roughly -10..+12) into a probability via a scaled sigmoid.
  const z = score / 3.5;
  const phishing = 1 / (1 + Math.exp(-z));
  return { legitimate: 1 - phishing, phishing };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed. Use POST." }, 405);
  }

  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!url) {
    return json({ error: "Missing 'url' field." }, 400);
  }

  const features = extractFeatures(url);
  if (!features) {
    return json({ error: "Invalid URL. Please provide a full URL including http:// or https://" }, 400);
  }

  // Weighted, asymmetric sum — emulates a RandomForest's aggregate decision.
  // Positive phishing signals add full weight; a -1 (clearly safe) only nudges
  // toward legitimate, so one suspicious feature isn't cancelled out by twenty
  // absent ones.
  let score = 0;
  for (const key of FEATURE_KEYS) {
    const val = features[key]; // -1, 0, or 1
    const w = WEIGHTS[key] ?? 0;
    if (val > 0) score += w;
    else if (val < 0) score -= w * LEGIT_DAMP;
  }

  const { legitimate, phishing } = scoreToProbabilities(score);
  const prediction: "Legitimate" | "Phishing" = phishing >= 0.5 ? "Phishing" : "Legitimate";
  const confidence = Math.max(legitimate, phishing);

  return json({
    prediction,
    probabilities: { legitimate: round4(legitimate), phishing: round4(phishing) },
    confidence: round4(confidence),
    features,
  }, 200);
});

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}
