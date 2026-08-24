export type Verdict = "Legitimate" | "Phishing";

export interface PredictionResponse {
  prediction: Verdict;
  probabilities: { legitimate: number; phishing: number };
  confidence: number;
  source?: string;
  features?: Record<string, number>;
}

const API_ENDPOINT = 'https://website-phishing-detector-3wbz.onrender.com/predict';

export async function checkUrl(url: string): Promise<PredictionResponse> {
  const response = await fetch(API_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API error: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  return {
    prediction: data.prediction as Verdict,
    probabilities: data.probabilities,
    confidence: data.confidence,
    source: data.source || 'unknown',
    features: data.features || {},
  };
}

export async function checkUrlWithFallback(url: string): Promise<PredictionResponse> {
  try {
    return await checkUrl(url);
  } catch (error) {
    console.warn('API failed, using client‑side heuristic fallback:', error);
    throw new Error('Unable to reach the prediction service. Please try again later.');
  }
}