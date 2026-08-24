export type Verdict = "Legitimate" | "Phishing";

export interface PredictionResponse {
  prediction: Verdict;
  probabilities: { legitimate: number; phishing: number };
  confidence: number;
  source?: string;          // 'ml_model' or 'heuristic'
  features?: Record<string, number>;
}

export async function checkUrl(url: string): Promise<PredictionResponse> {
  const response = await fetch('http://localhost:5000/predict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API error: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  
  // The backend already returns the correct prediction, probabilities, and confidence.
  // We just need to format it to match the frontend's expected type.
  return {
    prediction: data.prediction as Verdict,
    probabilities: data.probabilities,
    confidence: data.confidence,
    source: data.source || 'unknown',
    features: data.features || {},
  };
}

// If you want to keep the heuristic as a fallback (only when API fails):
export async function checkUrlWithFallback(url: string): Promise<PredictionResponse> {
  try {
    return await checkUrl(url);
  } catch (error) {
    console.warn('API failed, using client‑side heuristic fallback:', error);
    // You could optionally implement a simple heuristic here,
    // but ideally you'd just show an error to the user.
    throw new Error('Unable to reach the prediction service. Please try again later.');
  }
}