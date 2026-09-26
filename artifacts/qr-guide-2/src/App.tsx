import { type CSSProperties, type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import jsQR from 'jsqr';
import {
  ArrowLeft,
  ArrowRight,
  Camera,
  Check,
  CheckCircle2,
  CircleAlert,
  FileImage,
  Info,
  LockKeyhole,
  QrCode,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
} from 'lucide-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { Route, Switch, useLocation, Router as WouterRouter } from 'wouter';

const queryClient = new QueryClient();

type AppState = 'idle' | 'loading' | 'result' | 'invalid' | 'failed';
type ResultStatus = 'safe' | 'suspicious' | 'dangerous';
type SignalKind = 'good' | 'warn' | 'bad' | 'neutral';

type SecurityCheck = {
  label: string;
  value: string;
  kind: SignalKind;
};

type Analysis = {
  text: string;
  score: number;
  status: ResultStatus;
  reasons: Array<{ title: string; detail: string; kind: SignalKind }>;
  checks: SecurityCheck[];
  domain: string;
  protocol: string;
  urlType: string;
  https: string;
  source: 'demo' | 'upload' | 'camera';
};

type Detector = {
  detect: (source: CanvasImageSource) => Promise<Array<{ rawValue?: string }>>;
};

const demoText = 'https://www.citylibrary.org/events/spring-reading';

function makeAnalysis(text: string, source: Analysis['source']): Analysis {
  const trimmed = text.trim();
  const isUrl = /^(https?|javascript|data):/i.test(trimmed);
  const reasons: Analysis['reasons'] = [];
  const checks: SecurityCheck[] = [];
  let score = 21;
  let domain = 'Not applicable';
  let protocol = 'Plain text';
  let urlType = 'Plain text';
  let https = 'Not applicable';

  if (!isUrl) {
    score = 36;
    checks.push({ label: 'Payload type', value: 'Plain text', kind: 'neutral' });
    reasons.push({
      title: 'This is text, not a web address',
      detail: 'It does not open a website automatically. Check that you recognize the text before using it.',
      kind: 'good',
    });
  } else {
    try {
      const url = new URL(trimmed);
      const host = url.hostname.toLowerCase();
      const isWebScheme = url.protocol === 'https:' || url.protocol === 'http:';
      const hasUrgencyWords = /login|verify|claim|password|wallet/i.test(trimmed);
      const isShortened = /bit\.ly|tinyurl|t\.co|goo\.gl|shorturl/i.test(host);
      domain = host || 'No hostname';
      protocol = url.protocol.replace(':', '').toUpperCase();
      urlType = isWebScheme ? 'Web URL' : 'Non-web scheme';
      https = url.protocol === 'https:' ? 'Present' : 'Missing';
      checks.push({ label: 'Payload type', value: urlType, kind: isWebScheme ? 'neutral' : 'bad' });

      if (url.protocol === 'javascript:' || url.protocol === 'data:') {
        score = 88;
        checks.push({ label: 'Connection', value: 'Non-web scheme', kind: 'bad' });
        reasons.push({
          title: 'This is not a normal website link',
          detail: 'It uses a browser or data scheme instead of a standard web address. Do not open it unless you know exactly why it is there.',
          kind: 'bad',
        });
      } else if (url.protocol === 'https:') {
        score -= 9;
        checks.push({ label: 'Connection', value: 'HTTPS encrypted', kind: 'good' });
        reasons.push({
          title: 'The connection is encrypted',
          detail: 'This link uses HTTPS, which helps protect the connection while it travels.',
          kind: 'good',
        });
      } else {
        score += 24;
        checks.push({ label: 'Connection', value: 'HTTP not encrypted', kind: 'warn' });
        reasons.push({
          title: 'The link is not encrypted',
          detail: 'It uses HTTP instead of HTTPS. Avoid sharing private information on this site.',
          kind: 'warn',
        });
      }

      if (host.endsWith('.example') || host === 'citylibrary.org' || host.endsWith('.citylibrary.org')) {
        score -= 6;
        checks.push({ label: 'Domain structure', value: 'Clear and familiar', kind: 'good' });
        reasons.push({
          title: 'The address looks familiar',
          detail: 'The web address has a clear, readable domain rather than a disguised short link.',
          kind: 'good',
        });
      } else if (isShortened) {
        score += 25;
        checks.push({ label: 'Domain structure', value: 'Shortened destination', kind: 'warn' });
        reasons.push({
          title: 'The link is shortened',
          detail: 'Short links hide their destination. Take a moment to check where they lead before opening.',
          kind: 'warn',
        });
      } else {
        checks.push({ label: 'Domain structure', value: 'Readable; review it', kind: 'neutral' });
        reasons.push({
          title: 'The destination is ready to review',
          detail: 'Look at the domain carefully and make sure it is the organization you expect.',
          kind: 'good',
        });
      }

      if (url.username || /@/.test(url.hostname) || hasUrgencyWords) {
        score += 28;
        checks.push({ label: 'Pressure signals', value: 'Needs extra attention', kind: 'bad' });
        reasons.push({
          title: 'This link asks for extra attention',
          detail: 'Some words in the address can be used to create urgency or imitate a sign-in page.',
          kind: 'bad',
        });
      } else {
        checks.push({ label: 'Pressure signals', value: 'No common terms found', kind: 'good' });
        reasons.push({
          title: 'No urgent request found',
          detail: 'We did not see common pressure words that often try to rush people into a decision.',
          kind: 'good',
        });
      }
    } catch {
      score = 48;
      protocol = 'Unclear';
      urlType = 'Unusual web address';
      https = 'Unknown';
      checks.push({ label: 'Payload type', value: 'Web address', kind: 'warn' });
      checks.push({ label: 'Domain structure', value: 'Hard to verify', kind: 'warn' });
      reasons.push({
        title: 'The address is unusual',
        detail: 'This text looks like a web link, but its structure is difficult to verify safely.',
        kind: 'warn',
      });
    }
  }

  score = Math.max(4, Math.min(96, Math.round(score)));
  const status: ResultStatus = score >= 70 ? 'dangerous' : score >= 40 ? 'suspicious' : 'safe';
  return { text: trimmed, score, status, reasons, checks, domain, protocol, urlType, https, source };
}

function StatusIcon({ status }: { status: ResultStatus }) {
  if (status === 'safe') return <CheckCircle2 aria-hidden="true" />;
  return <CircleAlert aria-hidden="true" />;
}

function SignalIcon({ kind }: { kind: SignalKind }) {
  if (kind === 'good') return <Check aria-hidden="true" />;
  if (kind === 'neutral') return <Info aria-hidden="true" />;
  return <CircleAlert aria-hidden="true" />;
}

function UploadZone({
  onFile,
  onCamera,
  onDemo,
}: {
  onFile: (file: File) => void;
  onCamera: () => void;
  onDemo: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const handleFile = (file?: File) => {
    if (file) onFile(file);
  };

  return (
    <div className="scan-card reveal" data-testid="card-scan">
      <div className="scan-card-head">
        <div>
          <div className="card-label">Local scan console</div>
          <h2>Check a QR code</h2>
          <p>Choose a picture or use your camera.</p>
        </div>
        <QrCode aria-hidden="true" />
      </div>
      <div
        className={`drop-zone ${dragging ? 'dragging' : ''}`}
        onDragEnter={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          handleFile(event.dataTransfer.files[0]);
        }}
        data-testid="dropzone-qr-image"
      >
        <div className="upload-icon"><Upload aria-hidden="true" /></div>
        <strong>Drop an image here</strong>
        <p>PNG, JPG, or WEBP up to 10 MB</p>
        <button className="file-button" type="button" onClick={() => inputRef.current?.click()} data-testid="button-choose-image">
          Choose an image
        </button>
        <input ref={inputRef} className="hidden-file" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => handleFile(event.target.files?.[0])} data-testid="input-qr-image" />
      </div>
      <div className="or-rule"><span>or</span></div>
      <button className="camera-button" type="button" onClick={onCamera} data-testid="button-open-camera">
        <Camera aria-hidden="true" /> Use camera to scan
      </button>
      <div className="demo-strip">
        <Sparkles size={15} aria-hidden="true" />
        <span>Want to see how it works?</span>
        <button className="demo-button" type="button" onClick={onDemo} data-testid="button-try-demo">Try a demo scan</button>
      </div>
      <p className="privacy-note"><LockKeyhole aria-hidden="true" /> Images are checked in your browser and never uploaded.</p>
    </div>
  );
}

function Header() {
  return (
    <header className="qr-header qr-shell">
      <a className="brand-lockup" href="/" data-testid="link-home">
        <span className="brand-mark"><QrCode aria-hidden="true" /></span>
        <span className="brand-name">QR Guide <em>2</em></span>
      </a>
      <div className="header-note"><ShieldCheck aria-hidden="true" /> Browser-first security analysis</div>
    </header>
  );
}

function IntroSection({ onFile, onCamera, onDemo }: { onFile: (file: File) => void; onCamera: () => void; onDemo: () => void }) {
  return (
    <>
      <section className="hero qr-shell">
        <div className="reveal">
          <div className="eyebrow"><span className="eyebrow-line" /> Pause. Then proceed.</div>
          <h1>Know where it goes <span>before you go.</span></h1>
          <p className="hero-subtitle">Smart QR Safety &amp; Risk Analysis</p>
          <p className="hero-copy">Scan or upload a QR code to analyze its destination and identify potential security risks.</p>
        </div>
        <UploadZone onFile={onFile} onCamera={onCamera} onDemo={onDemo} />
      </section>
      <section className="how-section qr-shell">
        <div className="section-heading">
          <h2>Three small steps<br />to a better pause.</h2>
          <p>No jargon, no account, no guessing. Just a quick second opinion when you need one.</p>
        </div>
        <div className="steps">
          <div className="step"><div className="step-num">01 / SHOW IT</div><h3>Share the code</h3><p>Upload a screenshot, photo, or point your camera at the QR code.</p></div>
          <div className="step"><div className="step-num">02 / READ IT</div><h3>See what is inside</h3><p>We pull out the link or text so you can look at it before anything opens.</p></div>
          <div className="step"><div className="step-num">03 / DECIDE</div><h3>Make your call</h3><p>Get a clear score and simple reasons. You stay in control.</p></div>
        </div>
      </section>
    </>
  );
}

function ResultView({ analysis, onReset }: { analysis: Analysis; onReset: () => void }) {
  const color = analysis.status === 'safe' ? '#10a87e' : analysis.status === 'suspicious' ? '#d39122' : '#d34a51';
  const ringStyle = { background: `conic-gradient(${color} ${analysis.score * 3.6}deg, #e6edf5 0deg)` } as CSSProperties;
  const statusLabel = analysis.status[0].toUpperCase() + analysis.status.slice(1);
  const riskBand = analysis.status === 'safe' ? 'Low' : analysis.status === 'suspicious' ? 'Moderate' : 'High';
  const recommendation = analysis.status === 'safe'
    ? 'The local checks found few immediate warning signs. Confirm the destination matches your context before continuing.'
    : analysis.status === 'suspicious'
      ? 'Pause and inspect the domain carefully. Do not enter credentials or personal information until you are confident.'
      : 'Do not open this destination. Close the page and verify the code with the person or organization that shared it.';

  return (
    <main className="result-wrap qr-shell reveal">
      <button className="back-link" type="button" onClick={onReset} data-testid="button-back-to-scan"><ArrowLeft size={15} /> Scan another QR</button>
      <div className="result-heading">
        <div><div className="result-kicker">Scan result / local analysis</div><h1>Destination decoded.</h1></div>
        <p>This basic assessment looks only at the content inside the code. It is a useful pause, not a guarantee of safety.</p>
      </div>
      <div className="result-dashboard">
        <section className="result-card" data-testid="card-analysis-result">
          <div className="result-intro">
            <div><div className="card-label">Scan result</div><h2>Security overview</h2></div>
            <div className={`status-pill ${analysis.status}`} data-testid="status-risk"><StatusIcon status={analysis.status} /> {riskBand} risk <span>({statusLabel})</span></div>
          </div>
          <div className="score-area">
            <div className="score-ring" style={ringStyle} data-testid="value-risk-score"><div className="score-number">{analysis.score}<small>out of 100</small></div></div>
            <div className="score-copy">
              <strong>{analysis.status === 'safe' ? 'Low risk signal.' : analysis.status === 'suspicious' ? 'Moderate risk signal.' : 'High risk signal.'}</strong>
              <p>{analysis.status === 'safe' ? 'Nothing here raises an immediate concern.' : analysis.status === 'suspicious' ? 'A few details deserve a second look before you proceed.' : 'Several warning signs suggest you should stop before opening it.'}</p>
            </div>
          </div>
          <div className="url-block">
            <div className="detail-label">Decoded content</div>
            <p className="decoded-text" data-testid="text-decoded-content">{analysis.text}</p>
            <div className="detail-grid" aria-label="Destination details">
              <div className="detail-item"><span className="detail-label">Domain</span><strong data-testid="text-domain">{analysis.domain}</strong></div>
              <div className="detail-item"><span className="detail-label">Protocol</span><strong data-testid="text-protocol">{analysis.protocol}</strong></div>
              <div className="detail-item"><span className="detail-label">URL type</span><strong data-testid="text-url-type">{analysis.urlType}</strong></div>
              <div className="detail-item"><span className="detail-label">HTTPS presence</span><strong data-testid="text-https">{analysis.https}</strong></div>
            </div>
          </div>
          <div className="result-actions">
            <button className="primary-button" type="button" onClick={onReset} data-testid="button-scan-again"><RefreshCw aria-hidden="true" /> Scan again</button>
            {/^https?:\/\//i.test(analysis.text) && <button className="secondary-button" type="button" onClick={() => window.open(analysis.text, '_blank', 'noopener,noreferrer')} data-testid="button-open-link">Review link <ArrowRight aria-hidden="true" /></button>}
          </div>
        </section>
        <div className="result-side">
          <section className="checks-card" data-testid="card-security-checks">
            <h2>Security checks</h2>
            <p>Only signals available in the local analyzer are shown here.</p>
            <div className="check-list">
              {analysis.checks.map((check, index) => (
                <div className="check-item" key={`${check.label}-${index}`} data-testid={`check-${index}`}>
                  <div className={`check-icon ${check.kind}`}><SignalIcon kind={check.kind} /></div>
                  <div><strong>{check.label}</strong><span>{check.value}</span></div>
                </div>
              ))}
            </div>
          </section>
          <section className="reasons-card" data-testid="card-risk-reasons">
            <h2>Why this score?</h2>
            <p>These are the actual clues used to calculate this result.</p>
            {analysis.reasons.map((reason, index) => (
              <div className="reason" key={`${reason.title}-${index}`} data-testid={`reason-${index}`}>
                <div className={`reason-icon ${reason.kind}`}><SignalIcon kind={reason.kind} /></div>
                <div><strong>{reason.title}</strong><span>{reason.detail}</span></div>
              </div>
            ))}
            <div className="recommendation"><Info aria-hidden="true" /><span><strong>Security recommendation:</strong> {recommendation}</span></div>
            <div className="assessment-note">QR Guide 2 does not check live reputation, malware databases, or the content of a destination.</div>
          </section>
        </div>
      </div>
    </main>
  );
}

function CameraModal({ onClose, onDecoded }: { onClose: () => void; onDecoded: (value: string) => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    let stream: MediaStream | undefined;
    let frame = 0;
    const detectorCtor = (window as typeof window & { BarcodeDetector?: new () => Detector }).BarcodeDetector;
    if (!detectorCtor) {
      setError('Camera scanning is not available in this browser. Choose an image instead.');
      return () => undefined;
    }
    const setup = async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw new Error('media');
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
        if (!active || !videoRef.current) return;
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        const detector = new detectorCtor();
        const scan = async () => {
          if (!active || !videoRef.current) return;
          try {
            const found = await detector.detect(videoRef.current);
            if (found[0]?.rawValue) {
              onDecoded(found[0].rawValue);
              return;
            }
          } catch {
            // Keep looking while the camera is warming up.
          }
          frame = requestAnimationFrame(scan);
        };
        frame = requestAnimationFrame(scan);
      } catch {
        setError('We could not access your camera. Check your browser permission, or choose an image instead.');
      }
    };
    void setup();
    return () => {
      active = false;
      cancelAnimationFrame(frame);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, [onDecoded]);

  return (
    <div className="camera-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="camera-title">
      <div className="camera-modal">
        <div className="camera-modal-head"><div><h2 id="camera-title">Point at a QR code</h2><p>Keep it inside the frame. Nothing opens automatically.</p></div><button className="close-button" type="button" onClick={onClose} aria-label="Close camera" data-testid="button-close-camera"><X aria-hidden="true" /></button></div>
        <div className="video-frame">
          {error ? <div className="camera-error"><div><Camera aria-hidden="true" /><strong>Camera scan unavailable</strong><span>{error}</span></div></div> : <><video ref={videoRef} muted playsInline aria-label="Camera preview" /><div className="scan-reticle" /></>}
        </div>
        <div className="camera-footer"><span><LockKeyhole size={13} /> Your camera stays on this device.</span><button className="secondary-button" type="button" onClick={onClose} data-testid="button-cancel-camera">Cancel</button></div>
      </div>
    </div>
  );
}

function Home() {
  const [state, setState] = useState<AppState>('idle');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [cameraOpen, setCameraOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const finishAnalysis = useCallback((text: string, source: Analysis['source']) => {
    setAnalysis(makeAnalysis(text, source));
    setState('result');
  }, []);

  const readImage = useCallback((file: File) => {
    if (!file.type.startsWith('image/')) {
      setErrorMessage('That file is not an image. Choose a PNG, JPG, or WEBP file.');
      setState('invalid');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setErrorMessage('That image is larger than 10 MB. Try a smaller screenshot or photo.');
      setState('invalid');
      return;
    }
    setState('loading');
    setErrorMessage('');
    const reader = new FileReader();
    reader.onload = () => {
      const image = new Image();
      image.onload = () => {
        const canvas = document.createElement('canvas');
        const scale = Math.min(1, 1600 / Math.max(image.width, image.height));
        canvas.width = Math.max(1, Math.round(image.width * scale));
        canvas.height = Math.max(1, Math.round(image.height * scale));
        const context = canvas.getContext('2d', { willReadFrequently: true });
        if (!context) {
          setErrorMessage('We could not read that image. Try taking a new screenshot.');
          setState('failed');
          return;
        }
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
        const decoded = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: 'attemptBoth' });
        if (decoded?.data) finishAnalysis(decoded.data, 'upload');
        else {
          setErrorMessage('We could not find a clear QR code in that image. Try a closer, brighter photo.');
          setState('failed');
        }
      };
      image.onerror = () => {
        setErrorMessage('That image could not be opened. Try a different file.');
        setState('invalid');
      };
      image.src = String(reader.result);
    };
    reader.onerror = () => {
      setErrorMessage('That image could not be read. Try a different file.');
      setState('invalid');
    };
    reader.readAsDataURL(file);
  }, [finishAnalysis]);

  const reset = () => {
    setAnalysis(null);
    setErrorMessage('');
    setState('idle');
  };
  const runDemo = () => {
    setState('loading');
    window.setTimeout(() => finishAnalysis(demoText, 'demo'), 850);
  };
  const handleCameraDecoded = useCallback((value: string) => {
    setCameraOpen(false);
    setState('loading');
    window.setTimeout(() => finishAnalysis(value, 'camera'), 450);
  }, [finishAnalysis]);

  return (
    <div className="qr-app">
      <Header />
      {state === 'idle' && <IntroSection onFile={readImage} onCamera={() => setCameraOpen(true)} onDemo={runDemo} />}
      {state === 'loading' && <main className="qr-shell state-card reveal" data-testid="state-loading"><div className="state-icon"><QrCode aria-hidden="true" /></div><h1>Reading your QR code</h1><p>We are taking a closer look. This usually takes just a moment.</p><div className="loading-bars" aria-label="Loading"><span /><span /><span /></div></main>}
      {state === 'result' && analysis && <ResultView analysis={analysis} onReset={reset} />}
      {(state === 'invalid' || state === 'failed') && <main className="qr-shell state-card reveal" data-testid={`state-${state}`}><div className="state-icon"><FileImage aria-hidden="true" /></div><h1>{state === 'invalid' ? 'That image needs a rethink.' : 'No QR code found yet.'}</h1><p>{errorMessage}</p><button className="primary-button" type="button" onClick={reset} data-testid="button-try-another"><RefreshCw aria-hidden="true" /> Try another image</button></main>}
      <footer className="qr-footer qr-shell"><span><strong>QR Guide 2</strong> — a second opinion before you scan.</span><span>Private by design.</span></footer>
      {cameraOpen && <CameraModal onClose={() => setCameraOpen(false)} onDecoded={handleCameraDecoded} />}
    </div>
  );
}

function Router() {
  return (
    <RoutedErrorBoundary>
      <Switch><Route path="/" component={Home} /><Route component={NotFound} /></Switch>
    </RoutedErrorBoundary>
  );
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Router /></WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;