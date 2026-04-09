/**
 * SDK Intelligence — detects risky third-party SDKs from package manifests
 * and generates context for the AI Review Board.
 *
 * Reads package.json (or equivalent) during scans to identify SDKs that
 * collect data in ways that are relevant to COPPA, AADC, and other
 * child-safety regulations.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SDKRiskProfile {
  packageNames: string[];           // npm/pip/gradle package names
  defaultCollects: string[];        // what data it collects by default
  coppaRelevant: boolean;           // does this SDK matter for COPPA?
  consentRequired: boolean;         // does this need consent before use?
  safeConfigPattern?: RegExp;       // regex to detect "safe" configuration
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  description: string;             // human-readable risk description
}

export interface DetectedSDK {
  name: string;
  profile: SDKRiskProfile;
}

// ---------------------------------------------------------------------------
// SDK Risk Database
// ---------------------------------------------------------------------------

export const SDK_RISK_DATABASE: SDKRiskProfile[] = [
  // Analytics
  {
    packageNames: ['firebase', '@firebase/analytics', 'firebase-analytics'],
    defaultCollects: ['device_id', 'idfa', 'app_instance_id', 'behavior'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Firebase Analytics collects device IDs and IDFA by default',
  },
  {
    packageNames: ['@segment/analytics-react-native', '@segment/analytics-node', 'analytics-node'],
    defaultCollects: ['device_id', 'ip_address', 'behavior', 'location'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Segment collects device IDs, IP addresses, and behavioral data',
  },
  {
    packageNames: ['mixpanel', 'mixpanel-browser', 'mixpanel-react-native'],
    defaultCollects: ['device_id', 'ip_address', 'behavior', 'location'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Mixpanel collects device identifiers and behavioral analytics',
  },
  {
    packageNames: ['amplitude-js', '@amplitude/analytics-browser', '@amplitude/analytics-node'],
    defaultCollects: ['device_id', 'ip_address', 'behavior'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'high',
    description: 'Amplitude collects device IDs and behavioral analytics',
  },
  {
    packageNames: ['@google-analytics/data', 'react-ga', 'react-ga4', 'ga-4-react'],
    defaultCollects: ['cookies', 'ip_address', 'behavior', 'device_id'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Google Analytics uses cookies and collects IP/device data',
  },
  // Advertising
  {
    packageNames: ['react-native-admob', '@react-native-firebase/admob', 'react-native-google-mobile-ads'],
    defaultCollects: ['idfa', 'device_id', 'behavior', 'location'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'AdMob collects IDFA and behavioral data for ad targeting',
  },
  {
    packageNames: ['facebook-ads', 'react-native-fbads'],
    defaultCollects: ['idfa', 'device_id', 'behavior', 'social_graph'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Facebook Ads SDK collects IDFA and social graph data',
  },
  // Location
  {
    packageNames: ['expo-location', 'react-native-geolocation-service', '@react-native-community/geolocation'],
    defaultCollects: ['precise_location', 'location_history'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'high',
    description: 'Location SDK enables precise geolocation tracking',
  },
  // Social/Auth
  {
    packageNames: ['@react-native-google-signin/google-signin', 'react-native-fbsdk-next', 'expo-auth-session'],
    defaultCollects: ['email', 'profile_data', 'social_id'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'medium',
    description: 'Social sign-in collects email and profile data without age verification',
  },
  // Push Notifications
  {
    packageNames: ['@react-native-firebase/messaging', 'expo-notifications', 'onesignal-react-native'],
    defaultCollects: ['device_token', 'device_id'],
    coppaRelevant: true,
    consentRequired: false,
    riskLevel: 'medium',
    description: 'Push notification SDKs collect device tokens and identifiers',
  },
  // Error Tracking
  {
    packageNames: ['@sentry/react', '@sentry/react-native', '@sentry/node', '@sentry/browser'],
    defaultCollects: ['ip_address', 'device_info', 'breadcrumbs'],
    coppaRelevant: true,
    consentRequired: false,
    riskLevel: 'medium',
    description: 'Sentry collects IP addresses and device info in error reports',
  },
  {
    packageNames: ['@bugsnag/react-native', '@bugsnag/js', 'bugsnag'],
    defaultCollects: ['ip_address', 'device_info', 'breadcrumbs'],
    coppaRelevant: true,
    consentRequired: false,
    riskLevel: 'medium',
    description: 'Bugsnag collects IP and device data in crash reports',
  },
  // Consent management (safe/low-risk)
  {
    packageNames: ['@onetrust/otpublishers-native-sdk', 'cookiebot', 'react-cookie-consent'],
    defaultCollects: [],
    coppaRelevant: false,
    consentRequired: false,
    riskLevel: 'low',
    description: 'Consent management SDK — helps with compliance',
  },
  // In-App Purchases
  {
    packageNames: ['react-native-iap', 'expo-in-app-purchases', 'cordova-plugin-purchase'],
    defaultCollects: ['purchase_history', 'payment_info'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'high',
    description: 'IAP SDK enables purchases that may require parental consent for minors',
  },
  // Chat/Messaging
  {
    packageNames: ['stream-chat-react', 'stream-chat-react-native', '@sendbird/chat'],
    defaultCollects: ['messages', 'user_profiles', 'contacts'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'high',
    description: 'Chat SDK enables direct messaging which may require COPPA safeguards',
  },
  // Python analytics
  {
    packageNames: ['google-analytics-data', 'pyanalytics', 'snowplow-tracker'],
    defaultCollects: ['ip_address', 'behavior', 'cookies'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'high',
    description: 'Server-side analytics SDK collects user behavioral data',
  },
  // Session recording
  {
    packageNames: ['hotjar-react', '@hotjar/browser'],
    defaultCollects: ['session_recordings', 'clicks', 'scrolls', 'form_inputs', 'ip_address'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'Hotjar records user sessions including form inputs — extremely risky for children',
  },
  {
    packageNames: ['logrocket', '@logrocket/react'],
    defaultCollects: ['session_recordings', 'network_requests', 'dom_snapshots', 'ip_address'],
    coppaRelevant: true,
    consentRequired: true,
    riskLevel: 'critical',
    description: 'LogRocket records full session replays including personal data inputs',
  },
];

// ---------------------------------------------------------------------------
// Risk level ordering (for sorting: critical first)
// ---------------------------------------------------------------------------

const RISK_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ---------------------------------------------------------------------------
// Detection functions
// ---------------------------------------------------------------------------

/**
 * Match a flat dependency map (name → version) against the SDK risk database.
 * Returns detected SDKs sorted by risk level (critical first).
 */
export function detectSDKs(dependencies: Record<string, string>): DetectedSDK[] {
  const depNames = new Set(Object.keys(dependencies));
  const detected: DetectedSDK[] = [];

  for (const profile of SDK_RISK_DATABASE) {
    for (const pkgName of profile.packageNames) {
      if (depNames.has(pkgName)) {
        detected.push({ name: pkgName, profile });
        break; // one match per profile is enough
      }
    }
  }

  detected.sort((a, b) => (RISK_ORDER[a.profile.riskLevel] ?? 99) - (RISK_ORDER[b.profile.riskLevel] ?? 99));
  return detected;
}

/**
 * Parse a package.json string and detect risky SDKs from its
 * dependencies + devDependencies.
 */
export function detectSDKsFromPackageJson(packageJsonContent: string): DetectedSDK[] {
  try {
    const pkg = JSON.parse(packageJsonContent);
    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };
    return detectSDKs(allDeps);
  } catch {
    // Malformed JSON — best-effort, return empty
    return [];
  }
}

/**
 * Generate a human-readable summary string for the AI Review Board context.
 * Returns an empty string when no COPPA-relevant SDKs are detected.
 */
export function generateSDKContext(detectedSDKs: DetectedSDK[]): string {
  if (detectedSDKs.length === 0) {
    return '';
  }

  const coppaRelevant = detectedSDKs.filter(s => s.profile.coppaRelevant);
  const consentMgmt = detectedSDKs.filter(s => !s.profile.coppaRelevant && s.profile.riskLevel === 'low');

  const lines: string[] = [];

  if (coppaRelevant.length > 0) {
    lines.push('This project uses the following SDKs with COPPA-relevant data collection:');
    for (const sdk of coppaRelevant) {
      const collects = sdk.profile.defaultCollects.join(', ');
      lines.push(`  - ${sdk.name} (${sdk.profile.riskLevel.toUpperCase()}): collects ${collects}`);
    }
  }

  if (consentMgmt.length > 0) {
    lines.push(`Consent management SDK detected: ${consentMgmt.map(s => s.name).join(', ')}`);
  }

  return lines.join('\n');
}
