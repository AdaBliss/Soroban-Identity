import path from "node:path";
import { logger } from './logger.js';
import { parseCronExpression } from './cron.js';

const DEFAULT_DATA_DIR = path.resolve(process.cwd(), "data");
// Defaults used by the optional session-key encryption feature. The sensitive
// field list remains empty so deployments must opt in to fields explicitly.
const DEFAULT_ENCRYPTION_KEY_ROTATION_SECONDS = 900;
const DEFAULT_ENCRYPTION_SESSION_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_ENCRYPTION_SENSITIVE_FIELDS = [];

// #1325 BUG-28: all DB timestamps must be UTC. The indexer previously stored
// timestamps in the server's local timezone. The DB connection layer applies
// this timezone to every session; it defaults to UTC so a deployment that does
// not set DB_TIMEZONE still gets UTC timestamps.
const DEFAULT_DB_TIMEZONE = "UTC";

/**
 * Resolve the database session timezone from the environment.
 *
 * @param {Object} env - Environment variable object
 * @returns {string} The configured timezone, or "UTC" when unset/blank
 */
export function resolveDbTimezone(env = process.env) {
  const raw = env.DB_TIMEZONE;
  if (raw === undefined || raw === null) return DEFAULT_DB_TIMEZONE;
  const trimmed = String(raw).trim();
  return trimmed === "" ? DEFAULT_DB_TIMEZONE : trimmed;
}

// Force the process timezone to UTC at module load when the DB timezone is
// UTC, so any Date/DB session defaults that fall back to the process timezone
// also produce UTC timestamps. This runs before any other module reads TZ.
const initialDbTimezone = resolveDbTimezone(process.env);
if (initialDbTimezone.toUpperCase() === "UTC") {
  process.env.TZ = "UTC";
}

/**
 * Parse an integer from a string environment variable value.
 *
 * @param {string|undefined} value     - Raw env var string
 * @param {number}           fallback  - Default when value is absent or invalid
 * @param {boolean}         [allowZero=false] - When true, 0 is accepted as a
 *   valid "disabled" sentinel in addition to positive integers. Keys that
 *   support disable-via-0 (EVENT_POLL_INTERVAL_MS, RPC_MAX_RETRIES,
 *   SOROBAN_POOL_SIZE) must pass allowZero: true. All other keys require a
 *   strictly positive integer.
 */
function parseInteger(value, fallback, allowZero = false) {
  const parsed = Number.parseInt(value ?? "", 10);
  const isValid = Number.isFinite(parsed) && (allowZero ? parsed >= 0 : parsed > 0);
  return isValid ? parsed : fallback;
}

/**
 * Resolve the Stellar source account from environment variables.
 * STELLAR_SOURCE_ACCOUNT takes precedence over STELLAR_SECRET_KEY.
 * Both loadConfig and validateConfig use this helper so they always agree
 * on which variable is authoritative when both are set.
 *
 * @param {Object} env - Environment variable object
 * @returns {string} The resolved source account, or "" if neither is set
 */
function resolveSourceAccount(env) {
  return env.STELLAR_SOURCE_ACCOUNT ?? env.STELLAR_SECRET_KEY ?? "";
}

function parseJson(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`Invalid JSON configuration: ${error.message}`);
  }
}

/**
 * Parse the allowed CORS origins.
 *
 * Accepts a comma-separated list, a single origin, or `*`. `CORS_ORIGIN` is
 * the documented name; `CORS_ALLOWED_ORIGINS` is still read as an alias so
 * existing deployments keep working.
 *
 * Default: allow all in development, none in production — a production
 * deployment must name its origins explicitly rather than inheriting a
 * permissive default.
 *
 * @param {string|undefined} value
 * @param {string} nodeEnv
 * @returns {string[]}
 */
function parseCorsOrigins(value, nodeEnv) {
  if (!value) {
    return nodeEnv === "development" ? ["*"] : [];
  }
  if (value.trim() === "*") {
    return ["*"];
  }
  // Comma-separated list of origins
  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

/**
 * Parse a boolean environment variable.
 *
 * Accepts true/1/yes/on and false/0/no/off, case-insensitively. Anything else
 * (including an empty value) falls back to the default rather than being
 * silently treated as false.
 *
 * @param {string|undefined} value
 * @param {boolean} fallback
 * @returns {boolean}
 */
function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "off"].includes(normalized)) return false;
  return fallback;
}

/**
 * Parse a comma-separated list into a trimmed array, falling back to a default
 * when the variable is unset or contains only separators.
 *
 * @param {string|undefined} value
 * @param {string[]} fallback
 * @returns {string[]}
 */
function parseList(value, fallback) {
  if (!value) return fallback;
  const items = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length > 0 ? items : fallback;
}

export const DEFAULT_CORS_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
];

export const DEFAULT_CORS_ALLOWED_HEADERS = [
  "Content-Type",
  "Authorization",
  "X-API-Key",
  "X-Request-ID",
  "X-Correlation-ID",
  "X-Actor",
  "X-User-Tier",
  "X-API-Version",
];

export const DEFAULT_CORS_EXPOSED_HEADERS = [
  "X-Request-ID",
  "X-Correlation-ID",
  "Content-Type",
  "X-RateLimit-Limit",
  "X-RateLimit-Remaining",
  "X-RateLimit-Reset",
  "X-API-Version",
];

/** Preflight cache lifetime in seconds. Browsers cap this themselves. */
export const DEFAULT_CORS_MAX_AGE = 86400;

/**
 * Parse the geo-distributed read replica topology (#1051).
 *
 * Accepts a JSON object mapping region names to replica endpoints, e.g.
 * `{"us":"https://us.db.example.com","eu":"https://eu.db.example.com"}`.
 * A plain comma-separated list of `region=url` pairs is also accepted so the
 * value stays readable in a shell. Invalid entries are dropped rather than
 * throwing, so one malformed region cannot take down the whole server.
 *
 * @param {string|undefined} value
 * @returns {Object<string,string>} region (lowercased) -> endpoint URL
 */
function parseReplicaEndpoints(value) {
  if (!value) return {};
  const endpoints = {};
  const trimmed = String(value).trim();
  if (trimmed.startsWith("{")) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`Invalid JSON configuration: ${error.message}`);
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [region, url] of Object.entries(parsed)) {
        if (typeof url === "string" && url.trim()) {
          endpoints[region.trim().toLowerCase()] = url.trim();
        }
      }
    }
    return endpoints;
  }
  for (const pair of trimmed.split(",")) {
    const [region, ...rest] = pair.split("=");
    const url = rest.join("=").trim();
    if (region && region.trim() && url) {
      endpoints[region.trim().toLowerCase()] = url;
    }
  }
  return endpoints;
}

/**
 * Parse the region -> nearest-replica routing table (#1051).
 *
 * Accepts a JSON object or `region=replicaRegion` pairs, e.g.
 * `{"us-east-1":"us","eu-west-1":"eu"}`. Keys are lowercased so lookups can
 * be case-insensitive.
 *
 * @param {string|undefined} value
 * @returns {Object<string,string>}
 */
function parseRegionRouting(value) {
  if (!value) return {};
  const routing = {};
  const trimmed = String(value).trim();
  if (trimmed.startsWith("{")) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`Invalid JSON configuration: ${error.message}`);
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [region, replica] of Object.entries(parsed)) {
        if (typeof replica === "string" && replica.trim()) {
          routing[region.trim().toLowerCase()] = replica.trim().toLowerCase();
        }
      }
    }
    return routing;
  }
  for (const pair of trimmed.split(",")) {
    const [region, ...rest] = pair.split("=");
    const replica = rest.join("=").trim();
    if (region && region.trim() && replica) {
      routing[region.trim().toLowerCase()] = replica.toLowerCase();
    }
  }
  return routing;
}

function parseThresholds(value, fallback = [30, 7, 1]) {
  if (!value) return fallback;
  try {
    if (typeof value === "string") {
      const parsed = value
        .split(",")
        .map((s) => Number.parseInt(s.trim(), 10))
        .filter((n) => Number.isFinite(n) && n > 0);
      return parsed.length > 0 ? parsed.sort((a, b) => b - a) : fallback;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV ?? "development";
  return {
    nodeEnv,
    // The deterministic mock API is opt-in and never enabled in production.
    mockApiEnabled: nodeEnv !== "production" && parseBoolean(env.MOCK_API_ENABLED, false),
    port: parseInteger(env.PORT, 3001),
    adminApiKey: env.ADMIN_API_KEY ?? "",
    adminIpAllowlist: parseList(env.ADMIN_IP_ALLOWLIST, []),
    // Production admin routes are unavailable until an explicit allowlist is
    // supplied. Set ADMIN_IP_ALLOWLIST_REQUIRED=false only for a deliberate
    // migration window; a configured list is always enforced.
    adminIpAllowlistRequired: parseBoolean(
      env.ADMIN_IP_ALLOWLIST_REQUIRED,
      nodeEnv === "production",
    ),
    adminActor: env.ADMIN_ACTOR ?? "admin",
    corsAllowedOrigins: parseCorsOrigins(
      env.CORS_ORIGIN ?? env.CORS_ALLOWED_ORIGINS,
      nodeEnv,
    ),
    corsCredentials: parseBoolean(env.CORS_CREDENTIALS, false),
    corsMethods: parseList(env.CORS_METHODS, DEFAULT_CORS_METHODS),
    corsAllowedHeaders: parseList(
      env.CORS_ALLOWED_HEADERS,
      DEFAULT_CORS_ALLOWED_HEADERS,
    ),
    corsExposedHeaders: parseList(
      env.CORS_EXPOSED_HEADERS,
      DEFAULT_CORS_EXPOSED_HEADERS,
    ),
    corsMaxAge: parseInteger(env.CORS_MAX_AGE, DEFAULT_CORS_MAX_AGE, true),
    maxBodyBytes: parseInteger(env.MAX_BODY_BYTES, 64 * 1024),
    // End-to-end encryption of sensitive credential data in transit (#1049).
    // Off by default: enabling it changes the response shape for the fields
    // listed in ENCRYPTION_SENSITIVE_FIELDS, so clients must be updated to
    // decrypt before this is switched on.
    encryptionEnabled: parseBoolean(env.ENCRYPTION_ENABLED, false),
    // Session keys are rotated on this interval; must be shorter than the
    // session TTL so a client always has a window in which its key is valid.
    encryptionKeyRotationSeconds: parseInteger(
      env.ENCRYPTION_KEY_ROTATION_SECONDS,
      DEFAULT_ENCRYPTION_KEY_ROTATION_SECONDS,
    ),
    encryptionSessionTtlSeconds: parseInteger(
      env.ENCRYPTION_SESSION_TTL_SECONDS,
      DEFAULT_ENCRYPTION_SESSION_TTL_SECONDS,
    ),
    encryptionSensitiveFields: parseList(
      env.ENCRYPTION_SENSITIVE_FIELDS,
      DEFAULT_ENCRYPTION_SENSITIVE_FIELDS,
    ),
    // HMAC request signing (#752). Off by default: turning it on is a
    // breaking change for existing clients, which must be given their signing
    // secrets before their requests start being rejected.
    requestSigningEnabled: parseBoolean(env.REQUEST_SIGNING_ENABLED, false),
    // "mutations" signs POST/PUT/PATCH/DELETE only, which is where replay
    // actually causes damage; "all" additionally covers reads.
    requestSigningEnforce:
      (env.REQUEST_SIGNING_ENFORCE ?? "mutations").toLowerCase() === "all" ? "all" : "mutations",
    requestSigningMaxAgeSeconds: parseInteger(env.REQUEST_SIGNING_MAX_AGE_SECONDS, 300),
    // Nonce-based replay prevention (#1052). Off by default for the same
    // reason as request signing: enabling it rejects requests from clients
    // that do not yet send a nonce.
    requestNonceEnabled: parseBoolean(env.REQUEST_NONCE_ENABLED, false),
    // How long a used nonce is remembered in Redis. Falls back to the signing
    // max-age so the two windows stay aligned unless set explicitly.
    requestNonceTtlSeconds: parseInteger(
      env.REQUEST_NONCE_TTL_SECONDS ?? env.REQUEST_SIGNING_MAX_AGE_SECONDS,
      300,
    ),
    // Response header carrying the server-issued nonce for the next request.
    requestNonceHeader: env.REQUEST_NONCE_HEADER ?? "X-Nonce",
    // Content Security Policy (#754). Report-only by default: an enforced
    // policy that is even slightly too tight breaks the page, so a deployment
    // should watch reports first and switch to enforcing once they are clean.
    cspEnabled: parseBoolean(env.CSP_ENABLED, true),
    cspReportOnly: parseBoolean(env.CSP_REPORT_ONLY, true),
    cspReportUri: env.CSP_REPORT_URI ?? "/csp-report",
    // Extra trusted sources merged into the baseline directives. Each is a
    // comma-separated list of origins, e.g. "https://cdn.example.org".
    cspScriptSrc: parseList(env.CSP_SCRIPT_SRC, []),
    cspStyleSrc: parseList(env.CSP_STYLE_SRC, []),
    cspConnectSrc: parseList(env.CSP_CONNECT_SRC, []),
    cspImgSrc: parseList(env.CSP_IMG_SRC, []),
    cspFontSrc: parseList(env.CSP_FONT_SRC, []),
    cspFormAction: parseList(env.CSP_FORM_ACTION, []),
    cspFrameAncestors: parseList(env.CSP_FRAME_ANCESTORS, []),
    // W3C Verifiable Credentials JSON-LD (#753).
    // Base context: the v1.1 data model by default; set to the v2 URI to emit
    // v2 credentials (which renames issuanceDate/expirationDate).
    vcBaseContext:
      env.VC_BASE_CONTEXT ?? "https://www.w3.org/2018/credentials/v1",
    // Additional contexts appended to every credential, for a deployment with
    // its own vocabulary.
    vcExtraContexts: parseList(env.VC_EXTRA_CONTEXTS, []),
    // Public base URL. When set, credential and status ids are resolvable
    // https URLs instead of urn: identifiers.
    vcBaseUrl: env.VC_BASE_URL ?? "",
    // 32-byte Ed25519 seed (hex or base64) used to sign credentials. Without
    // it credentials are emitted unsigned rather than carrying a fake proof.
    vcProofPrivateKey: env.VC_PROOF_PRIVATE_KEY ?? "",
    // Defaults to "<issuer DID>#key-1" when unset.
    vcProofVerificationMethod: env.VC_PROOF_VERIFICATION_METHOD ?? "",
    dataDir: env.DATA_DIR ? path.resolve(env.DATA_DIR) : DEFAULT_DATA_DIR,
    auditLogPath: env.AUDIT_LOG_PATH
      ? path.resolve(env.AUDIT_LOG_PATH)
      : path.join(DEFAULT_DATA_DIR, "audit"),
    auditLogRetentionDays: parseInteger(env.AUDIT_LOG_RETENTION_DAYS, 30),
    credentialStorePath: env.CREDENTIAL_STORE_PATH
      ? path.resolve(env.CREDENTIAL_STORE_PATH)
      : path.join(DEFAULT_DATA_DIR, "credentials.json"),
    rateLimitWhitelist: (env.RATE_LIMIT_WHITELIST ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
    rateLimitMaxBuckets: parseInteger(env.RATE_LIMIT_MAX_BUCKETS, 10000),
    // #956: per-IP and per-user token buckets, plus premium bypass.
    rateLimitIpPerMinute: parseInteger(env.RATE_LIMIT_IP_PER_MINUTE, 300),
    rateLimitIpBurst: parseInteger(env.RATE_LIMIT_IP_BURST, 60),
    rateLimitUserPerMinute: parseInteger(env.RATE_LIMIT_USER_PER_MINUTE, 600),
    rateLimitUserBurst: parseInteger(env.RATE_LIMIT_USER_BURST, 120),
    rateLimitPremiumTiers: (env.RATE_LIMIT_PREMIUM_TIERS ?? "premium,enterprise")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
    rateLimitPremiumKeys: (env.RATE_LIMIT_PREMIUM_KEYS ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
    trustProxy: env.TRUST_PROXY === "true",
    ddosProtectionEnabled: parseBoolean(env.DDOS_PROTECTION_ENABLED, false),
    ddosWindowMs: parseInteger(env.DDOS_WINDOW_MS, 60_000),
    ddosMaxRequestsPerIp: parseInteger(env.DDOS_MAX_REQUESTS_PER_IP, 120),
    ddosMaxConnectionsPerIp: parseInteger(env.DDOS_MAX_CONNECTIONS_PER_IP, 20),
    ddosSuspiciousThreshold: parseInteger(env.DDOS_SUSPICIOUS_THRESHOLD, 96),
    ddosCaptchaEnabled: parseBoolean(env.DDOS_CAPTCHA_ENABLED, false),
    ddosCaptchaSecret: env.DDOS_CAPTCHA_SECRET ?? "",
    ddosCaptchaUrl: env.DDOS_CAPTCHA_URL ?? "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    ddosBlockedRegions: parseList(env.DDOS_BLOCKED_REGIONS, []),
    redisUrl: env.REDIS_URL ?? "",
    didCacheTtlMs: parseInteger(env.DID_CACHE_TTL_MS, 60 * 1000),
    redisMaxRetries: parseInteger(env.REDIS_MAX_RETRIES, 5),
    redisRetryBaseMs: parseInteger(env.REDIS_RETRY_BASE_MS, 200),
    redisCommandTimeoutMs: parseInteger(env.REDIS_COMMAND_TIMEOUT_MS, 1000),
    redisEnableAutoReconnect: env.REDIS_ENABLE_AUTO_RECONNECT !== "false",
    redisReconnectDelayMs: parseInteger(env.REDIS_RECONNECT_DELAY_MS, 1000),
    cacheFailureThreshold: parseInteger(env.CACHE_FAILURE_THRESHOLD, 3),
    didCacheWarmList: (env.DID_CACHE_WARM_LIST ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
    // Multi-layer caching strategy (#1118).
    // L1: in-process LRU cache. CACHE_L1_MAX_ENTRIES=0 disables L1.
    cacheL1Enabled: parseBoolean(env.CACHE_L1_ENABLED, true),
    cacheL1MaxEntries: parseInteger(env.CACHE_L1_MAX_ENTRIES, 1000, true),
    cacheL1DefaultTtlMs: parseInteger(env.CACHE_L1_DEFAULT_TTL_MS, 30_000),
    // L2: Redis-backed shared cache. TTLs are per data type so volatile data
    // (e.g. balances) is not held as long as stable data (e.g. DIDs).
    cacheL2Enabled: parseBoolean(env.CACHE_L2_ENABLED, true),
    cacheL2KeyPrefix: env.CACHE_L2_KEY_PREFIX ?? "cache:",
    cacheL2TtlDefaultMs: parseInteger(env.CACHE_L2_TTL_DEFAULT_MS, 60_000),
    cacheL2TtlDidMs: parseInteger(env.CACHE_L2_TTL_DID_MS, 60_000),
    cacheL2TtlCredentialMs: parseInteger(env.CACHE_L2_TTL_CREDENTIAL_MS, 30_000),
    cacheL2TtlVerificationMs: parseInteger(env.CACHE_L2_TTL_VERIFICATION_MS, 10_000),
    cacheL2TtlApiResponseMs: parseInteger(env.CACHE_L2_TTL_API_RESPONSE_MS, 5_000),
    cacheL2TtlSessionMs: parseInteger(env.CACHE_L2_TTL_SESSION_MS, 300_000),
    cacheL2TtlAnalyticsMs: parseInteger(env.CACHE_L2_TTL_ANALYTICS_MS, 600_000),
    // L3: CDN. Purging is opt-in; without a purge URL the CDN is assumed to
    // expire entries on its own TTL.
    cacheL3Enabled: parseBoolean(env.CACHE_L3_ENABLED, false),
    cacheL3PurgeUrl: env.CACHE_L3_PURGE_URL ?? "",
    cacheL3PurgeToken: env.CACHE_L3_PURGE_TOKEN ?? "",
    cacheL3PurgeTimeoutMs: parseInteger(env.CACHE_L3_PURGE_TIMEOUT_MS, 5000),
    // Cache warming: a cron schedule (empty disables) plus the list of keys
    // to preload on startup and on each scheduled run.
    cacheWarmEnabled: parseBoolean(env.CACHE_WARM_ENABLED, false),
    cacheWarmCronSchedule: env.CACHE_WARM_CRON_SCHEDULE ?? "",
    cacheWarmKeys: parseList(env.CACHE_WARM_KEYS, []),
    cacheWarmOnStartup: parseBoolean(env.CACHE_WARM_ON_STARTUP, true),
    // Stampede prevention: a per-key lock so only one caller recomputes a
    // missing entry while the rest wait (or serve stale) instead of all
    // hammering the origin at once.
    cacheStampedeLockTtlMs: parseInteger(env.CACHE_STAMPEDE_LOCK_TTL_MS, 5000),
    cacheStampedeWaitTimeoutMs: parseInteger(env.CACHE_STAMPEDE_WAIT_TIMEOUT_MS, 2000),
    cacheStampedeServeStale: parseBoolean(env.CACHE_STAMPEDE_SERVE_STALE, true),
    // Hit-rate monitoring: per-layer counters exposed on the metrics endpoint.
    cacheMetricsEnabled: parseBoolean(env.CACHE_METRICS_ENABLED, true),
    cacheMetricsLogIntervalMs: parseInteger(
      env.CACHE_METRICS_LOG_INTERVAL_MS,
      60_000,
      true,
    ),
    // API usage metering and billing (#1119).
    meteringEnabled: parseBoolean(env.METERING_ENABLED, false),
    // Where usage records are persisted (JSONL append log).
    usageStoragePath: env.USAGE_STORAGE_PATH
      ? path.resolve(env.USAGE_STORAGE_PATH)
      : path.join(DEFAULT_DATA_DIR, "usage"),
    // Tier definitions: name -> monthly included calls and per-call overage
    // price in cents. Overridable as JSON so pricing can change without a
    // deploy; the defaults mirror the documented Free/Pro/Enterprise tiers.
    billingTiers: parseJson(env.BILLING_TIERS, {
      free: { monthlyCalls: 1000, overageCentsPerCall: 0, custom: false },
      pro: { monthlyCalls: 50000, overageCentsPerCall: 1, custom: false },
      enterprise: { monthlyCalls: 0, overageCentsPerCall: 0, custom: true },
    }),
    billingDefaultTier: (env.BILLING_DEFAULT_TIER ?? "free").trim().toLowerCase(),
    // Stripe integration. Without a secret key invoices are generated but
    // never charged, so a deployment can meter usage before billing is live.
    stripeApiKey: env.STRIPE_API_KEY ?? "",
    stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET ?? "",
    stripeApiBaseUrl: env.STRIPE_API_BASE_URL ?? "https://api.stripe.com",
    stripeTimeoutMs: parseInteger(env.STRIPE_TIMEOUT_MS, 10_000),
    // Monthly invoice generation. Empty schedule falls back to the 1st of the
    // month at midnight.
    invoiceCronSchedule: env.INVOICE_CRON_SCHEDULE ?? "0 0 1 * *",
    invoiceCurrency: (env.INVOICE_CURRENCY ?? "usd").trim().toLowerCase(),
    // Overage alerts: warn once usage crosses these percentages of the
    // tier's included quota.
    usageAlertThresholds: parseThresholds(env.USAGE_ALERT_THRESHOLDS, [80, 100]),
    usageAlertWebhookUrl: env.USAGE_ALERT_WEBHOOK_URL ?? "",
    // Usage-based discounts: percentage off the overage charge once a
    // customer's monthly call volume reaches the given threshold.
    usageDiscountTiers: parseJson(env.USAGE_DISCOUNT_TIERS, []),
    healthProbeTimeoutMs: parseInteger(env.HEALTH_PROBE_TIMEOUT_MS, 2000),
    redisUrl: env.REDIS_URL ?? "",
    accessLogEnabled: env.ACCESS_LOG_ENABLED !== "false",
    accessLogPath: env.ACCESS_LOG_PATH ?? "",
    accessLogMaxBytes: parseInteger(env.ACCESS_LOG_MAX_BYTES, 10 * 1024 * 1024),
    accessLogMaxFiles: parseInteger(env.ACCESS_LOG_MAX_FILES, 5),
    logPayloads: env.LOG_PAYLOADS === "true",
    logHeaders: env.LOG_HEADERS === "true",
    logPayloadMaxBytes: parseInteger(env.LOG_PAYLOAD_MAX_BYTES, 2048),
    trustProxy: env.TRUST_PROXY === "true",
    expiryWarningDays: parseInteger(env.EXPIRY_WARNING_DAYS, 7),
    expiryReminderThresholds: parseThresholds(
      env.EXPIRY_REMINDER_THRESHOLDS,
      [30, 7, 1],
    ),
    expiryJobIntervalMs: parseInteger(
      env.EXPIRY_JOB_INTERVAL_MS,
      60 * 60 * 1000,
    ),
    expiryConcurrency: parseInteger(env.EXPIRY_CONCURRENCY, 8),
    expiryCronSchedule: env.EXPIRY_CRON_SCHEDULE ?? "",
    notificationWebhookUrl: env.NOTIFICATION_WEBHOOK_URL ?? "",
    subjectNotificationWebhooks: parseJson(
      env.SUBJECT_NOTIFICATION_WEBHOOKS,
      {},
    ),
    emailApiUrl: env.EMAIL_API_URL ?? "",
    emailApiKey: env.EMAIL_API_KEY ?? "",
    emailFrom: env.EMAIL_FROM ?? "",
    notificationEmail: env.NOTIFICATION_EMAIL ?? "",
    subjectNotificationEmails: parseJson(env.SUBJECT_NOTIFICATION_EMAILS, {}),
    notificationMaxRetries: parseInteger(env.NOTIFICATION_MAX_RETRIES, 3),
    notificationRetryBaseMs: parseInteger(env.NOTIFICATION_RETRY_BASE_MS, 500),
    // SOROBAN_POOL_SIZE=0 disables the pool (allowZero: true)
    poolSize: parseInteger(env.SOROBAN_POOL_SIZE, 4, true),
    sorobanInvokeTimeoutMs: parseInteger(env.SOROBAN_INVOKE_TIMEOUT_MS, 10000),
    stellarCli: env.STELLAR_CLI ?? "stellar",
    sourceAccount: resolveSourceAccount(env),
    network: env.STELLAR_NETWORK ?? "testnet",
    rpcUrl: env.STELLAR_RPC_URL ?? env.RPC_URL ?? "https://soroban-testnet.stellar.org",
    rpcCacheTtlMs: parseInteger(env.RPC_CACHE_TTL_MS, 5000),
    queryCacheEnabled: parseBoolean(env.QUERY_CACHE_ENABLED, true),
    queryCacheDefaultTtlMs: parseInteger(env.QUERY_CACHE_DEFAULT_TTL_MS, 5000),
    queryCacheTtlVolatileMs: parseInteger(env.QUERY_CACHE_TTL_VOLATILE_MS, 1000),
    queryCacheTtlStableMs: parseInteger(env.QUERY_CACHE_TTL_STABLE_MS, 60_000),
    queryCacheWarmQueries: parseJson(env.QUERY_CACHE_WARM_QUERIES, []),
    // RPC_MAX_RETRIES=0 disables retries (allowZero: true)
    rpcMaxRetries: parseInteger(env.RPC_MAX_RETRIES, 3, true),
    rpcRetryBaseMs: parseInteger(env.RPC_RETRY_BASE_MS, 500),
    rpcRetryBackoff: parseInteger(env.RPC_RETRY_BACKOFF, 2),
    // Circuit breaker configuration (#715)
    circuitBreakerFailureThreshold: parseInteger(env.CIRCUIT_BREAKER_FAILURE_THRESHOLD, 5),
    circuitBreakerSuccessThreshold: parseInteger(env.CIRCUIT_BREAKER_SUCCESS_THRESHOLD, 2),
    circuitBreakerOpenDurationMs: parseInteger(env.CIRCUIT_BREAKER_OPEN_DURATION_MS, 30_000),
    circuitBreakerTimeoutMs: parseInteger(env.CIRCUIT_BREAKER_TIMEOUT_MS, 10_000, true),
    circuitBreakerEnabled: parseBoolean(env.CIRCUIT_BREAKER_ENABLED, true),
    // EVENT_POLL_INTERVAL_MS=0 disables the event poller (allowZero: true)
    eventPollIntervalMs: parseInteger(env.EVENT_POLL_INTERVAL_MS, 5000, true),
    // #750: GET /events/poll long-polling. Timeout is clamped to
    // [1s, longPollMaxTimeoutMs] regardless of what a caller requests.
    longPollDefaultTimeoutMs: parseInteger(env.LONG_POLL_DEFAULT_TIMEOUT_MS, 30_000),
    longPollMaxTimeoutMs: parseInteger(env.LONG_POLL_MAX_TIMEOUT_MS, 60_000),
    // #748: whether a request over its daily/monthly quota is rejected
    // ("block") or let through flagged as overage ("allow").
    quotaOverageMode: (env.QUOTA_OVERAGE_MODE ?? "block").toLowerCase() === "allow" ? "allow" : "block",
    // WS_ENABLED=false turns the WebSocket endpoint off entirely
    wsEnabled: (env.WS_ENABLED ?? "true").toLowerCase() !== "false",
    wsPath: env.WS_PATH ?? "/ws",
    wsMessageLimit: parseInteger(env.WS_MESSAGE_LIMIT, 60),
    wsMessageWindowMs: parseInteger(env.WS_MESSAGE_WINDOW_MS, 60_000),
    // WS_HEARTBEAT_INTERVAL_MS=0 disables heartbeats (allowZero: true)
    wsHeartbeatIntervalMs: parseInteger(env.WS_HEARTBEAT_INTERVAL_MS, 30_000, true),
    // Response compression (#721)
    compressionEnabled: parseBoolean(env.COMPRESSION_ENABLED, true),
    compressionThreshold: parseInteger(env.COMPRESSION_THRESHOLD, 1024),
    compressionGzipLevel: parseInteger(env.COMPRESSION_GZIP_LEVEL, 6),
    compressionBrotliLevel: parseInteger(env.COMPRESSION_BROTLI_LEVEL, 4),
    compressionEnableBrotli: parseBoolean(env.COMPRESSION_ENABLE_BROTLI, true),
    // Graceful shutdown (#722)
    shutdownTimeoutMs: parseInteger(env.SHUTDOWN_TIMEOUT_MS, 30000),
    // Database connection pooling (#718)
    dbPoolMinSize: parseInteger(env.DB_POOL_MIN_SIZE, 2),
    dbPoolMaxSize: parseInteger(env.DB_POOL_MAX_SIZE, 10),
    dbPoolConnectionTimeoutMs: parseInteger(env.DB_POOL_CONNECTION_TIMEOUT_MS, 5000),
    dbPoolIdleTimeoutMs: parseInteger(env.DB_POOL_IDLE_TIMEOUT_MS, 30000),
    dbPoolMaxConnectionAgeMs: parseInteger(env.DB_POOL_MAX_CONNECTION_AGE_MS, 3600000),
    dbPoolHealthCheckIntervalMs: parseInteger(env.DB_POOL_HEALTH_CHECK_INTERVAL_MS, 30000),
    // #1325 BUG-28: session timezone applied to every DB connection so all
    // stored timestamps are UTC regardless of the server's local timezone.
    dbTimezone: resolveDbTimezone(env),
    // Job queue for async processing (#716)
    jobQueueEnabled: parseBoolean(env.JOB_QUEUE_ENABLED, true),
    jobQueueConcurrency: parseInteger(env.JOB_QUEUE_CONCURRENCY, 4),
    jobQueueMaxRetries: parseInteger(env.JOB_QUEUE_MAX_RETRIES, 3),
    jobQueueRetryBackoffMs: parseInteger(env.JOB_QUEUE_RETRY_BACKOFF_MS, 1000),
    jobQueueProcessingTimeoutMs: parseInteger(env.JOB_QUEUE_PROCESSING_TIMEOUT_MS, 30000),
    credentialIssueQueueEnabled: parseBoolean(env.CREDENTIAL_ISSUE_QUEUE_ENABLED, true),
    batchVerificationQueueEnabled: parseBoolean(env.BATCH_VERIFICATION_QUEUE_ENABLED, true),
    contracts: {
      identity: env.IDENTITY_REGISTRY_ID ?? "",
      credential: env.CREDENTIAL_CONTRACT_ID ?? env.CREDENTIAL_MANAGER_ID ?? "",
      reputation: env.REPUTATION_ID ?? "",
    },
    // Geo-distributed read replicas (#1051). Replicas are opt-in: with no
    // endpoints configured every query goes to the primary, so an existing
    // single-region deployment is unaffected.
    readReplicasEnabled: parseBoolean(env.READ_REPLICAS_ENABLED, false),
    // Region -> replica endpoint, e.g. {"us":"https://us