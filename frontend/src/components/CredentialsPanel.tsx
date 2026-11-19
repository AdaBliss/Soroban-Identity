import { useState, useEffect, useReducer, useRef, lazy, Suspense } from "react";
import { StrKey, SorobanRpc, TransactionBuilder, BASE_FEE, nativeToScVal, Contract, scValToNative } from '@stellar/stellar-sdk';
import type { CredentialType, Credential, RevocationReason, VerifyResult } from "../../../sdk/src/types";
import { REVOCATION_REASONS } from "../../../sdk/src/types";
import { CredentialClient } from '../../../sdk/src';
import { validateStellarAddress } from "../../../sdk/src/utils";
import { getNetworkConfig } from '../network';
import SkeletonCard from "./SkeletonCard";
import FormField from "./FormField";
import { formatTimestamp } from "../utils/formatDate";
import { handleError } from "../utils/handleError";
import { useWalletContext } from "../context/WalletContext";
import { useToast } from "../context/ToastContext";
import TemplateSelector from "../templates/TemplateSelector";
import BrowserExtensionBanner from "./BrowserExtensionBanner";
import { type CredentialTemplate, validateClaimsAgainstTemplate } from "../templates/credentialTemplates";
import { exportCredentialsAsCSV, downloadExport } from "../utils/exportCredentials";
import {
  exportBatch,
  downloadFile,
  allTemplates,
  saveCustomTemplates,
  type BatchMode,
  type ExportTemplate,
} from "../export";
import LoadingFallback from "./LoadingFallback";
import AdvancedSearch, { type AdvancedSearchHandle } from "./AdvancedSearch";
import type { SearchResult } from "../search/searchEngine";

// ── Lazy-loaded components for code-splitting (#854) ─────────────────────────
// These credential components are loaded on-demand to reduce initial bundle size

const CredentialImport = lazy(() => import("./CredentialImport"));
const CredentialTimeline = lazy(() => import("./CredentialTimeline"));
const CredentialShare = lazy(() => import("./CredentialShare"));
const CredentialComparison = lazy(() => import("./CredentialComparison"));
const PrivacySettings = lazy(() => import("./PrivacySettings"));
const TemplateEditor = lazy(() => import("../export/TemplateEditor"));

// Preload functions for hover/focus to improve perceived performance
const preloadCredentialImport = () => void import("./CredentialImport");
const preloadCredentialTimeline = () => void import("./CredentialTimeline");
const preloadCredentialShare = () => void import("./CredentialShare");
const preloadCredentialComparison = () => void import("./CredentialComparison");
const preloadPrivacySettings = () => void import("./PrivacySettings");
const preloadTemplateEditor = () => void import("../export/TemplateEditor");

type ExportFormat = "json" | "csv" | "xml" | "pdf";

type VerifyState =
  | "idle"
  | "valid"
  | "not_found"
  | "revoked"
  | "expired"
  | "not_yet_active"
  | "invalid"
  | "unknown";

type FilterType = "All" | CredentialType;
type ExpiryFilterType = "All" | "Active" | "Expired";
type CredentialStatus = "active" | "expired" | "revoked";

// ── #1101: Credential privacy controls ──────────────────────────────────────
type CredentialVisibility = "public" | "private" | "custom";

interface CredentialPrivacySettings {
  visibility: CredentialVisibility;
  /** Claim keys that are disclosed when visibility is "custom". */
  disclosedAttributes: string[];
  /** Trusted verifier addresses allowed to view the credential. */
  whitelist: string[];
  /** Optional expiry (unix seconds) for sharing links; 0 = no expiry. */
  shareExpiry: number;
}

const PRIVACY_STORAGE_PREFIX = "credential-privacy:";

const DEFAULT_PRIVACY_SETTINGS: CredentialPrivacySettings = {
  visibility: "private",
  disclosedAttributes: [],
  whitelist: [],
  shareExpiry: 0,
};

function loadPrivacySettings(credentialId: string): CredentialPrivacySettings {
  try {
    const raw = localStorage.getItem(`${PRIVACY_STORAGE_PREFIX}${credentialId}`);
    if (!raw) return DEFAULT_PRIVACY_SETTINGS;
    const parsed = JSON.parse(raw) as Partial<CredentialPrivacySettings>;
    return {
      visibility:
        parsed.visibility === "public" || parsed.visibility === "custom" || parsed.visibility === "private"
          ? parsed.visibility
          : DEFAULT_PRIVACY_SETTINGS.visibility,
      disclosedAttributes: Array.isArray(parsed.disclosedAttributes) ? parsed.disclosedAttributes : [],
      whitelist: Array.isArray(parsed.whitelist) ? parsed.whitelist : [],
      shareExpiry: typeof parsed.shareExpiry === "number" ? parsed.shareExpiry : 0,
    };
  } catch {
    return DEFAULT_PRIVACY_SETTINGS;
  }
}

function savePrivacySettings(credentialId: string, settings: CredentialPrivacySettings): void {
  try {
    localStorage.setItem(`${PRIVACY_STORAGE_PREFIX}${credentialId}`, JSON.stringify(settings));
  } catch {
    // Storage may be unavailable (private mode / quota) — privacy controls
    // still work for the current session, so fail silently.
  }
}

const VISIBILITY_BADGE: Record<CredentialVisibility, { label: string; icon: string; className: string }> = {
  public: { label: "Public", icon: "🌐", className: "badge badge-green" },
  private: { label: "Private", icon: "🔒", className: "badge badge-red" },
  custom: { label: "Custom", icon: "🎛", className: "badge badge-yellow" },
};

const MAX_SAFE_TIMESTAMP_SECS = 8_640_000_000_000; // Max ECMAScript Date in seconds (~year 275760)
const MAX_U64_TIMESTAMP = 18_446_744_073_709_551_615n;

function normalizeExpiryTimestamp(expiresAt: number | bigint | string): number {
  if (typeof expiresAt === "bigint") {
    if (expiresAt <= 0n) return 0;
    return expiresAt > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(expiresAt);
  }
  const num = typeof expiresAt === "string" ? Number(expiresAt) : expiresAt;
  if (!Number.isFinite(num)) return 0;
  // Recover from signed 32-bit integer overflow (e.g. dates past 2038/2106 coerced via bitwise ops)
  if (num < 0) {
    return num + 0x100000000;
  }
  return num;
}

function formatExpiry(expiresAt: number | bigint | string): string {
  const normalized = normalizeExpiryTimestamp(expiresAt);
  if (normalized === 0) return "No expiry";

  const nowSec = Math.floor(Date.now() / 1000);
  const diffSec = normalized - nowSec;
  const absSec = Math.abs(diffSec);
  const diffDays = Math.floor(absSec / (60 * 60 * 24));
  const diffHours = Math.floor(absSec / (60 * 60));
  const diffMinutes = Math.floor(absSec / 60);
  if (diffSec < 0) {
    if (diffDays > 0) return `Expired ${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
    if (diffHours > 0) return `Expired ${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
    return `Expired ${diffMinutes} min${diffMinutes > 1 ? "s" : ""} ago`;
  }

  if (diffDays > 0) return `Expires in ${diffDays} day${diffDays > 1 ? "s" : ""}`;
  if (diffHours > 0) return `Expires in ${diffHours} hour${diffHours > 1 ? "s" : ""}`;
  return `Expires in ${diffMinutes} min${diffMinutes > 1 ? "s" : ""}`;
}

function getExpiryStyle(expiresAt: number | bigint): React.CSSProperties {
  const sec = normalizeExpiryTimestamp(expiresAt);
  if (sec === 0) return { color: "var(--text-muted)" };

  const nowSec = Math.floor(Date.now() / 1000);
  const diffSec = sec - nowSec;
  const diffDays = Math.floor(Math.abs(diffSec) / (60 * 60 * 24));

  if (diffSec < 0) {
    return { color: "var(--error)", fontWeight: 600 };
  }
  if (diffDays <= 7) {
    return { color: "var(--warning)", fontWeight: 600 };
  }
  return { color: "var(--text-muted)" };
}

function isExpired(expiresAt: number | bigint): boolean {
  const normalized = normalizeExpiryTimestamp(expiresAt);
  return normalized > 0 && Math.floor(Date.now() / 1000) > normalized;
}

function getCredentialStatus(credential: Credential): CredentialStatus {
  if (credential.revoked) return "revoked";
  if (isExpired(credential.expiresAt)) return "expired";
  return "active";
}

function getStatusBadgeClass(status: CredentialStatus): string {
  if (status === "revoked") return "badge badge-red";
  if (status === "expired") return "badge badge-yellow";
  return "badge badge-green";
}

function getStatusLabel(status: CredentialStatus): string {
  if (status === "revoked") return "Revoked";
  if (status === "expired") return "Expired";
  return "Active";
}

function getStatusTooltip(credential: Credential, status: CredentialStatus): string {
  if (status === "revoked") return "This credential has been revoked by the issuer and is no longer valid.";
  if (status === "expired") return `This credential expired on ${formatTimestamp(credential.expiresAt)}.`;
  return credential.expiresAt === 0
    ? "This credential is valid and does not expire."
    : `This credential is valid until ${formatTimestamp(credential.expiresAt)}.`;
}

const STATUS_REFRESH_INTERVAL_MS = 30_000;

function formatCheckedAt(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

function getStatusSortRank(credential: Credential): number {
  const status = getCredentialStatus(credential);
  if (status === "active") return 0;
  if (status === "expired") return 1;
  return 2;
}

// TODO: integrate SDK — replace with CredentialClient.getCredentialsBySubject() (see issue #226)

const FILTER_OPTIONS: FilterType[] = ["All", "Kyc", "Reputation", "Achievement", "Custom"];
const EXPIRY_FILTER_OPTIONS: ExpiryFilterType[] = ["All", "Active", "Expired"];

const CREDENTIAL_TYPE_ICONS: Record<CredentialType, string> = {
  Kyc: "🆔",
  Reputation: "⭐",
  Achievement: "🏆",
  Custom: "📋",
};

function countByType(creds: Credential[], type: FilterType): number {
  if (type === "All") return creds.length;
  return creds.filter((c) => c.credentialType === type).length;
}

function countByExpiry(creds: Credential[], filter: ExpiryFilterType): number {
  if (filter === "All") return creds.length;
  if (filter === "Active") return creds.filter((c) => !isExpired(c.expiresAt) && !c.revoked).length;
  if (filter === "Expired") return creds.filter((c) => isExpired(c.expiresAt) || c.revoked).length;
  return creds.length;
}

function CredentialEmptyState({ searchedAddress }: { searchedAddress: string | null }) {
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "0.75rem",
        minHeight: "12rem",
        padding: "2.5rem 1rem",
        textAlign: "center",
        color: "var(--text-muted)",
      }}
    >
      <svg
        width="56"
        height="56"
        viewBox="0 0 56 56"
        fill="none"
        aria-hidden="true"
      >
        <rect
          x="10"
          y="8"
          width="36"
          height="40"
          rx="8"
          fill="var(--card-bg-accent)"
          stroke="var(--border-input)"
          strokeWidth="2"
        />
        <path
          d="M19 23h18M19 31h12"
          stroke="var(--accent-light)"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
        <circle
          cx="38"
          cy="38"
          r="7"
          fill="var(--card-bg)"
          stroke="var(--accent-light)"
          strokeWidth="2"
        />
        <path
          d="m35.5 38 1.8 1.8 3.7-4"
          stroke="var(--accent-light)"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <div>
        <h3 style={{ margin: "0 0 0.35rem", color: "var(--text)", fontSize: "1rem" }}>
          No credentials yet
        </h3>
        <p style={{ margin: 0, fontSize: "0.9rem", lineHeight: 1.5 }}>
          Credentials issued to your DID will appear here.
        </p>
        {searchedAddress && (
          <p style={{ margin: "0.35rem 0 0", fontSize: "0.8rem", lineHeight: 1.4 }}>
            Searched account {searchedAddress.slice(0, 6)}...{searchedAddress.slice(-4)}
          </p>
        )}
      </div>
    </div>
  );
}

type CredentialState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; credentials: Credential[]; searchedAddress: string }
  | { status: 'error'; message: string };

type CredentialAction =
  | { type: 'FETCH_START' }
  | { type: 'FETCH_SUCCESS'; credentials: Credential[]; searchedAddress: string }
  | { type: 'FETCH_ERROR'; message: string }
  | { type: 'RESET' };

function credentialReducer(_state: CredentialState, action: CredentialAction): CredentialState {
  switch (action.type) {
    case 'FETCH_START': return { status: 'loading' };
    case 'FETCH_SUCCESS': return { status: 'success', credentials: action.credentials, searchedAddress: action.searchedAddress };
    case 'FETCH_ERROR': return { status: 'error', message: action.message };
    case 'RESET': return { status: 'idle' };
  }
}

export default function CredentialsPanel({ verifyId, wallet: propWallet }: { verifyId?: string | null; wallet?: any } = {}) {
  const contextWallet = useWalletContext();
  const wallet = propWallet ?? contextWallet;
  const toast = useToast();
  const [credentialState, dispatchCredential] = useReducer(credentialReducer, { status: 'idle' });

  const fetchedCredentials = credentialState.status === 'success' ? credentialState.credentials : null;
  const fetching = credentialState.status === 'loading';
  const searchedAddress = credentialState.status === 'success' ? credentialState.searchedAddress : null;

  const [credId, setCredId] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState>("idle");
  const [verifying, setVerifying] = useState(false);
  const [expandedCredId, setExpandedCredId] = useState<string | null>(null);

  const [subject, setSubject] = useState("");
  const [claims, setClaims] = useState<Array<{ key: string; value: string }>>([{ key: "", value: "" }]);
  const [expiresAt, setExpiresAt] = useState("0");
  const [issueResult, setIssueResult] = useState<string | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<CredentialTemplate | null>(null);
  const [issueErrors, setIssueErrors] = useState<Record<string, string>>({});

  const [activeFilter, setActiveFilter] = useState<FilterType>("All");
  const [activeExpiryFilter, setActiveExpiryFilter] = useState<ExpiryFilterType>("All");
  const [isIssuer, setIsIssuer] = useState(false);
  const [checkingIssuer, setCheckingIssuer] = useState(false);

  const jsonImportRef = useRef<HTMLInputElement>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [importedCount, setImportedCount] = useState<number | null>(null);
  const [revokeId, setRevokeId] = useState("");
  const [revokeReason, setRevokeReason] = useState<RevocationReason>("Compromised");
  const [revokeResult, setRevokeResult] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

  // ── #1303: Revocation submission guards ─────────────────────────────────
  // `revokingRef` is a synchronous in-flight flag so rapid double-clicks can't
  // start two revocations before React re-renders with `revoking === true`.
  // `revokeInFlightHashRef` tracks the hash of a transaction that has already
  // been broadcast so we never re-broadcast the same signed transaction.
  // `revokeSignedXdrRef` holds the last signed XDR; it is cleared whenever the
  // user rejects the signing prompt so a retry rebuilds a fresh transaction
  // instead of re-submitting the stale one (BUG-06).
  const revokingRef = useRef(false);
  const revokeInFlightHashRef = useRef<string | null>(null);
  const revokeSignedXdrRef = useRef<string | null>(null);

  const [searchAddress, setSearchAddress] = useState("");
  const [lastCheckedAt, setLastCheckedAt] = useState<number | null>(null);
  const [verifyCheckedAt, setVerifyCheckedAt] = useState<number | null>(null);

  // ── Advanced search (#1104) ─────────────────────────────────────────────
  // `searchResults` holds the ranked IDs produced by the advanced search
  // engine (null = no active query). Filters are applied on top of this set.
  const advancedSearchRef = useRef<AdvancedSearchHandle>(null);
  const [searchResults, setSearchResults] = useState<SearchResult<Credential>[] | null>(null);
  const searchResultIds = searchResults ? new Set(searchResults.map((r) => r.item.id)) : null;
  const searchHighlights = new Map<string, string[]>(
    (searchResults ?? []).map((r) => [r.item.id, r.highlights]),
  );
  const hasActiveSearch = searchResults !== null;

  // Import/Export state
  const [showImportModal, setShowImportModal] = useState(false);
  const [exportFormat, setExportFormat] = useState<ExportFormat>("json");
  const [exportBatchMode, setExportBatchMode] = useState<BatchMode>("combined");
  const [exportTemplates, setExportTemplates] = useState<ExportTemplate[]>(allTemplates);
  const [exportTemplateId, setExportTemplateId] = useState("standard");
  const [editingExportTemplate, setEditingExportTemplate] = useState(false);
  const exportTemplate = exportTemplates.find((t) => t.id === exportTemplateId) ?? exportTemplates[0];
  const [isExporting, setIsExporting] = useState(false);
  const [selectedCredentialsForExport, setSelectedCredentialsForExport] = useState<Set<string>>(new Set());
  const [sharingCredential, setSharingCredential] = useState<Credential | null>(null);

  // ── #1101: Privacy controls ─────────────────────────────────────────────
  // Privacy settings are persisted per credential in localStorage so they
  // survive reloads and are available to the share flow.
  const [privacySettings, setPrivacySettings] = useState<Record<string, CredentialPrivacySettings>>({});
  const [privacyCredential, setPrivacyCredential] = useState<Credential | null>(null);

  const getPrivacySettings = (credentialId: string): CredentialPrivacySettings =>
    privacySettings[credentialId] ?? loadPrivacySettings(credentialId);

  const handleSavePrivacySettings = (credentialId: string, settings: CredentialPrivacySettings) => {
    savePrivacySettings(credentialId, settings);
    setPrivacySettings((prev) => ({ ...prev, [credentialId]: settings }));
    toast.success("Privacy settings saved.");
  };

  // ── Credential comparison (#1048) ───────────────────────────────────────
  // Selection is separate from the export selection so the two features don't
  // interfere with each other. 2-4 credentials can be compared at once.
  const MIN_COMPARE = 2;
  const MAX_COMPARE = 4;
  const [selectedForComparison, setSelectedForComparison] = useState<Set<string>>(new Set());
  const [showComparison, setShowComparison] = useState(false);
  const [comparisonIds, setComparisonIds] = useState<string[]>([]);

  const toggleComparisonSelection = (credentialId: string) => {
    setSelectedForComparison((prev) => {
      const next = new Set(prev);
      if (next.has(credentialId)) {
        next.delete(credentialId);
      } else if (next.size < MAX_COMPARE) {
        next.add(credentialId);
      } else {
        toast.error(`You can compare at most ${MAX_COMPARE} credentials at once.`);
      }
      return next;
    });
  };

  const openComparison = (ids: string[]) => {
    if (ids.length < MIN_COMPARE || ids.length > MAX_COMPARE) {
      toast.error(`Select between ${MIN_COMPARE} and ${MAX_COMPARE} credentials to compare.`);
      return;
    }
    setComparisonIds(ids);
    setShowComparison(true);
  };

  // Shareable-link entry point: read `compare` credential IDs from the URL and
  // open the comparison view automatically once the credentials are available.
  const [pendingCompareIds] = useState<string[]>(() => {
    const raw = new URLSearchParams(window.location.search).get("compare");
    if (!raw) return [];
    return raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, MAX_COMPARE);
  });

  useEffect(() => {
    if (pendingCompareIds.length < MIN_COMPARE) return;
    if (displayCredentials.length === 0) return;
    const available = pendingCompareIds.filter((id) => displayCredentials.some((c) => c.id === id));
    if (available.length >= MIN_COMPARE) {
      setSelectedForComparison(new Set(available));
      setComparisonIds(available);
      setShowComparison(true);
    }
  }, [pendingCompareIds, fetchedCredentials]);

  // ── Pagination ──────────────────────────────────────────────────────────
  const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;
  const readIntParam = (name: string, fallback: number): number => {
    const raw = new URLSearchParams(window.location.search).get(name);
    const parsed = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  };
  const [page, setPage] = useState(() => readIntParam("page", 1));
  const [pageSize, setPageSize] = useState(() => {
    const fromUrl = readIntParam("pageSize", 10);
    return (PAGE_SIZE_OPTIONS as readonly number[]).includes(fromUrl) ? fromUrl : 10;
  });

  const updatePaginationParams = (nextPage: number, nextPageSize: number) => {
    const url = new URL(window.location.href);
    url.searchParams.set("page", String(nextPage));
    url.searchParams.set("pageSize", String(nextPageSize));
    window.history.replaceState({}, "", url);
  };

  const goToPage = (nextPage: number) => {
    setPage(nextPage);
    updatePaginationParams(nextPage, pageSize);
  };

  const handlePageSizeChange = (nextPageSize: number) => {
    setPageSize(nextPageSize);
    setPage(1);
    updatePaginationParams(1, nextPageSize);
  };

  // Reused across calls instead of instantiating a fresh CredentialClient (and its
  // own RequestQueue + health check) on every verify/search/issuer-check — see #612.
  const credentialClientRef = useRef<CredentialClient | null>(null);
  const getCredentialClient = () => {
    if (!credentialClientRef.current) {
      credentialClientRef.current = new CredentialClient(getNetworkConfig());
    }
    return credentialClientRef.current;
  };
  useEffect(() => {
    return () => {
      credentialClientRef.current?.dispose();
      credentialClientRef.current = null;
    };
  }, []);

  // ── #737: JSON credential import handler ───────────────────────────────
  // Wraps JSON.parse in a try/catch so a malformed file shows a user-friendly
  // validation error instead of crashing the component. The file input is
  // reset after every attempt so the same file can be re-selected after fixing.
  const handleJsonImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    setImportedCount(null);

    const file = e.target.files?.[0];
    if (!file) return;

    // Reset the file input so the same file can be picked again after an error
    if (jsonImportRef.current) jsonImportRef.current.value = "";

    if (!file.name.endsWith(".json") && file.type !== "application/json") {
      const msg = "Invalid file type. Please select a .json file.";
      setImportError(msg);
      toast.error(msg);
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const raw = event.target?.result;
      if (typeof raw !== "string") {
        const msg = "Could not read the file. Please try again.";
        setImportError(msg);
        toast.error(msg);
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        // #737: catch SyntaxError from malformed JSON instead of crashing
        const msg = "Invalid JSON: the file contains a syntax error. Please fix it and try again.";
        setImportError(msg);
        toast.error(msg);
        return;
      }

      // Normalise: accept either a single credential object or an array
      const candidates = Array.isArray(parsed) ? parsed : [parsed];

      const valid: Credential[] = [];
      const errors: string[] = [];

      candidates.forEach((item: unknown, idx) => {
        if (
          typeof item !== "object" ||
          item === null ||
          typeof (item as Record<string, unknown>).id !== "string" ||
          typeof (item as Record<string, unknown>).subject !== "string" ||
          typeof (item as Record<string, unknown>).issuer !== "string"
        ) {
          errors.push(`Item ${idx + 1} is missing required fields (id, subject, issuer).`);
          return;
        }
        valid.push(item as Credential);
      });

      if (errors.length > 0) {
        const msg = `Import failed: ${errors.join(" ")}`;
        setImportError(msg);
        toast.error(msg);
        return;
      }

      if (valid.length === 0) {
        const msg = "The file contains no valid credentials.";
        setImportError(msg);
        toast.error(msg);
        return;
      }

      // Merge imported credentials into the current displayed list
      dispatchCredential({
        type: 'FETCH_SUCCESS',
        credentials: valid,
        searchedAddress: valid[0]?.subject ?? "",
      });
      setImportedCount(valid.length);
      toast.success(`Imported ${valid.length} credential${valid.length > 1 ? "s" : ""} successfully.`);
    };

    reader.onerror = () => {
      const msg = "Failed to read the file. Please try again.";
      setImportError(msg);
      toast.error(msg);
    };

    reader.readAsText(file);
  };

  const handleVerify = async (credentialId?: string, silent = false) => {
    if (verifying) return; // guard against duplicate submissions
    const id = (credentialId ?? credId).trim();
    if (!id) return;
    if (!silent) {
      setVerifying(true);
      setVerifyState("idle");
    }
    try {
      const credentialClient = getCredentialClient();
      const caller = wallet.publicKey || "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
      const result = await credentialClient.verifyCredential(caller, id);
      setVerifyCheckedAt(Date.now());
      const reason = result.reason;
      const knownReason: VerifyState =
        reason === "not_found" || reason === "revoked" || reason === "expired" || reason === "not_yet_active" || reason === "unknown"
          ? reason
          : "invalid";
      setVerifyState(result.valid ? "valid" : knownReason);
      if (result.valid) {
        toast.success("Credential is valid.");
      } else {
        toast.error(`Credential is invalid (${knownReason.replace("_", " ")}).`);
      }
    } catch (e: unknown) {
      setVerifyState("invalid");
      setVerifyCheckedAt(Date.now());
      toast.error(handleError(e));
    } finally {
      if (!silent) setVerifying(false);
    }
  };

  // ── #736: Clear cached credential data immediately on wallet disconnect ─────
  // When the wallet disconnects (publicKey becomes null), reset the credential
  // list, issue result, and verify state so a subsequent user on a shared
  // device never briefly sees the previous user's data.
  useEffect(() => {
    if (!wallet.connected) {
      dispatchCredential({ type: 'RESET' });
      setVerifyState("idle");
      setCredId("");
      setIssueResult(null);
      setIssueErrors({});
      setExpandedCredId(null);
      setSearchAddress("");
      setIsIssuer(false);
      // #1303: drop any stale revocation transaction state on disconnect
      revokeSignedXdrRef.current = null;
      revokeInFlightHashRef.current = null;
    }
  }, [wallet.connected]);

  useEffect(() => {
    if (!wallet.connected || !wallet.publicKey) {
      setIsIssuer(false);
      return;
    }

    const checkIssuerStatus = async () => {
      setCheckingIssuer(true);
      try {
        const credentialClient = getCredentialClient();
        const caller = wallet.publicKey || "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        const issuer = await credentialClient.isIssuer(caller, wallet.publicKey!);
        setIsIssuer(issuer);
      } catch {
        setIsIssuer(false);
      } finally {
        setCheckingIssuer(false);
      }
    };

    checkIssuerStatus();
  }, [wallet.connected, wallet.publicKey]);

  // Handle deep link verification
  useEffect(() => {
    if (!verifyId) return;
    setCredId(verifyId);
    void handleVerify(verifyId);
  }, [verifyId]);

  // Auto-refresh the verification result so a revoke/expiry elsewhere is reflected here
  useEffect(() => {
    if (verifyState === "idle" || !credId) return;
    const interval = setInterval(() => {
      void handleVerify(credId, true);
    }, STATUS_REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [verifyState, credId]);

  const fetchCredentialsForAddress = async (addr: string) => {
    const trimmed = addr.trim();
    if (!trimmed) return;
    if (!StrKey.isValidEd25519PublicKey(trimmed)) {
      const message = 'Invalid Stellar address format. Address must start with "G" and be 56 characters long.';
      dispatchCredential({ type: 'FETCH_ERROR', message });
      toast.error(message);
      return;
    }
    dispatchCredential({ type: 'FETCH_START' });
    try {
      const credentialClient = getCredentialClient();
      const caller = wallet.publicKey || "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
      const results = await credentialClient.getCredentialsBySubject(caller, trimmed);
      dispatchCredential({ type: 'FETCH_SUCCESS', credentials: results, searchedAddress: trimmed });
      setLastCheckedAt(Date.now());
    } catch (e: unknown) {
      const message = handleError(e);
      dispatchCredential({ type: 'FETCH_ERROR', message });
      toast.error(message);
    }
  };

  const handleSearch = async () => {
    const addr = searchAddress.trim();
    if (!addr) return;

    // Validate Stellar address format
    if (!StrKey.isValidEd25519PublicKey(addr)) {
      dispatchCredential({
        type: 'FETCH_ERROR',
        message: 'Invalid Stellar address format. Address must start with "G" and be 56 characters long.'
      });
      return;
    }

    await fetchCredentialsForAddress(addr);
  };

  // Auto-refresh the credential list periodically so status changes (revoke/expiry) show up
  useEffect(() => {
    if (!searchedAddress) return;
    const interval = setInterval(() => {
      void fetchCredentialsForAddress(searchedAddress);
    }, STATUS_REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [searchedAddress]);

  const validateIssueForm = (): boolean => {
    const errors: Record<string, string> = {};

    // Validate subject address
    if (!subject.trim()) {
      errors.subject = "Subject address is required";
    } else if (!StrKey.isValidEd25519PublicKey(subject.trim())) {
      errors.subject = "Invalid Stellar address format. Address must start with 'G' and be 56 characters long.";
    }

    // Validate at least one claim
    const filledClaims = claims.filter((c) => c.key.trim() || c.value.trim());
    if (filledClaims.length === 0) {
      errors.claims = "At least one claim key-value pair is required";
    }

    // Validate expiry date (supports 64-bit timestamps beyond year 2106 up to u64::MAX)
    const trimmedExpiry = expiresAt.trim() || "0";
    if (!/^\d+$/.test(trimmedExpiry)) {
      errors.expiresAt = "Expiry must be 0 or a positive integer timestamp";
    } else {
      const expiryBig = BigInt(trimmedExpiry);
      if (expiryBig > MAX_U64_TIMESTAMP) {
        errors.expiresAt = "Expiry exceeds maximum 64-bit timestamp value";
      } else if (expiryBig > 0n) {
        const now = BigInt(Math.floor(Date.now() / 1000));
        if (expiryBig <= now) {
          errors.expiresAt = "Expiry date must be in the future";
        }
      }
    }

    // Validate claims against template schema if a template is selected
    if (selectedTemplate) {
      const claimsMap: Record<string, string> = {};
      claims.forEach((c) => {
        if (c.key.trim()) claimsMap[c.key.trim()] = c.value.trim();
      });
      const tplValidation =