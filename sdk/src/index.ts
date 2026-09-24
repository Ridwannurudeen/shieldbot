/**
 * ShieldBot SDK — Web3 security intelligence for wallets and dApps.
 *
 * Usage:
 *   import { ShieldBot } from '@shieldbot/sdk';
 *   const shield = new ShieldBot({ apiKey: 'sb_...' });
 *   const result = await shield.scan('0x...', { chainId: 56 });
 */

export interface ShieldBotConfig {
  /** API key (sb_... prefix). Required for authenticated endpoints. */
  apiKey?: string;
  /** Agent ID for agent firewall mode (e.g. "erc8004:31253"). */
  agentId?: string;
  /** Base URL of the ShieldBot API. Defaults to production. */
  baseUrl?: string;
  /** Request timeout in milliseconds. Default: 10000. */
  timeout?: number;
  /** Local verdict cache size. Default: 10000. */
  cacheSize?: number;
  /** Local verdict cache TTL in seconds. Default: 60 (bounds stale decisions to one minute). */
  cacheTtl?: number;
  /** Fail mode when API is unreachable: 'cached' | 'open' | 'closed'. Default: 'cached'. */
  failMode?: 'cached' | 'open' | 'closed';
}

/** Chains the ShieldBot API analyzes. `health()` returns the live list as `supported_chains`. */
export const SUPPORTED_CHAIN_IDS = [56, 1, 8453, 42161, 137, 10, 204, 4663] as const;

/** 56=BSC, 1=Ethereum, 8453=Base, 42161=Arbitrum, 137=Polygon, 10=Optimism, 204=opBNB, 4663=Robinhood Chain. */
export type ChainId = (typeof SUPPORTED_CHAIN_IDS)[number];

/** True for a chain in SUPPORTED_CHAIN_IDS. The SDK does not reject other chains itself: the API answers them with 400. */
export function isSupportedChainId(chainId: number): chainId is ChainId {
  return (SUPPORTED_CHAIN_IDS as readonly number[]).includes(chainId);
}

export interface ScanOptions {
  /** Chain to analyze. Required: the SDK never assumes a chain, and the API rejects an unsupported one with 400. */
  chainId: number;
}

export interface FirewallOptions extends ScanOptions {
  /** Sender address. */
  from?: string;
  /** Transaction calldata. */
  data?: string;
  /** Value in wei, as a decimal or 0x hex string. Sent as decimal wei; anything else throws INVALID_VALUE. */
  value?: string;
  /**
   * Asks for the streamed answer (Accept: text/event-stream) and is called with the interim verdict
   * if the API sends one before the final. firewall() still resolves with the final verdict. Without
   * it, firewall() makes the plain request.
   */
  onFirst?: (first: FirstVerdict) => void;
  /**
   * With onFirst: milliseconds to wait for the response and then for each next event before the
   * request is aborted (TIMEOUT). It replaces `timeout` for a streamed request. Default: 30000.
   */
  finalTimeout?: number;
}

export interface RiskScore {
  overall: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';
  threat_type: string;
  critical_flags: string[];
  confidence: number;
  category_scores: Record<string, number | null>;
  status?: 'ok' | 'unknown';
  coverage?: Record<string, number>;
  coverage_reasons?: Record<string, string>;
  risk_display?: string;
}

export interface ScanResult {
  status?: 'ok' | 'unknown';
  coverage?: Record<string, number>;
  coverage_reasons?: Record<string, string>;
  risk_display?: string;
  classification: 'SAFE' | 'CAUTION' | 'HIGH_RISK' | 'BLOCK_RECOMMENDED';
  risk_score: number;
  danger_signals: string[];
  shield_score?: RiskScore;
  raw_checks?: Record<string, unknown>;
  chain_id?: number;
  network?: string;
  cached?: boolean;
  simulation?: Record<string, unknown> | null;
  greenfield_url?: string | null;
  partial?: boolean;
  failed_sources?: string[];
  policy_mode?: string;
  /** Checks that could not run and only add risk: information, not danger signals. */
  notes?: string[];
  /** keccak256 of the verdict's canonical evidence document. */
  evidence_hash?: string;
  /** Where the evidence document is shown (GET /evidence/{hash}; JSON at /api/evidence/{hash}); null when it could not be stored. Kept 90 days. */
  evidence_url?: string | null;
}

export interface FirewallResult extends ScanResult {
  transaction_impact: {
    sending: string;
    granting_access: string;
    recipient: string;
    post_tx_state: string;
  };
  analysis?: string;
  plain_english?: string;
  verdict: string;
  /** True on the final verdict of a streamed request (onFirst); absent on a plain request. */
  final?: boolean;
}

/**
 * The interim verdict of a streamed firewall() call, sent while the analysis still runs. It is always
 * Unknown and never SAFE: its score and classification come only from hard floors already known,
 * such as a blacklisted target, so it can warn early but never clears a transaction.
 */
export interface FirstVerdict extends Omit<FirewallResult, 'status' | 'classification' | 'final'> {
  status: 'unknown';
  classification: Exclude<FirewallResult['classification'], 'SAFE'>;
  final: false;
  /** The analyzers still running when it was sent. */
  pending_sources: string[];
  /** Milliseconds from the start of the API's handler to this verdict. */
  elapsed_ms: number;
}

export interface MempoolAlert {
  alert_type: string;
  severity: string;
  description: string;
  victim_tx?: string;
  attacker_tx?: string;
  attacker_addr?: string;
  target_token?: string;
  chain_id: number;
  created_at: number;
}

export interface RescueResult {
  wallet: string;
  chain_id: number;
  /** 'unknown' when approval history, allowances, balances or prices are incomplete: the lists below are then not a clean bill of health. */
  status: 'ok' | 'unknown';
  coverage: Record<string, boolean>;
  coverage_reasons: Record<string, string>;
  /** Block range whose approval history was read. rescue() throws SCAN_UNAVAILABLE instead of returning a result that read nothing. */
  scanned_blocks: { from_block: number; to_block: number } | null;
  total_approvals: number;
  high_risk: number;
  medium_risk: number;
  /** Null when the scan is incomplete. */
  total_value_at_risk_usd: number | null;
  approvals: ApprovalInfo[];
  alerts: RescueAlert[];
  revoke_txs: RevokeTx[];
}

export interface ApprovalInfo {
  token_address: string;
  token_symbol: string;
  spender: string;
  spender_label: string;
  allowance: string;
  risk_level: string;
  risk_reason: string;
}

export interface RescueAlert {
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  what_it_means: string;
  what_you_can_do: string[];
}

export interface RevokeTx {
  token: string;
  token_symbol: string;
  spender: string;
  risk_level: string;
  transaction: {
    from: string;
    to: string;
    data: string;
    value: string;
    chainId: string;
  };
}

export interface CampaignGraph {
  address: string;
  deployer?: string;
  funder?: string;
  cross_chain_contracts: Array<{
    contract: string;
    chain_id: number;
    risk_score?: number;
    risk_level?: string;
  }>;
  campaign: {
    is_campaign: boolean;
    severity: string;
    indicators: string[];
  };
}

export interface ThreatFeedItem {
  type: string;
  address?: string;
  chain_id: number;
  risk_score?: number;
  risk_level?: string;
  detected_at?: number;
}

export interface AgentTransaction {
  from: string;
  to: string;
  data?: string;
  value?: string;
  chainId: number;
}

export interface Verdict {
  verdict: 'ALLOW' | 'WARN' | 'BLOCK';
  score: number;
  flags: string[];
  policy_check?: Record<string, unknown>;
  cached: boolean;
  latency_ms: number;
  /** Convenience: true if verdict === 'ALLOW' */
  allowed: boolean;
  /** Convenience: true if verdict === 'BLOCK' */
  blocked: boolean;
  evidence?: string;
  status: 'ok' | 'unknown';
  coverage: Record<string, number>;
  coverage_reasons: Record<string, string>;
  risk_display: string;
  risk_level?: RiskScore['risk_level'];
  category_scores?: Record<string, number | null>;
  confidence?: number | null;
  /** True when the decision comes from fail-mode rather than a completed analysis. */
  analysis_unavailable: boolean;
}

export interface ReputationScore {
  agent_id: string;
  composite_score: number;
  breakdown: {
    erc8004: number;
    bap578: number;
    shieldbot: number;
    sentinelnet: number;
  };
  verified: boolean;
  verdict_summary: {
    total: number;
    allowed: number;
    blocked: number;
    warned: number;
  };
}

class ShieldBotError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
  ) {
    super(message);
    this.name = 'ShieldBotError';
  }
}

export { ShieldBotError };

/** Carries an exception thrown by the caller's onFirst through _request's error mapping unchanged. */
class ListenerError {
  constructor(public error: unknown) {}
}

const DEFAULT_BASE_URL = 'https://api.shieldbotsecurity.online';
const DEFAULT_TIMEOUT = 10_000;
const DEFAULT_FINAL_TIMEOUT = 30_000;
const MAX_WEI = 2n ** 256n - 1n;

export class ShieldBot {
  private baseUrl: string;
  private apiKey?: string;
  private agentId?: string;
  private timeout: number;
  private failMode: 'cached' | 'open' | 'closed';
  private cacheSize: number;
  private cacheTtl: number;
  private verdictCache: Map<string, { verdict: Verdict; timestamp: number }>;

  constructor(config: ShieldBotConfig = {}) {
    this.baseUrl = (config.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.agentId = config.agentId;
    this.timeout = config.timeout || DEFAULT_TIMEOUT;
    this.failMode = config.failMode || 'cached';
    this.cacheSize = config.cacheSize || 10000;
    this.cacheTtl = (config.cacheTtl ?? 60) * 1000; // convert to ms
    this.verdictCache = new Map();
  }

  /**
   * Scan a contract or token address for risks.
   */
  async scan(address: string, options: ScanOptions): Promise<ScanResult> {
    return this._post<ScanResult>('/api/scan', {
      address,
      chainId: this._requireChainId(options?.chainId, 'scan'),
    });
  }

  /**
   * Run the full firewall analysis on a pending transaction.
   *
   * With `onFirst` the answer is streamed: `onFirst` gets the interim verdict (always Unknown,
   * never SAFE) if the API sends one before the final, and the promise resolves with the final
   * verdict, `final: true`. The API sends no interim verdict under a STRICT policy.
   */
  async firewall(toAddress: string, options: FirewallOptions): Promise<FirewallResult> {
    const chainId = this._requireChainId(options?.chainId, 'firewall');
    const body = {
      to: toAddress,
      from: options.from || '',
      data: options.data || '0x',
      value: this._weiValue(options.value, 'firewall'),
      chainId,
    };
    if (!options.onFirst) {
      return this._post<FirewallResult>('/api/firewall', body);
    }
    return this._request<FirewallResult>('POST', '/api/firewall', body, {
      onFirst: options.onFirst,
      timeout: options.finalTimeout ?? DEFAULT_FINAL_TIMEOUT,
    });
  }

  /**
   * Get recent mempool alerts (sandwich attacks, frontrunning).
   */
  async getMempoolAlerts(chainId?: number, limit = 50): Promise<MempoolAlert[]> {
    const params = new URLSearchParams();
    if (chainId) params.set('chain_id', String(chainId));
    params.set('limit', String(limit));
    const result = await this._get<{ alerts: MempoolAlert[] }>(
      `/api/mempool/alerts?${params}`,
    );
    return result.alerts;
  }

  /**
   * Scan a wallet's active approvals and get revoke transactions (Rescue Mode).
   */
  async rescue(walletAddress: string, chainId: number): Promise<RescueResult> {
    const result = await this._get<RescueResult>(
      `/api/rescue/${walletAddress}?chain_id=${this._requireChainId(chainId, 'rescue')}`,
    );
    if (result.status === 'unknown' && result.scanned_blocks == null) {
      const reasons = Object.values(result.coverage_reasons || {}).join('; ') || 'no blocks were read';
      throw new ShieldBotError(`Approval scan unavailable: ${reasons}`, 503, 'SCAN_UNAVAILABLE');
    }
    return result;
  }

  /**
   * Get the campaign/entity graph for an address.
   */
  async getCampaign(address: string): Promise<CampaignGraph> {
    return this._get<CampaignGraph>(`/api/campaign/${address}`);
  }

  /**
   * Get the real-time threat feed.
   */
  async getThreats(options: { chainId?: number; limit?: number; since?: number } = {}): Promise<ThreatFeedItem[]> {
    const params = new URLSearchParams();
    if (options.chainId) params.set('chain_id', String(options.chainId));
    if (options.limit) params.set('limit', String(options.limit));
    if (options.since) params.set('since', String(options.since));
    const result = await this._get<{ threats: ThreatFeedItem[] }>(
      `/api/threats/feed?${params}`,
    );
    return result.threats;
  }

  /**
   * Check API health status.
   */
  async health(): Promise<{ status: string; service: string; supported_chains: number[] }> {
    return this._get('/api/health');
  }

  // --- V3 Agent Firewall ---

  /**
   * Check a transaction through the agent firewall.
   * Returns a Verdict with allowed/blocked convenience booleans.
   * Uses local cache and fail-mode when API is unreachable.
   */
  async check(transaction: AgentTransaction): Promise<Verdict> {
    if (!this.agentId) {
      throw new ShieldBotError('agentId required for check()', 400, 'MISSING_AGENT_ID');
    }
    const chainId = this._requireChainId(transaction.chainId, 'check');
    const value = this._weiValue(transaction.value, 'check');

    const canonicalInteger = (value: unknown): string => {
      if (
        !['string', 'number', 'bigint'].includes(typeof value) ||
        (typeof value === 'string' && value.trim() === '')
      ) {
        return `raw:${typeof value}:${String(value)}`;
      }
      try {
        return BigInt(value as string | number | bigint).toString();
      } catch {
        return `raw:${typeof value}:${String(value)}`;
      }
    };
    const cacheKey = JSON.stringify([
      transaction.from?.toLowerCase(),
      transaction.to?.toLowerCase(),
      canonicalInteger(chainId),
      (transaction.data || '0x').toLowerCase(),
      value,
    ]);

    // Check local cache
    const cached = this.verdictCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTtl) {
      return { ...cached.verdict, cached: true };
    }

    try {
      const raw = await this._post<Record<string, unknown>>('/api/agent/firewall', {
        agent_id: this.agentId,
        transaction: {
          from: transaction.from,
          to: transaction.to,
          data: transaction.data || '0x',
          value,
          chain_id: chainId,
        },
      });

      const coverage = (raw.coverage || {}) as Record<string, number>;
      const incomplete = raw.status !== 'ok' || raw.risk_level === 'UNKNOWN' || Object.keys(coverage).length === 0 || Object.values(coverage).some(value => value !== 1);
      const decision = incomplete && raw.verdict === 'ALLOW' ? 'WARN' : raw.verdict as Verdict['verdict'];
      const verdict: Verdict = {
        verdict: decision,
        status: incomplete ? 'unknown' : 'ok',
        coverage,
        coverage_reasons: (raw.coverage_reasons || {}) as Record<string, string>,
        risk_display: incomplete ? 'Unknown (incomplete provider coverage)' : (raw.risk_display as string || `${raw.score}%`),
        risk_level: raw.risk_level as RiskScore['risk_level'],
        category_scores: raw.category_scores as Record<string, number | null>,
        confidence: raw.confidence as number | null,
        analysis_unavailable: false,
        score: raw.score as number,
        flags: (raw.flags || []) as string[],
        policy_check: raw.policy_check as Record<string, unknown>,
        cached: !!raw.cached,
        latency_ms: raw.latency_ms as number,
        allowed: decision === 'ALLOW',
        blocked: decision === 'BLOCK',
        evidence: raw.evidence as string,
      };

      // Cache the verdict
      this._cacheVerdict(cacheKey, verdict);
      return verdict;
    } catch (error) {
      if (error instanceof ShieldBotError && error.status >= 400 && error.status < 500 && error.code !== 'TIMEOUT') {
        throw error;
      }
      return this._handleFailMode(cacheKey, error as Error);
    }
  }

  /**
   * Register this agent with the firewall.
   */
  async register(ownerAddress: string, policy: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.agentId) {
      throw new ShieldBotError('agentId required for register()', 400, 'MISSING_AGENT_ID');
    }
    return this._post('/api/agent/register', {
      agent_id: this.agentId,
      owner_address: ownerAddress,
      policy,
    });
  }

  /**
   * Look up an agent's composite trust score.
   */
  async checkReputation(agentId?: string): Promise<ReputationScore> {
    const id = agentId || this.agentId;
    if (!id) {
      throw new ShieldBotError('agentId required', 400, 'MISSING_AGENT_ID');
    }
    return this._get<ReputationScore>(`/api/reputation/${encodeURIComponent(id)}`);
  }

  /**
   * Query the threat graph for an address.
   */
  async queryThreatGraph(address: string, chainId: number, maxDepth = 3): Promise<Record<string, unknown>> {
    return this._get(
      `/api/graph/check/${address}?chain_id=${this._requireChainId(chainId, 'queryThreatGraph')}&max_depth=${maxDepth}`,
    );
  }

  /**
   * Scan content for prompt injection attempts.
   */
  async scanForInjection(content: string, depth: 'fast' | 'thorough' = 'fast'): Promise<Record<string, unknown>> {
    return this._post('/api/scan/injection', { content, depth });
  }

  // --- Internal ---

  private _requireChainId(chainId: number | undefined, method: string): number {
    if (chainId == null) {
      throw new ShieldBotError(`chainId required for ${method}()`, 400, 'MISSING_CHAIN_ID');
    }
    return chainId;
  }

  private _weiValue(value: unknown, method: string): string {
    if (value === undefined || value === null) {
      return '0';
    }
    const text = typeof value === 'string' ? value.trim() : '';
    const parseable =
      typeof value === 'bigint' ||
      (typeof value === 'number' && Number.isSafeInteger(value)) ||
      /^(0x[0-9a-f]+|[0-9]+)$/i.test(text);
    const wei = parseable ? BigInt(typeof value === 'string' ? text : (value as number | bigint)) : -1n;
    if (wei < 0n || wei > MAX_WEI) {
      throw new ShieldBotError(`value for ${method}() must be an integer amount of wei from 0 to 2^256 - 1`, 400, 'INVALID_VALUE');
    }
    return wei.toString();
  }

  private _cacheVerdict(key: string, verdict: Verdict): void {
    // Evict oldest if at capacity
    if (this.verdictCache.size >= this.cacheSize) {
      const oldestKey = this.verdictCache.keys().next().value;
      if (oldestKey !== undefined) {
        this.verdictCache.delete(oldestKey);
      }
    }
    this.verdictCache.set(key, { verdict, timestamp: Date.now() });
  }

  private _handleFailMode(cacheKey: string, error: Error): Verdict {
    const cached = this.verdictCache.get(cacheKey);
    if (cached && this.failMode === 'cached' && Date.now() - cached.timestamp < this.cacheTtl) {
      return { ...cached.verdict, cached: true };
    }

    if (this.failMode === 'open') {
      return {
        verdict: 'ALLOW',
        status: 'unknown',
        coverage: {},
        coverage_reasons: { analysis: 'API unavailable' },
        risk_display: 'Unknown (analysis unavailable)',
        analysis_unavailable: true,
        score: 0,
        flags: ['fail_open'],
        cached: false,
        latency_ms: 0,
        allowed: true,
        blocked: false,
        evidence: `API unreachable, fail-open: ${error.message}`,
      };
    }

    if (this.failMode === 'cached') {
      return {
        verdict: 'WARN',
        status: 'unknown',
        coverage: {},
        coverage_reasons: { analysis: 'API unavailable' },
        risk_display: 'Unknown (analysis unavailable)',
        analysis_unavailable: true,
        score: 50,
        flags: ['fail_cached'],
        cached: false,
        latency_ms: 0,
        allowed: false,
        blocked: false,
        evidence: `API unreachable, no cached verdict: ${error.message}`,
      };
    }

    // fail_closed
    return {
      verdict: 'BLOCK',
      status: 'unknown',
      coverage: {},
      coverage_reasons: { analysis: 'API unavailable' },
      risk_display: 'Unknown (analysis unavailable)',
      analysis_unavailable: true,
      score: 100,
      flags: ['fail_closed'],
      cached: false,
      latency_ms: 0,
      allowed: false,
      blocked: true,
      evidence: `API unreachable, fail-closed: ${error.message}`,
    };
  }

  private async _get<T>(path: string): Promise<T> {
    return this._request<T>('GET', path);
  }

  private async _post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return this._request<T>('POST', path, body);
  }

  private async _request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    stream?: { onFirst: (first: FirstVerdict) => void; timeout: number },
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (stream) {
      headers['Accept'] = 'text/event-stream';
    }
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const timeout = stream ? stream.timeout : this.timeout;
    const controller = new AbortController();
    let timer = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        let errorMsg = `HTTP ${response.status}`;
        try {
          const json = await response.json();
          errorMsg = json.detail || json.error || errorMsg;
        } catch {
          // Response wasn't JSON — use status code only
        }
        throw new ShieldBotError(
          `ShieldBot API error: ${errorMsg}`,
          response.status,
        );
      }

      // A STRICT policy, or a server that does not stream, answers a streamed request with plain JSON.
      if (stream && (response.headers.get('content-type') || '').startsWith('text/event-stream')) {
        return (await this._readStream(response, stream.onFirst, () => {
          clearTimeout(timer);
          timer = setTimeout(() => controller.abort(), timeout);
        })) as T;
      }
      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof ListenerError) throw error.error;
      if (error instanceof ShieldBotError) throw error;
      if ((error as Error).name === 'AbortError') {
        throw new ShieldBotError('Request timed out', 408, 'TIMEOUT');
      }
      throw new ShieldBotError(
        `Network error: ${(error as Error).message}`,
        0,
        'NETWORK_ERROR',
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Reads a streamed firewall response: `first` goes to onFirst, `final` resolves, and `error`
   * throws a ShieldBotError with the API's status. onEvent runs on every event. Lines may end in
   * LF, CRLF or CR, and an event's `data:` lines are joined with LF.
   */
  private async _readStream(
    response: Response,
    onFirst: (first: FirstVerdict) => void,
    onEvent: () => void,
  ): Promise<FirewallResult> {
    const reader = response.body!.getReader();
    try {
      const decoder = new TextDecoder();
      let buffer = '';
      let event = '';
      let data: string[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value, { stream: !done });
        // A CR that ends the text so far may be half of a CRLF, so it waits for the next chunk.
        if (done && buffer.endsWith('\r')) {
          buffer += '\n';
        }
        const lines = buffer.split(/\r\n|\n|\r(?!$)/);
        buffer = lines.pop() as string;
        for (const line of lines) {
          if (line.startsWith('event:')) {
            event = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            data.push(line.slice(line.startsWith('data: ') ? 6 : 5));
          } else if (line === '') {
            // An empty line ends an event, dispatched if it has data; the next one starts afresh.
            const name = event;
            const text = data.join('\n');
            const dispatch = data.length > 0;
            event = '';
            data = [];
            if (!dispatch) {
              continue;
            }
            onEvent();
            const payload = JSON.parse(text);
            if (name === 'first') {
              try {
                onFirst(payload as FirstVerdict);
              } catch (error) {
                throw new ListenerError(error);
              }
            } else if (name === 'final') {
              return payload as FirewallResult;
            } else if (name === 'error') {
              throw new ShieldBotError(`ShieldBot API error: ${payload.detail || `HTTP ${payload.status}`}`, payload.status);
            }
          }
        }
        if (done) {
          throw new Error('the stream ended without a final verdict');
        }
      }
    } finally {
      // Release the connection however reading ends: the final, an error event, onFirst throwing,
      // data that is not JSON or an early end. On a stream that already failed (an abort), cancel()
      // rejects with that same failure, which is then the reason reading stopped.
      await reader.cancel();
    }
  }
}

export default ShieldBot;
