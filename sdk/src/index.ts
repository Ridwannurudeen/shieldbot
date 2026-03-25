/**
 * ShieldBot SDK — Web3 security intelligence for wallets and dApps.
 *
 * Usage:
 *   import { ShieldBot } from 'shieldbot-sdk';
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
  /** Local verdict cache TTL in seconds. Default: 86400 (24h). */
  cacheTtl?: number;
  /** Fail mode when API is unreachable: 'cached' | 'open' | 'closed'. Default: 'cached'. */
  failMode?: 'cached' | 'open' | 'closed';
}

export interface ScanOptions {
  /** Chain ID (56=BSC, 1=ETH, 8453=Base, 42161=Arb, 137=Poly, 10=OP, 204=opBNB). */
  chainId?: number;
}

export interface FirewallOptions extends ScanOptions {
  /** Sender address. */
  from?: string;
  /** Transaction calldata. */
  data?: string;
  /** Transaction value in hex. */
  value?: string;
}

export interface RiskScore {
  overall: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
  threat_type: string;
  critical_flags: string[];
  confidence: number;
  category_scores: Record<string, number>;
}

export interface ScanResult {
  classification: string;
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
  total_approvals: number;
  high_risk: number;
  medium_risk: number;
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
  chainId?: number;
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

const DEFAULT_BASE_URL = 'https://api.shieldbotsecurity.online';
const DEFAULT_TIMEOUT = 10_000;

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
    this.cacheTtl = (config.cacheTtl || 86400) * 1000; // convert to ms
    this.verdictCache = new Map();
  }

  /**
   * Scan a contract or token address for risks.
   */
  async scan(address: string, options: ScanOptions = {}): Promise<ScanResult> {
    const chainId = options.chainId || 56;
    return this._post<ScanResult>('/api/scan', {
      address,
      chainId,
    });
  }

  /**
   * Run the full firewall analysis on a pending transaction.
   */
  async firewall(toAddress: string, options: FirewallOptions = {}): Promise<FirewallResult> {
    return this._post<FirewallResult>('/api/firewall', {
      to: toAddress,
      from: options.from || '',
      data: options.data || '0x',
      value: options.value || '0x0',
      chainId: options.chainId || 56,
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
  async rescue(walletAddress: string, chainId = 56): Promise<RescueResult> {
    return this._get<RescueResult>(
      `/api/rescue/${walletAddress}?chain_id=${chainId}`,
    );
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
  async health(): Promise<{ status: string; chains: number[] }> {
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

    const cacheKey = `${transaction.to}:${transaction.chainId || 56}:${(transaction.data || '0x').slice(0, 10)}`;

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
          value: transaction.value || '0',
          chain_id: transaction.chainId || 56,
        },
      });

      const verdict: Verdict = {
        verdict: raw.verdict as Verdict['verdict'],
        score: raw.score as number,
        flags: (raw.flags || []) as string[],
        policy_check: raw.policy_check as Record<string, unknown>,
        cached: !!raw.cached,
        latency_ms: raw.latency_ms as number,
        allowed: raw.verdict === 'ALLOW',
        blocked: raw.verdict === 'BLOCK',
        evidence: raw.evidence as string,
      };

      // Cache the verdict
      this._cacheVerdict(cacheKey, verdict);
      return verdict;
    } catch (error) {
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
  async queryThreatGraph(address: string, maxDepth = 3): Promise<Record<string, unknown>> {
    return this._get(`/api/graph/check/${address}?max_depth=${maxDepth}`);
  }

  /**
   * Scan content for prompt injection attempts.
   */
  async scanForInjection(content: string, depth: 'fast' | 'thorough' = 'fast'): Promise<Record<string, unknown>> {
    return this._post('/api/scan/injection', { content, depth });
  }

  // --- Internal ---

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
    // Try local cache regardless of mode
    const cached = this.verdictCache.get(cacheKey);
    if (cached && this.failMode === 'cached') {
      return { ...cached.verdict, cached: true };
    }

    if (this.failMode === 'open') {
      return {
        verdict: 'ALLOW',
        score: 0,
        flags: ['fail_open'],
        cached: false,
        latency_ms: 0,
        allowed: true,
        blocked: false,
        evidence: `API unreachable, fail-open: ${error.message}`,
      };
    }

    // fail_closed or no cache
    return {
      verdict: 'BLOCK',
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
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new ShieldBotError(
          `ShieldBot API error: ${response.status} ${text}`,
          response.status,
        );
      }

      return (await response.json()) as T;
    } catch (error) {
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
}

export default ShieldBot;
