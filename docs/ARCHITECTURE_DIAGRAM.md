# ShieldBot - Architecture Diagram

## System Architecture

```mermaid
flowchart TB
    A[Chrome Extension] --> D[FastAPI Backend]
    B[Telegram Bot] --> D
    C[Web dApps] --> A

    D --> E[Risk Engine]
    D --> F[AI Analyzer]
    D --> G[Calldata Decoder]
    D --> H[Tenderly Simulator]

    E --> I1[Contract Service]
    E --> I2[Honeypot Service]
    E --> I3[Dex Service]
    E --> I4[Ethos Service]
    H --> I5[Tenderly Service]
    D --> I6[Greenfield Service]

    I1 --> K1[GoPlus API]
    I1 --> K6[BscScan API]
    I2 --> K2[Honeypot API]
    I3 --> K3[DexScreener API]
    I4 --> K4[Ethos API]
    I5 --> K5[Tenderly API]
    I6 --> J3[BNB Greenfield]

    I1 --> J1[BSC Mainnet]
    I1 --> J2[opBNB L2]

    style A fill:#e3f2fd
    style B fill:#e3f2fd
    style D fill:#fff3e0
    style E fill:#f3e5f5
    style F fill:#f3e5f5
    style G fill:#f3e5f5
    style H fill:#f3e5f5
```

## Transaction Flow

```mermaid
sequenceDiagram
    participant User
    participant dApp
    participant Extension
    participant API
    participant RiskEngine
    participant Services
    participant BSC
    participant Greenfield

    User->>dApp: Initiate Token Swap
    dApp->>Extension: eth_sendTransaction
    Extension->>API: POST /api/firewall

    par Parallel Data Gathering
        API->>Services: ContractService.fetch()
        API->>Services: HoneypotService.fetch()
        API->>Services: DexService.fetch()
        API->>Services: EthosService.fetch()
        API->>Services: TenderlyService.simulate()
    end

    Services->>BSC: eth_getCode, eth_call
    BSC-->>Services: Contract Data
    Services-->>API: Aggregated Data

    API->>RiskEngine: compute_composite_risk()
    RiskEngine-->>API: ShieldScore + Verdict

    alt High Risk (Score >= 71)
        API->>Greenfield: Upload Forensic Report
        Greenfield-->>API: Report URL
        API-->>Extension: BLOCK + Report URL
        Extension->>User: 🔴 RED MODAL (Blocked)
    else Medium Risk (31-70)
        API-->>Extension: WARN
        Extension->>User: 🟡 ORANGE OVERLAY (Proceed/Cancel)
        User->>Extension: User Decision
    else Low Risk (0-30)
        API-->>Extension: ALLOW
        Extension->>dApp: Forward Transaction
        dApp->>User: MetaMask Signature Request
    end
```

## Data Flow (Composite Risk Scoring)

```mermaid
flowchart LR
    A1[Contract Data] --> B1[Structural 40%]
    A2[Honeypot Data] --> B4[Honeypot 15%]
    A3[Market Data] --> B2[Market 25%]
    A4[Ethos Data] --> B3[Behavioral 20%]

    B1 --> C[Weighted Sum]
    B2 --> C
    B3 --> C
    B4 --> C

    C --> D[Escalation Rules]
    D --> E[Reduction Rules]
    E --> F[ShieldScore]
    F --> G[Risk Level]
    F --> H[Critical Flags]

    style C fill:#f3e5f5
    style F fill:#fff9c4
```

## Chrome Extension Architecture

```mermaid
flowchart TB
    A[dApp Website] --> B[window.ethereum]
    B --> C[inject.js]
    C --> D[content.js]
    D --> E[background.js]
    E --> G[ShieldBot API]
    G --> E
    E --> D
    D --> A
    F[popup.html] --> E

    style C fill:#e3f2fd
    style D fill:#fff3e0
    style E fill:#f3e5f5
```

## BNB Chain Integration Points

```mermaid
flowchart TB
    A[Web3Client] --> C[Contract Bytecode]
    A --> D[Token Metadata]
    A --> E[Ownership Info]
    A --> F[PancakeSwap V2]
    A --> G[opBNB Scanning]
    A --> J[Contract Verification]
    A --> K[Source Code]

    B[GreenfieldService] --> H[Bucket Reports]
    H --> I[Forensic JSON]

    style C fill:#fff9c4
    style H fill:#e8f5e9
```

## Risk Scoring Algorithm

```mermaid
flowchart TD
    A[Start] --> B{Is Contract?}
    B -->|No| C[Score 0]
    B -->|Yes| D[Fetch Data]

    D --> E[Structural]
    D --> F[Market]
    D --> G[Behavioral]
    D --> H[Honeypot]

    E --> I[Weighted Sum]
    F --> I
    G --> I
    H --> I

    I --> J{Honeypot?}
    J -->|Yes| K[Floor 80]
    J -->|No| L{Rug Pattern?}

    L -->|Yes| M[Floor 85]
    L -->|No| N{Renounced?}

    N -->|Yes| O[Reduce 20]
    N -->|No| P[Keep Score]

    K --> Q[Final Score]
    M --> Q
    O --> Q
    P --> Q

    Q --> R{Score >= 71?}
    R -->|Yes| S[BLOCK]
    R -->|No| T{Score >= 31?}
    T -->|Yes| U[WARN]
    T -->|No| V[ALLOW]

    style S fill:#ffebee
    style U fill:#fff3e0
    style V fill:#e8f5e9
```

---

**Note:** These diagrams are rendered automatically on GitHub. You can also use [Mermaid Live Editor](https://mermaid.live/) to view/edit them.
