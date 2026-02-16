# ShieldBot - Architecture Diagram

## System Architecture

```mermaid
graph TB
    subgraph "User Interfaces"
        A[Chrome Extension]
        B[Telegram Bot]
        C[Web dApps]
    end

    subgraph "Delivery Layer"
        D[FastAPI Backend Port 8000]
    end

    subgraph "Intelligence Engine"
        E[RiskEngine Composite Scoring]
        F[AI Analyzer Claude API]
        G[Calldata Decoder]
        H[Tenderly Simulator]
    end

    subgraph "Data Services Layer"
        I1[ContractService GoPlus BscScan]
        I2[HoneypotService Honeypot.is]
        I3[DexService DexScreener]
        I4[EthosService Ethos Network]
        I5[TenderlyService Simulation]
        I6[GreenfieldService BNB Greenfield]
    end

    subgraph "Blockchain Layer"
        J1[BSC Mainnet Chain ID 56]
        J2[opBNB Mainnet Chain ID 204]
        J3[BNB Greenfield Storage]
    end

    subgraph "External APIs"
        K1[GoPlus API]
        K2[Honeypot.is API]
        K3[DexScreener API]
        K4[Ethos Network API]
        K5[Tenderly API]
        K6[BscScan API]
    end

    A -->|Transaction Intercept| D
    B -->|Commands| D
    C -->|Web3 Calls| A

    D --> E
    D --> F
    D --> G
    D --> H

    E --> I1
    E --> I2
    E --> I3
    E --> I4
    H --> I5
    D --> I6

    I1 --> K1
    I1 --> K6
    I2 --> K2
    I3 --> K3
    I4 --> K4
    I5 --> K5
    I6 --> J3

    I1 --> J1
    I1 --> J2

    K1 -.->|Contract Intelligence| J1
    K2 -.->|Honeypot Simulation| J1
    K3 -.->|Market Data| J1
    K6 -.->|Verification Data| J1

    style A fill:#e3f2fd
    style B fill:#e3f2fd
    style D fill:#fff3e0
    style E fill:#f3e5f5
    style F fill:#f3e5f5
    style G fill:#f3e5f5
    style H fill:#f3e5f5
    style I1 fill:#e8f5e9
    style I2 fill:#e8f5e9
    style I3 fill:#e8f5e9
    style I4 fill:#e8f5e9
    style I5 fill:#e8f5e9
    style I6 fill:#e8f5e9
    style J1 fill:#fff9c4
    style J2 fill:#fff9c4
    style J3 fill:#fff9c4
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
graph LR
    subgraph "Input Data"
        A1[Contract Data]
        A2[Honeypot Data]
        A3[Market Data]
        A4[Ethos Data]
    end

    subgraph "Category Scoring"
        B1[Structural Score 40%]
        B2[Market Score 25%]
        B3[Behavioral Score 20%]
        B4[Honeypot Score 15%]
    end

    subgraph "Risk Engine"
        C[Weighted Sum]
        D[Escalation Rules]
        E[Reduction Rules]
    end

    subgraph "Output"
        F[ShieldScore 0-100]
        G[Risk Level HIGH MED LOW]
        H[Critical Flags]
    end

    A1 --> B1
    A3 --> B2
    A4 --> B3
    A2 --> B4

    B1 --> C
    B2 --> C
    B3 --> C
    B4 --> C

    C --> D
    D --> E
    E --> F
    F --> G
    F --> H

    style C fill:#f3e5f5
    style D fill:#ffebee
    style E fill:#e8f5e9
    style F fill:#fff9c4
    style G fill:#fff9c4
    style H fill:#ffebee
```

## Chrome Extension Architecture

```mermaid
graph TB
    subgraph "Web Page Context"
        A[dApp Website PancakeSwap]
        B[window.ethereum Provider]
    end

    subgraph "Extension MAIN World"
        C[inject.js Provider Wrapper]
    end

    subgraph "Extension ISOLATED World"
        D[content.js Overlay Renderer]
    end

    subgraph "Extension Service Worker"
        E[background.js API Communication]
    end

    subgraph "Extension UI"
        F[popup.html Settings History]
    end

    A -->|User Action| B
    B -->|Request Intercepted| C
    C -->|window.postMessage| D
    D -->|chrome.runtime.sendMessage| E
    E -->|HTTP Request| G[ShieldBot API]
    G -->|Response| E
    E -->|chrome.tabs.sendMessage| D
    D -->|Inject Modal| A

    F -.->|Settings| E

    style C fill:#e3f2fd
    style D fill:#fff3e0
    style E fill:#f3e5f5
    style F fill:#e8f5e9
```

## BNB Chain Integration Points

```mermaid
graph TB
    subgraph "ShieldBot Backend"
        A[Web3Client]
        B[GreenfieldService]
    end

    subgraph "BSC Mainnet"
        C[Contract Bytecode eth_getCode]
        D[Token Metadata name symbol decimals]
        E[Ownership Info owner]
        F[PancakeSwap V2 getPair balanceOf]
    end

    subgraph "opBNB L2"
        G[Contract Scanning Chain ID 204]
    end

    subgraph "BNB Greenfield"
        H[Bucket shieldbot-reports]
        I[Forensic Reports JSON Objects]
    end

    subgraph "BscScan API"
        J[Contract Verification]
        K[Source Code]
        L[Creation Info]
    end

    A --> C
    A --> D
    A --> E
    A --> F
    A --> G
    A --> J
    A --> K
    A --> L

    B --> H
    H --> I

    style C fill:#fff9c4
    style D fill:#fff9c4
    style E fill:#fff9c4
    style F fill:#fff9c4
    style G fill:#fff9c4
    style H fill:#e8f5e9
    style I fill:#e8f5e9
```

## Risk Scoring Algorithm

```mermaid
graph TD
    A[Start Analyze Contract] --> B{Is Contract?}
    B -->|No| C[Score 0 SAFE]
    B -->|Yes| D[Fetch Data from 6 Sources]

    D --> E[Calculate Structural Score Verification Ownership Bytecode]
    D --> F[Calculate Market Score Liquidity Volume Age]
    D --> G[Calculate Behavioral Score Reputation Scam Flags]
    D --> H[Calculate Honeypot Score Buy Sell Simulation]

    E --> I[Weighted Sum 40% 25% 20% 15%]
    F --> I
    G --> I
    H --> I

    I --> J{Honeypot Confirmed?}
    J -->|Yes| K[Floor Score = 80]
    J -->|No| L{Rug Pull Pattern?}

    L -->|Yes| M[Floor Score = 85]
    L -->|No| N{Owner Renounced?}

    N -->|Yes + High Liq| O[Reduce Score -20]
    N -->|No| P[Keep Score]

    K --> Q[Final ShieldScore]
    M --> Q
    O --> Q
    P --> Q

    Q --> R{Score >= 71?}
    R -->|Yes| S[BLOCK Red Modal]
    R -->|No| T{Score >= 31?}
    T -->|Yes| U[WARN Orange Overlay]
    T -->|No| V[ALLOW Silent Pass]

    style S fill:#ffebee
    style U fill:#fff3e0
    style V fill:#e8f5e9
    style Q fill:#f3e5f5
```

---

**Note:** These diagrams are rendered automatically on GitHub. You can also use [Mermaid Live Editor](https://mermaid.live/) to view/edit them.
