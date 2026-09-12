# AI-Assisted Triage Architecture

The following diagram illustrates the overall system architecture, data flow, and key modules of the AI-Assisted Triage (AI-Assisted Vulnerability Triage Platform).

```mermaid
graph TD
    %% Define Styles
    classDef external fill:#f9f,stroke:#333,stroke-width:2px;
    classDef module fill:#bbf,stroke:#333,stroke-width:2px;
    classDef db fill:#ffb,stroke:#333,stroke-width:2px;
    classDef ui fill:#bfb,stroke:#333,stroke-width:2px;

    %% External Inputs
    subgraph External Sources
        S1[Nessus]:::external
        S2[Burp]:::external
        S3[Snyk / Trivy]:::external
        S4[SARIF / ZAP]:::external
    end

    %% Ingestion Module (M1)
    subgraph M1: Ingestion & Normalization
        API_Ingest[Ingestion API]:::module
        Norm[Normalizer]:::module
    end

    %% Processing Modules (M2 & M3)
    subgraph M2-M3: Embeddings & Deduplication
        ViewExt[View Extractor]:::module
        Embed[Embedding Engine<br/>SentenceTransformer]:::module
        Dedup[Deduplicator<br/>Fingerprint & HDBSCAN]:::module
    end

    %% Validation & Risk (M4 & M5)
    subgraph M4-M5: Validation & Prioritization
        Sand[Sandbox Simulation]:::module
        Risk[Risk Engine]:::module
        Threat[Threat Intel<br/>KEV/EPSS]:::external
    end

    %% Case Management (M6)
    subgraph M6: Case Management
        CaseMan[Case Assembly & Review]:::module
    end

    %% Persistence
    subgraph Persistence
        SQLite[(SQLite Database)]:::db
    end

    %% User Interface (F0 & M7)
    subgraph Analyst Interface
        Console[Analyst Console & Dashboard]:::ui
    end

    %% Data Flow
    S1 --> API_Ingest
    S2 --> API_Ingest
    S3 --> API_Ingest
    S4 --> API_Ingest

    API_Ingest --> Norm
    Norm -- Canonical Findings --> SQLite
    
    Norm --> ViewExt
    ViewExt --> Embed
    Embed --> Dedup
    Dedup -- Canonical Issues --> SQLite
    
    Dedup --> Sand
    Sand -- Evidence / Hashes --> SQLite
    
    Sand --> Risk
    Threat --> Risk
    Risk -- Priority Scores --> SQLite
    
    Risk --> CaseMan
    CaseMan -- Cases & Audits --> SQLite
    
    CaseMan <--> Console
    SQLite -. Metrics & Data .-> Console
```

## Key Components

1. **Ingestion & Normalization**: Standardizes raw findings from various scanners into a canonical format.
2. **Embeddings & Deduplication**: Extracts relevant text views, computes embeddings, and clusters duplicate findings into canonical issues.
3. **Validation**: Simulates exploits (offline) to validate vulnerabilities and stores immutable, hashed evidence.
4. **Prioritization**: Uses external threat intelligence (KEV, EPSS) alongside validation results to compute a weighted risk score.
5. **Case Management & Analyst Console**: Assembles prioritized issues into cases for human review via the dashboard.
