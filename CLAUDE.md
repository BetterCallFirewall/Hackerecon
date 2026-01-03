# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Hackerecon** is an AI-powered security analysis assistant for penetration testing and bug bounty hunting. It acts as a "second pilot" for security researchers, analyzing HTTP traffic in real-time to identify potential vulnerabilities.

**Key Principle**: Human-in-the-loop approach. This is an intelligent assistant, not an automated system. The AI suggests hypotheses and observations, but humans make decisions.

**Architecture**: Fully client-side application with no centralized server. All processing happens locally on the user's machine.

### Current Architecture (5-Phase ReAct Flow)

The system implements a complex multi-stage analysis pipeline:

```
HTTP Request → Request Filter → Phase 1: URL Analysis (cached, 90% LLM reduction)
                                    ↓ (if high interest)
                          Phase 2: Reasoning (observations + hypotheses)
                                    ↓
                          Phase 3: Planning (5-step attack plans)
                                    ↓
                          Phase 4: Acting (test request generation)
                                    ↓
                          Phase 5: Validation (verify test_requests match plans)
                                    ↓
                          Batch Verification (parallel testing)
                                    ↓
                          WebSocket Broadcast → Dashboard
```

### Future Architecture (Detective Flow)

A simplified "detective game" flow is planned for migration (see `/docs/` for detailed migration docs):

```
HTTP Request → Request Filter (heuristic, NO LLM) → 60-70% skip rate
    ↓
Unified Analysis (single LLM call) → Observation + Connections + BigPicture
    ↓
Lead Generation (async, optional LLM) → Auto-verification (if safe)
    ↓
WebSocket Broadcast → Dashboard
```

**Expected improvement**: 60-70% reduction in LLM calls while maintaining quality.

## Common Commands

### Running the Application

```bash
# Run the main application
make run
# or
go run cmd/main.go

# Run with Genkit Dev UI (for flow inspection)
genkit start -- go run cmd/main.go
```

### Build and Development

```bash
# Build the application
go build -o hackerecon cmd/main.go

# Install/update dependencies
go mod tidy

# Run all tests
go test ./...

# Run specific package tests with verbose output
go test ./internal/utils -v
go test ./internal/llm -v

# Run specific test
go test -run TestURLNormalizer ./internal/utils
go test -run TestUnifiedAnalysisFlow ./internal/driven
```

## Code Architecture

### Directory Structure

```
cmd/                          # Application entry points
├── main.go                   # Main entry point (initialization + proxy start)
└── api.go                    # REST API server (/api/hypothesis endpoint)

internal/
├── config/                   # Configuration management
│   └── config.go             # Environment-based config (.env loading)
│
├── driven/                   # Core analysis logic (THE HEART of the system)
│   ├── analyzer.go           # Main 5-phase orchestration (~1470 lines)
│   ├── burp_integration.go   # Burp Suite proxy integration
│   ├── context_manager.go    # SiteContext lifecycle management
│   ├── extractor.go          # Data extraction from HTML/JS
│   ├── hypothesis.go         # Hypothesis generation logic
│   ├── http.go               # HTTP utilities and proxy handling
│   ├── types.go              # Type definitions
│   ├── url_cache.go          # URL analysis cache (90% LLM reduction)
│   └── *_test.go             # Tests
│
├── llm/                      # LLM provider layer (abstraction + implementation)
│   ├── provider.go           # Provider interface
│   ├── factory.go            # Provider factory
│   ├── middleware.go         # LLM middleware
│   ├── simple_genkit_provider.go  # Firebase Genkit implementation
│   ├── prompt.go             # All prompts (Reasoning, Planning, Acting)
│   └── *_test.go             # Tests
│
├── models/                   # Data models (entities)
│   ├── reasoning.go          # Observation, Hypothesis, AttackPlan
│   ├── vulnerabilities.go    # Finding, TestRequest, Verification
│   ├── site_context.go       # SiteContext, URLPattern, AppInsights (~566 lines)
│   ├── dto.go                # Data transfer objects
│   └── *_test.go             # Tests
│
├── verification/             # Active verification
│   └── client.go             # HTTP client for executing test requests
│
├── websocket/                # Real-time communication
│   └── hub.go                # WebSocket manager for dashboard updates
│
├── utils/                    # Utility functions
│   ├── crud_mapper.go        # CRUD operations detection
│   ├── form_extractor.go     # HTML form extraction
│   ├── heuristics.go         # Heuristic analysis
│   ├── request_filter.go     # Request filtering logic (60-70% skip rate)
│   ├── temporal_tracker.go   # Temporal request tracking
│   └── *_test.go             # Tests
│
└── limits/                   # Rate limiting
    └── limits.go

docs/                         # Comprehensive documentation (see below)
notes/                        # Design notes and research
```

### Core Components

#### 1. GenkitSecurityAnalyzer (`internal/driven/analyzer.go`)

The heart of the system. Orchestrates the entire 5-phase pipeline:

```go
type GenkitSecurityAnalyzer struct {
    llmProvider         llm.Provider
    WsHub               *websocket.WebsocketManager
    genkitApp           *genkit.Genkit

    // Genkit flows
    unifiedAnalysisFlow *genkitcore.Flow[...]
    verificationFlow    *genkitcore.Flow[...]

    // Modular components
    contextManager      *SiteContextManager
    dataExtractor       *DataExtractor
    hypothesisGen       *HypothesisGenerator
    requestFilter       *utils.RequestFilter
    verificationClient  *verification.VerificationClient
    urlCache            *URLAnalysisCache  // 90% LLM reduction

    // Enhanced tracking
    formExtractor       *utils.FormExtractor
    crudMapper          *utils.CRUDMapper
    temporalTracker     *utils.TemporalTracker
}
```

**Key method**: `AnalyzeHTTPTraffic()` - processes each request through the full pipeline.

#### 2. Models (`internal/models/`)

**Core Entities**:

- **Observation** (`reasoning.go`): What was observed, where, why it's interesting, severity
- **Hypothesis** (`reasoning.go`): Vulnerability type, reasoning, target param, attack vector, confidence
- **AttackPlan** (`reasoning.go`): 5-step plan (Observe, Change, Where, ExpectVuln, ExpectSafe)
- **Finding** (`vulnerabilities.go`): Final output with test requests and verification status
- **SiteContext** (`site_context.go`): Application state tracking (URLPatterns, TechStack, AppInsights, Forms, CRUD)

#### 3. LLM Provider (`internal/llm/`)

**Provider Interface** (`provider.go`):

```go
type Provider interface {
    GenerateSecurityAnalysis(ctx, req) (*SecurityAnalysisResponse, error)
    GenerateURLAnalysis(ctx, req) (*URLAnalysisResponse, error)
    GenerateHypothesis(ctx, req) (*HypothesisResponse, error)
    GenerateVerificationPlan(ctx, req) (*VerificationPlanResponse, error)
    AnalyzeVerificationResults(ctx, req) (*VerificationAnalysisResponse, error)
    AnalyzeBatchVerification(ctx, req) (*BatchVerificationResult, error)

    // ReAct methods
    GenerateReasoning(ctx, req) (*ReasoningResponse, error)
    GeneratePlan(ctx, reasoning, req) (*PlanResponse, error)
}
```

**Implementation**: `SimpleGenkitProvider` - Firebase Genkit integration supporting:
- Gemini API (default)
- Generic OpenAI-compatible APIs (Ollama, LocalAI, etc.)
- JSON schema validation
- Prompt engineering in `prompt.go`

#### 4. Configuration (`internal/config/`)

Environment-based configuration via `.env`:

```bash
# LLM Configuration
LLM_PROVIDER=gemini  # or "generic" for OpenAI-compatible APIs
LLM_MODEL=
API_KEY=
LLM_BASE_URL=       # For generic provider
LLM_FORMAT=openai   # openai, ollama, raw

# Application
PORT=8090

# Burp Suite Integration
BURP_HOST=
BURP_PORT=8080
```

## Documentation

### Main Documentation (`/docs/`)

- **README.md**: Migration documentation index (5-phase → Detective flow)
- **ENTITY_MAPPING.md**: Detailed entity-by-entity mapping analysis
- **ENTITY_MAPPING_DIAGRAM.md**: Visual ASCII diagrams of the architecture
- **MAPPING_CHEAT_SHEET.md**: Quick reference tables for migration
- **MIGRATION_GUIDE.md**: Step-by-step implementation guide with code examples

### Design Notes (`/notes/`)

- **MAIN_IDEA.md**: Project concept and Human-in-the-loop philosophy
- **DETECTIVE_FLOW_DESIGN.md**: Future "detective game" architecture (1000+ lines)
- **DETECTIVE_GAME_FLOW.md**: Detective game mechanics

## Data Flow

### Full Request Lifecycle

```
1. HTTP Request received by proxy
   ↓
2. RequestFilter heuristic check (skip 60-70%: static assets, health checks)
   ↓
3. SiteContext retrieval (per-host state tracking)
   ↓
4. Enhanced tracking (forms, CRUD, temporal patterns)
   ↓
5. URL Analysis (LLM, cached by pattern) - 90% cache hit rate
   ↓ (if high interest)
6. Phase 2: Reasoning (LLM) → Observations + Hypotheses
   ↓
7. Phase 3: Planning (LLM) → AttackPlans (5-step structure)
   ↓
8. Phase 4: Acting (LLM) → Findings with TestRequests
   ↓
9. Phase 5: Validation → Verify test_requests match plans
   ↓
10. Batch Verification → Parallel test execution
   ↓
11. WebSocket Broadcast → Dashboard
```

### SiteContext Lifecycle

```
Per-host state tracking:
├── URLPatterns      → Cached URL analysis results
├── TechStack        → Detected technologies
├── AppInsights      → Application understanding
├── Forms            → Extracted HTML forms
├── ResourceCRUD     → CRUD resource mapping
└── VerifiedPatterns → Verified vulnerability patterns
```

## Key Features

- **Real-time traffic analysis**: Intercepts HTTP/HTTPS via proxy
- **5-phase ReAct pipeline**: Multi-stage LLM reasoning for thorough analysis
- **URL caching**: 90% reduction in LLM calls via pattern-based caching
- **Active verification**: Executes test requests to validate findings
- **Burp Suite integration**: Works as upstream proxy or standalone
- **Per-site context**: Rich state tracking across requests
- **WebSocket dashboard**: Real-time updates to web interface

## Development Guidelines

### Code Style

- **Language**: Go 1.25.1
- Follow [Go Best Practices](https://go.dev/doc/effective_go) and [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)
- Tests co-located with source files (`*_test.go`)
- Use `sync.RWMutex` for concurrent access to shared state (SiteContext)

### Important Principles

1. **Human-in-the-loop**: This is an assistant, not an automated system
2. **Teach, don't just solve**: Provide explanations with examples from the codebase
3. **Use skills and subagents**: Leverage available tools for speed and quality
4. **Don't make changes without explicit command**: Read-only exploration unless told otherwise

### Key Files to Understand

- `internal/driven/analyzer.go` - Core orchestration logic
- `internal/models/` - Data structures and relationships
- `internal/llm/prompt.go` - Prompt engineering patterns
- `internal/llm/provider.go` - LLM abstraction layer

## Git Worktrees

The project uses Git worktrees for parallel development:

- `worktrees/active-verification/` - Active verification feature
- `worktrees/enhanced-hypothesis/` - Hypothesis enhancements
- `worktrees/enhanced-sitecontext/` - SiteContext improvements

Each worktree has its own CLAUDE.md with branch-specific guidance.

## Current Branch

**Branch**: `feature/plain_agent`

Recent work focuses on refactoring the analysis flow and prompt improvements.

## Security Context

This is a legitimate security testing tool designed for:
- Authorized penetration testing
- Security research and education
- Vulnerability assessment of own applications
- Defensive security analysis

The tool should only be used on systems you own or have explicit permission to test.
