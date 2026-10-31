
# HMG Shared Contracts

## Incoming Security Event

All event producers must follow shared/event_schema.json.

### Required fields
- event_id
- timestamp
- source_ip
- source_mac
- honeypot
- event
- details

### Producers
- Member 1: Gateway and network events
- Member 2: HTTP, SSH and SMB honeypot events

### Consumer
- Member 3: Intelligence engine

### Downstream consumer
- Member 4: FastAPI backend and React dashboard

## Member 3 Processing Pipeline

1. Event validation
2. Event correlation
3. Behaviour analysis
4. Risk scoring
5. IOC extraction
6. MITRE ATT&CK mapping
7. Incident generation
8. Audit recording

## Response Policy

- The intelligence engine produces recommendations.
- The administrator approves or dismisses quarantine.
- Member 1's containment module applies approved firewall changes.
- Administrator decisions must be recorded as new audit entries.

## Audit Policy

- Audit records are append-only through the application.
- Ordinary update and delete operations are blocked.
- Hash-chain verification detects modifications.
- The dashboard must use read-only access to audit records.

## Change Management

Shared contracts must not be changed independently.
