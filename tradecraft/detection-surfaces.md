---
layout: post
title: "Understanding Detection Surfaces in Modern Environments"
date: 2026-01-29
categories: tradecraft detection
---

## Background

Detection engineering requires understanding the full spectrum of telemetry available in modern environments. This analysis examines common detection surfaces, their capabilities, and limitations from an adversary perspective.

Understanding detection surfaces informs both offensive operational security decisions and defensive detection strategies.

## Detection Surface Categories

### Process and Memory Telemetry

Modern endpoint detection relies heavily on process creation, command-line parameters, and memory operations.

**Available Telemetry**:
- Process creation events (Windows Event ID 4688, Sysmon Event ID 1)
- Command-line arguments and parent-child relationships
- Image load events and unsigned binary execution
- Memory allocation and injection patterns

**Detection Opportunities**:
- Anomalous process ancestry chains
- Suspicious command-line patterns
- Unsigned or uncommon binary execution
- Process injection indicators

**Visibility Gaps**:
- In-memory execution without disk artifacts
- Process hollowing and direct syscalls
- Legitimate binary abuse (LOLBins)

### Network Telemetry

Network communications provide detection opportunities but present operational trade-offs.

**Available Telemetry**:
- DNS queries and responses
- HTTP/HTTPS metadata (SNI, JA3 fingerprints)
- Network flow data and connection patterns
- Protocol anomalies and beaconing

**Detection Opportunities**:
- Command and control beaconing patterns
- Domain reputation and threat intelligence matches
- Certificate and TLS anomalies
- Unusual network destinations or ports

**Visibility Gaps**:
- Encrypted channel contents (HTTPS, TLS 1.3)
- Domain fronting and CDN abuse
- Blending with legitimate traffic patterns

## Operational Considerations

### Trade-off Analysis

Adversaries face operational decisions balancing effectiveness against detection risk:

**Execution Method**: Disk-based binaries provide reliability but increase detection surface. In-memory execution reduces artifacts but increases implementation complexity.

**Network Communications**: Direct connections enable reliable C2 but expose infrastructure. Domain fronting and legitimate service abuse reduce detection risk but add operational constraints.

**Credential Access**: LSASS dumping is well-documented but heavily monitored. Alternative techniques reduce visibility but may have reliability constraints.

### Decision Framework

Operational security decisions should consider:

1. **Detection Likelihood**: Probability of technique detection given environment
2. **Impact of Detection**: Operational consequences if technique is detected
3. **Alternative Methods**: Availability of lower-risk alternatives
4. **Mission Requirements**: Necessity of technique for objective completion

## Defensive Recommendations

### Detection Strategy

Effective detection requires layered telemetry and behavioral analytics:

1. **Baseline Normal Activity**: Understand legitimate process patterns and network behaviors
2. **Anomaly Detection**: Identify deviations from established baselines
3. **Threat Intelligence**: Incorporate known adversary patterns and IOCs
4. **Behavioral Analytics**: Detect technique patterns regardless of specific implementations

### Telemetry Priorities

Focus telemetry collection on high-value detection surfaces:

- Process execution and command-line logging (Sysmon, EDR)
- PowerShell script block logging and transcription
- DNS query logging with historical retention
- Network flow data with metadata extraction

## Conclusion

Understanding detection surfaces from both offensive and defensive perspectives improves security outcomes. Adversaries must balance operational requirements against detection risk, while defenders must optimize telemetry collection and detection logic.

Continuous improvement requires analyzing adversary tradecraft, understanding detection gaps, and iteratively enhancing visibility and detection capabilities.

---

**Detection Artifacts Summary**:
- Process creation telemetry: High visibility, moderate evasion difficulty
- Network communications: Moderate visibility, high evasion complexity
- Memory operations: Low baseline visibility, increasing with EDR adoption

**Defensive Priorities**:
1. Comprehensive process execution logging
2. PowerShell visibility and monitoring
3. DNS and network flow collection
4. Behavioral analytics and anomaly detection

*Research notes on detection engineering and operational security trade-offs.*
