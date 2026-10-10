import type { ScanResult, MigrationComparison } from '../types/contract';

export const mockScanResult: ScanResult = {
  schema_version: '1.0',
  scan_id: 'scan-jx-2026-demo-01',
  started_at: '2026-10-10T14:15:00Z',
  evaluated_at: '2026-10-10T14:15:18Z',
  ruleset_version: '2026.10-nist-fips',
  tool_versions: {
    tshark: '4.2.6',
    rules_engine: '1.0.0-deterministic',
    source_analyzer: 'cryptoscan-adapter-v1',
    cloud_parser: 'aws-adapter-v1'
  },
  input_hashes: {
    network_pcap: 'sha256:4a8b79c02d8f99e32a...',
    source_bundle: 'sha256:88e3b29c91d4021a...',
    cloud_kms: 'sha256:12c49a88df0149bb...',
    cloud_alb: 'sha256:fe99139a04cd123e...',
    cloud_certs: 'sha256:ba770192e104ca81...'
  },
  coverage: {
    network: {
      assessed: 118,
      unknown: 12,
      unsupported: 5,
      failed: 0,
      unit: 'sessions'
    },
    source: {
      assessed: 22,
      unknown: 2,
      unsupported: 0,
      failed: 0,
      unit: 'files'
    },
    cloud: {
      assessed: 21,
      unknown: 0,
      unsupported: 0,
      failed: 0,
      unit: 'resources'
    }
  },
  errors: [],
  findings: [
    {
      schema_version: '1.0',
      id: 'f-src-rsa1024-001',
      asset_id: 'src-py-crypto-service',
      source_type: 'source',
      algorithm: 'RSA',
      parameters: {
        key_bits: 1024,
        mode: null,
        named_group: null
      },
      usage: 'signature',
      evidence_kind: 'declared',
      evidence: [
        {
          file: 'services/identity/crypto_service.py',
          locator: 'lines 42-45',
          detail: 'Crypto.PublicKey.RSA.generate(1024) invoked for session token signing'
        }
      ],
      confidence: 'high',
      quantum_status: 'vulnerable',
      challenge_tier: 'critical',
      classical_issues: ['Key length < 2048 bits is considered broken classically'],
      owner: 'team-identity',
      observed_at: null,
      rule_id: 'R-SRC-RSA-DEPRECATED',
      rationale: 'RSA-1024 is trivially broken by Shor algorithm and unsafe classically under NIST SP 800-131A.',
      recommendation: 'Replace with NIST FIPS 204 ML-DSA-65 (or hybrid ML-DSA/Ed25519) for quantum-resistant signatures.',
      references: [
        'https://csrc.nist.gov/pubs/fips/204/final',
        'https://csrc.nist.gov/Projects/post-quantum-cryptography'
      ]
    },
    {
      schema_version: '1.0',
      id: 'f-net-tls-offer-002',
      asset_id: 'net-stream-44-edge',
      source_type: 'pcap',
      algorithm: 'X25519MLKEM768',
      parameters: {
        key_bits: null,
        mode: null,
        named_group: 'x25519_kyber768_draft00'
      },
      usage: 'key_establishment',
      evidence_kind: 'offered',
      evidence: [
        {
          file: 'traffic/edge_gateway.pcap',
          locator: 'stream 44, frame 112',
          detail: 'ClientHello supported_groups offers hybrid group 0x6399 (draft X25519MLKEM768)'
        }
      ],
      confidence: 'high',
      quantum_status: 'hybrid',
      challenge_tier: 'resilient',
      classical_issues: ['Draft Kyber group ID rather than IANA standardized FIPS 203 ML-KEM codepoint'],
      owner: 'team-edge-net',
      observed_at: '2026-10-10T13:42:01Z',
      rule_id: 'R-NET-TLS-OFFER-HYBRID',
      rationale: 'Client offered hybrid PQ key exchange. Note: Client offers are NOT server selections.',
      recommendation: 'Verify ServerHello negotiation to confirm if server selected PQ or fell back to classical secp256r1.',
      references: ['https://www.iana.org/assignments/tls-parameters', 'https://csrc.nist.gov/pubs/fips/203/final']
    },
    {
      schema_version: '1.0',
      id: 'f-net-tls-sel-003',
      asset_id: 'net-stream-44-edge-selected',
      source_type: 'pcap',
      algorithm: 'secp256r1 (NIST P-256)',
      parameters: {
        key_bits: 256,
        mode: null,
        named_group: 'secp256r1'
      },
      usage: 'key_establishment',
      evidence_kind: 'observed',
      evidence: [
        {
          file: 'traffic/edge_gateway.pcap',
          locator: 'stream 44, frame 116',
          detail: 'ServerHello selected key_share secp256r1, rejecting client hybrid PQ offer'
        }
      ],
      confidence: 'high',
      quantum_status: 'vulnerable',
      challenge_tier: 'critical',
      classical_issues: [],
      owner: 'team-edge-net',
      observed_at: '2026-10-10T13:42:01Z',
      rule_id: 'R-NET-TLS-FALLBACK-CLASSICAL',
      rationale: 'Negotiated session fell back to classical ECDHE. Server does not support post-quantum key exchange on the wire.',
      recommendation: 'Update TLS server termination config to support standardized X25519MLKEM768 group.',
      references: ['https://csrc.nist.gov/pubs/fips/203/final']
    },
    {
      schema_version: '1.0',
      id: 'f-net-tls-unknown-004',
      asset_id: 'net-stream-44-auth',
      source_type: 'pcap',
      algorithm: 'Unknown (Encrypted TLS 1.3 Handshake)',
      parameters: {},
      usage: 'signature',
      evidence_kind: 'observed',
      evidence: [
        {
          file: 'traffic/edge_gateway.pcap',
          locator: 'stream 44, frames 117-120',
          detail: 'TLS 1.3 encrypted handshake records; certificate and CertificateVerify are encrypted on the wire'
        }
      ],
      confidence: 'low',
      quantum_status: 'unknown',
      challenge_tier: 'unknown',
      classical_issues: [],
      owner: 'team-edge-net',
      observed_at: '2026-10-10T13:42:02Z',
      rule_id: 'R-NET-TLS-ENCRYPTED-CERT-LIMIT',
      rationale: 'Passive TLS 1.3 wire capture hides server certificate. Cryptographic algorithm cannot be deduced without out-of-band evidence.',
      recommendation: 'Inspect cloud certificate manager (ACM) or host keystore to determine authentication algorithm.',
      references: ['https://www.rfc-editor.org/rfc/rfc8446.html']
    },
    {
      schema_version: '1.0',
      id: 'f-cld-alb-005',
      asset_id: 'arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/partner-api-alb/4891b0',
      source_type: 'cloud',
      algorithm: 'ECDHE + RSA / ECDSA (TLS 1.3 Classical)',
      parameters: {
        named_group: 'secp256r1, x25519'
      },
      usage: 'key_establishment',
      evidence_kind: 'configured',
      evidence: [
        {
          file: 'cloud/load_balancers.json',
          locator: '/LoadBalancers/2/Listeners/0/SslPolicy',
          detail: 'Configured SSL Policy: ELBSecurityPolicy-TLS13-1-2-2021-06'
        }
      ],
      confidence: 'high',
      quantum_status: 'vulnerable',
      challenge_tier: 'critical',
      classical_issues: [],
      owner: 'team-infra-cloud',
      observed_at: null,
      rule_id: 'R-CLD-ALB-NON-PQ',
      rationale: 'ELBSecurityPolicy-TLS13-1-2-2021-06 provides modern classical TLS 1.3, but lacks hybrid post-quantum key exchange groups.',
      recommendation: 'Upgrade policy to ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 to support ML-KEM hybrid key encapsulation.',
      references: [
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html'
      ]
    },
    {
      schema_version: '1.0',
      id: 'f-src-ed25519-006',
      asset_id: 'src-go-auth-jwt',
      source_type: 'source',
      algorithm: 'Ed25519',
      parameters: {
        key_bits: 256
      },
      usage: 'signature',
      evidence_kind: 'declared',
      evidence: [
        {
          file: 'auth/jwt_issuer.go',
          locator: 'line 88',
          detail: 'ed25519.GenerateKey(rand.Reader) used for API authentication tokens'
        }
      ],
      confidence: 'high',
      quantum_status: 'vulnerable',
      challenge_tier: 'critical',
      classical_issues: [],
      owner: 'team-security-core',
      observed_at: null,
      rule_id: 'R-SRC-ED25519-SHOR',
      rationale: 'Ed25519 is high-grade classical ECC, but completely vulnerable to Shor polynomial-time discrete logarithm factoring.',
      recommendation: 'Plan dual-signature or stateful migration to ML-DSA (FIPS 204). Do NOT assume Ed25519 is post-quantum.',
      references: ['https://csrc.nist.gov/pubs/fips/204/final']
    },
    {
      schema_version: '1.0',
      id: 'f-src-aesecb-007',
      asset_id: 'src-java-crypto-util',
      source_type: 'source',
      algorithm: 'AES-128',
      parameters: {
        key_bits: 128,
        mode: 'ECB'
      },
      usage: 'encryption',
      evidence_kind: 'declared',
      evidence: [
        {
          file: 'backend/src/main/java/CipherUtil.java',
          locator: 'line 112',
          detail: 'Cipher.getInstance("AES/ECB/PKCS5Padding")'
        }
      ],
      confidence: 'high',
      quantum_status: 'not_applicable',
      challenge_tier: 'critical',
      classical_issues: ['ECB mode leaks plaintext pattern structures', 'No authentication tag (AEAD missing)'],
      owner: 'team-backend-java',
      observed_at: null,
      rule_id: 'R-SRC-AES-ECB-INSECURE',
      rationale: 'Classical vulnerability: ECB mode does not randomize identical blocks. Classified as Classical Weakness, separate from Quantum Shor risk.',
      recommendation: 'Migrate immediately to AES-256-GCM or ChaCha20-Poly1305 with random IV per message.',
      references: ['https://csrc.nist.gov/publications/detail/sp/800-38d/final']
    },
    {
      schema_version: '1.0',
      id: 'f-cld-kms-008',
      asset_id: 'arn:aws:kms:eu-west-1:123456789012:key/3b889a-data-encrypt',
      source_type: 'cloud',
      algorithm: 'AES-256',
      parameters: {
        key_bits: 256,
        mode: 'GCM'
      },
      usage: 'encryption',
      evidence_kind: 'configured',
      evidence: [
        {
          file: 'cloud/kms_keys.json',
          locator: '/Keys/4',
          detail: 'KeySpec: SYMMETRIC_DEFAULT; KeyRotationEnabled: false'
        }
      ],
      confidence: 'high',
      quantum_status: 'resistant_primitive',
      challenge_tier: 'resilient',
      classical_issues: ['Automatic key rotation is disabled'],
      owner: 'team-infra-cloud',
      observed_at: null,
      rule_id: 'R-CLD-KMS-ROTATION-FLAG',
      rationale: 'AES-256 is quantum-resistant against Grover search (128-bit quantum security margin). However, operational key rotation is disabled.',
      recommendation: 'Enable automatic AWS KMS annual key rotation to resolve operational posture issue.',
      references: ['https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html']
    }
  ]
};

export const mockMigrationComparison: MigrationComparison = {
  asset_id: 'arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/partner-api-alb/4891b0',
  name: 'partner-api-alb (External Partner Gateway)',
  description: 'Production public Application Load Balancer terminating partner TLS traffic.',
  original: {
    policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06',
    tls_version: 'TLS 1.3 / 1.2',
    quantum_status: 'vulnerable',
    wire_status: 'classical_observed',
    findings: [
      {
        schema_version: '1.0',
        id: 'orig-alb-1',
        asset_id: 'partner-api-alb',
        source_type: 'cloud',
        algorithm: 'ECDHE (Classical Curves)',
        parameters: { named_group: 'secp256r1, x25519' },
        usage: 'key_establishment',
        evidence_kind: 'configured',
        evidence: [{ file: 'cloud/load_balancers.json', locator: '/Listeners/0', detail: 'ELBSecurityPolicy-TLS13-1-2-2021-06' }],
        confidence: 'high',
        quantum_status: 'vulnerable',
        challenge_tier: 'critical',
        classical_issues: [],
        rule_id: 'R-CLD-ALB-NON-PQ',
        rationale: 'Key exchange uses elliptic curve Diffie-Hellman vulnerable to quantum decryption.',
        recommendation: 'Upgrade to AWS Hybrid Post-Quantum policy.',
        references: []
      }
    ]
  },
  upgraded: {
    policy: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09',
    tls_version: 'TLS 1.3 (Hybrid PQ Supported)',
    quantum_status: 'hybrid',
    wire_status: 'unverified',
    findings: [
      {
        schema_version: '1.0',
        id: 'upg-alb-1',
        asset_id: 'partner-api-alb',
        source_type: 'cloud',
        algorithm: 'X25519MLKEM768 (Hybrid Post-Quantum)',
        parameters: { named_group: 'x25519_mlkem768' },
        usage: 'key_establishment',
        evidence_kind: 'configured',
        evidence: [{ file: 'cloud/load_balancers_modified.json', locator: '/Listeners/0', detail: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' }],
        confidence: 'high',
        quantum_status: 'hybrid',
        challenge_tier: 'resilient',
        classical_issues: [],
        rule_id: 'R-CLD-ALB-HYBRID-PQ',
        rationale: 'ALB configured with hybrid post-quantum key encapsulation mechanism (FIPS 203 ML-KEM).',
        recommendation: 'Collect secondary PCAP capture to verify whether client peers actually negotiate hybrid PQ.',
        references: ['https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html']
      }
    ]
  },
  summary_note: 'CRITICAL AUDIT NOTE: Configuration is upgraded to Post-Quantum Capable. Observed wire negotiation remains UNVERIFIED until a client handshake capture validates server key_share selection.'
};
