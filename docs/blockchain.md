\# NetSecureAI Blockchain Attestation



\## Overview



NetSecureAI uses Hyperledger Fabric as an integrity and attestation layer for

security compliance analysis. The blockchain does not replace the existing

database or compliance engine. It provides tamper-evident records that can be

used to verify that analysis evidence and related outputs have not been

modified after anchoring.



\## Architecture



The blockchain integration follows this flow:



Configuration / Analysis

&#x20;       |

&#x20;       v

SHA-256 Hashing

&#x20;       |

&#x20;       v

FastAPI Blockchain API

&#x20;       |

&#x20;       v

Fabric Gateway

&#x20;       |

&#x20;       v

Hyperledger Fabric

&#x20;       |

&#x20;       v

Evidence Verification



\## Components



\### Backend Blockchain Module



Location:



`backend/blockchain/`



Main components:



\- `hashing.py` - canonicalizes data and generates SHA-256 hashes.

\- `models.py` - defines blockchain anchor and verification request/response models.

\- `config.py` - stores Fabric gateway configuration through environment variables.

\- `fabric\_client.py` - communicates with the Fabric Gateway.



\### Fabric Chaincode



Location:



`blockchain/chaincode/evidence/`



The evidence chaincode stores audit metadata and cryptographic hashes.



The blockchain record contains:



\- Record ID

\- Record type

\- Analysis ID

\- Device ID

\- Vendor

\- Framework

\- SHA-256 hash

\- Hash algorithm

\- Actor

\- Timestamp

\- Previous hash



Raw configuration files, passwords, private keys, and full sensitive reports

are not stored on-chain.



\### Fabric Gateway



Location:



`blockchain/gateway/`



The gateway provides an HTTP interface between the FastAPI backend and

Hyperledger Fabric.



Main operations:



\- Health check

\- Anchor evidence

\- Verify evidence

\- Retrieve an anchored record



\## Hashing



NetSecureAI uses SHA-256.



Before hashing, JSON data is canonicalized by:



\- Sorting object keys

\- Using consistent JSON separators

\- Encoding the resulting data as UTF-8



This ensures that the same logical payload produces the same hash.



\## Anchoring



When an analysis is anchored:



1\. The backend constructs the attestation payload.

2\. The payload is canonicalized.

3\. A SHA-256 hash is generated.

4\. The hash and audit metadata are sent to the Fabric Gateway.

5\. The Gateway submits the record to Hyperledger Fabric.

6\. Fabric returns a transaction ID.

7\. The transaction ID and hash can be used for later verification.



\## Verification



During verification:



1\. The supplied analysis data is reconstructed.

2\. A new SHA-256 hash is calculated.

3\. The corresponding blockchain record is retrieved.

4\. The calculated hash is compared with the blockchain hash.

5\. Matching hashes result in successful verification.

6\. A different hash is reported as tampered.



\## Tested Integration



The integration was tested through the FastAPI API.



\### Successful verification



The original payload produced the same hash as the blockchain record:



\- Supplied hash: `d449a8bdb38e10cff42dc0f08deedc21c9e93f69e0f78c63c04f19445c879c11`

\- Blockchain hash: `d449a8bdb38e10cff42dc0f08deedc21c9e93f69e0f78c63c04f19445c879c11`

\- Verification result: `verified: true`



\### Tamper detection



After modifying the payload, the calculated hash changed:



\- Supplied hash: `0274d6a3fff9c38fb110fe1247454343654bcb3dc283f26149cef01b5616c6c9`

\- Blockchain hash: `d449a8bdb38e10cff42dc0f08deedc21c9e93f69e0f78c63c04f19445c879c11`

\- Verification result: `verified: false`

\- Status: `tampered`



This demonstrates that modifications to the attested payload can be detected.



\## Security Design



The blockchain is used as an integrity layer rather than the primary application

database.



The design follows these principles:



\- Store hashes and metadata instead of raw sensitive data.

\- Use SHA-256 for integrity verification.

\- Keep the compliance analysis engine independent from blockchain availability.

\- Use a permissioned blockchain network.

\- Use transaction IDs as audit references.

\- Support verification of previously anchored evidence.



\## Current Fabric Configuration



\- Blockchain: Hyperledger Fabric

\- Channel: `mychannel`

\- Chaincode: `evidence`

\- Chaincode version: `2`

\- Chaincode sequence: `2`

\- Endorsement policy: Org1 or Org2 peer



\## Future Extensions



Possible future extensions include:



\- Anchoring reports and findings

\- Audit history retrieval

\- Previous-hash chaining for stronger audit continuity

\- UI verification badges

\- Persistent transaction/audit references

\- Additional organizations and permissioned-network deployment

