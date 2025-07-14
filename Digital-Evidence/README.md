# Decentralized Document Registry and Verification System

A comprehensive blockchain-based smart contract platform for secure document management, enabling immutable registration, multi-party verification workflows, and granular access control for digital document authentication.

## Overview

This smart contract provides a decentralized solution for document registration, verification, and access management on the blockchain. It ensures document integrity through cryptographic hashing, implements multi-party verification workflows, and provides fine-grained access control mechanisms.

## Features

### Core Functionality
- **Document Registration**: Register documents with cryptographic hash verification
- **Document Verification**: Multi-party verification system with approval/rejection workflows
- **Access Control**: Granular permissions for viewing and verifying documents
- **Revision Management**: Track document revisions with version control
- **Immutable Records**: Blockchain-based immutable document history

### Security Features
- Comprehensive input validation
- Owner-based authorization
- Verifier permission management
- Finalization controls to prevent tampering
- Buffer length validation for all inputs

## Data Structures

### Document Record
```clarity
{
    owner-address: principal,
    content-hash: (buff 32),
    timestamp-created: uint,
    verification-status: (string-ascii 20),
    verifier-address: (optional principal),
    metadata-content: (string-utf8 256),
    revision-count: uint,
    is-finalized: bool
}
```

### Access Permissions
```clarity
{
    can-view: bool,
    can-verify: bool
}
```

## Verification Status

- **PENDING**: Document awaiting verification
- **VERIFIED**: Document successfully verified
- **REJECTED**: Document verification rejected

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| u100 | ERR-UNAUTHORIZED-ACCESS | Caller lacks required permissions |
| u101 | ERR-DOCUMENT-ALREADY-EXISTS | Document ID already registered |
| u102 | ERR-DOCUMENT-NOT-FOUND | Document ID not found in registry |
| u103 | ERR-VERIFICATION-ALREADY-COMPLETED | Document already finalized |
| u104 | ERR-INVALID-DOCUMENT-ID | Invalid document ID format |
| u105 | ERR-INVALID-HASH-FORMAT | Invalid hash format |
| u106 | ERR-INVALID-METADATA-FORMAT | Invalid metadata format |
| u107 | ERR-INVALID-VERIFIER-ADDRESS | Invalid verifier address |
| u108 | ERR-INVALID-PARAMETERS | Invalid function parameters |
| u109 | ERR-INSUFFICIENT-PERMISSIONS | Insufficient permissions for operation |
| u110 | ERR-NULL-INPUT-PROVIDED | Null input provided |

## Functions

### Read-Only Functions

#### `get-document-details`
```clarity
(get-document-details (document-id (buff 32)))
```
Retrieves complete document information including owner, hash, status, and metadata.

#### `get-verifier-permissions`
```clarity
(get-verifier-permissions (document-id (buff 32)) (verifier-address principal))
```
Returns access permissions for a specific verifier on a document.

#### `check-document-exists`
```clarity
(check-document-exists (document-id (buff 32)))
```
Checks if a document exists in the registry.

### Public Functions

#### Document Management

##### `register-new-document`
```clarity
(register-new-document 
    (document-id (buff 32))
    (content-hash (buff 32))
    (metadata-info (string-utf8 256)))
```
Registers a new document in the system.

**Parameters:**
- `document-id`: Unique 32-byte identifier for the document
- `content-hash`: SHA256 hash of the document content
- `metadata-info`: Document metadata (max 256 UTF-8 characters)

**Requirements:**
- Document ID must not already exist
- All parameters must be valid format
- Caller becomes the document owner

##### `update-document-revision`
```clarity
(update-document-revision
    (document-id (buff 32))
    (new-content-hash (buff 32))
    (updated-metadata (string-utf8 256)))
```
Updates an existing document with new content and metadata.

**Requirements:**
- Caller must be document owner
- Document must not be finalized
- Increments revision count
- Resets verification status to PENDING

#### Verification Functions

##### `verify-document`
```clarity
(verify-document (document-id (buff 32)))
```
Verifies a document (sets status to VERIFIED).

**Requirements:**
- Caller must have verification permissions
- Document must exist and not be finalized
- Finalizes the document upon verification

##### `reject-document`
```clarity
(reject-document (document-id (buff 32)))
```
Rejects a document (sets status to REJECTED).

**Requirements:**
- Caller must have verification permissions
- Document must exist and not be finalized
- Finalizes the document upon rejection

#### Access Control Functions

##### `grant-verifier-access`
```clarity
(grant-verifier-access
    (document-id (buff 32))
    (verifier-principal principal)
    (can-view-document bool)
    (can-verify-document bool))
```
Grants access permissions to a verifier.

**Parameters:**
- `document-id`: Target document ID
- `verifier-principal`: Address of the verifier
- `can-view-document`: Whether verifier can view the document
- `can-verify-document`: Whether verifier can verify/reject the document

**Requirements:**
- Caller must be document owner
- Verifier address must be valid

##### `revoke-verifier-access`
```clarity
(revoke-verifier-access
    (document-id (buff 32))
    (verifier-principal principal))
```
Revokes all access permissions from a verifier.

**Requirements:**
- Caller must be document owner
- Verifier address must be valid

## Usage Examples

### Register a Document
```clarity
(register-new-document 
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    u"Medical Certificate - John Doe - 2024")
```

### Grant Verification Access
```clarity
(grant-verifier-access
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    'SP1234567890ABCDEF1234567890ABCDEF12345678
    true   ;; can view
    true)  ;; can verify
```

### Verify Document
```clarity
(verify-document 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)
```

## Security Considerations

1. **Input Validation**: All inputs are validated for proper format and length
2. **Access Control**: Strict permission checks for all operations
3. **Immutability**: Documents cannot be modified after finalization
4. **Ownership**: Only document owners can grant/revoke access
5. **Hash Integrity**: Document content is verified through cryptographic hashes

## Best Practices

1. **Document IDs**: Use cryptographically secure random 32-byte identifiers
2. **Content Hashes**: Always use SHA256 hashes of document content
3. **Metadata**: Keep metadata concise and relevant (256 character limit)
4. **Access Management**: Regularly audit and update verifier permissions
5. **Verification**: Implement proper verification workflows before finalizing documents

## Limitations

- Document metadata is limited to 256 UTF-8 characters
- Document IDs must be exactly 32 bytes
- Content hashes must be exactly 32 bytes (SHA256)
- Documents cannot be modified after finalization
- Maximum one verifier per document verification