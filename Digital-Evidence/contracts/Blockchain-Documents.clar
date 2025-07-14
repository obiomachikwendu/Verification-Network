;; Decentralized Document Registry and Verification System Smart Contract
;; A comprehensive blockchain-based platform for secure document management,
;; enabling immutable registration, multi-party verification workflows, and
;; granular access control for digital document authentication

;; ERROR CONSTANTS

(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-DOCUMENT-ALREADY-EXISTS (err u101))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u102))
(define-constant ERR-VERIFICATION-ALREADY-COMPLETED (err u103))
(define-constant ERR-INVALID-DOCUMENT-ID (err u104))
(define-constant ERR-INVALID-HASH-FORMAT (err u105))
(define-constant ERR-INVALID-METADATA-FORMAT (err u106))
(define-constant ERR-INVALID-VERIFIER-ADDRESS (err u107))
(define-constant ERR-INVALID-PARAMETERS (err u108))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u109))
(define-constant ERR-NULL-INPUT-PROVIDED (err u110))

;; STATUS CONSTANTS

(define-constant verification-status-pending "PENDING")
(define-constant verification-status-verified "VERIFIED")
(define-constant verification-status-rejected "REJECTED")

;; DATA STRUCTURES

(define-data-var document-template 
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
    {
        owner-address: tx-sender,
        content-hash: 0x0000000000000000000000000000000000000000000000000000000000000000,
        timestamp-created: u0,
        verification-status: verification-status-pending,
        verifier-address: none,
        metadata-content: u"",
        revision-count: u0,
        is-finalized: false
    }
)

;; STORAGE MAPS

(define-map document-registry
    { document-id: (buff 32) }
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
)

(define-map access-permissions
    { document-id: (buff 32), verifier-principal: principal }
    { can-view: bool, can-verify: bool }
)

;; VALIDATION UTILITIES

(define-private (is-valid-buffer-length (input-buffer (buff 32)))
    (is-eq (len input-buffer) u32))

(define-private (is-valid-metadata-length (metadata-input (string-utf8 256)))
    (and (<= (len metadata-input) u256) (> (len metadata-input) u0)))

(define-private (is-valid-principal (principal-input principal))
    (and 
        (not (is-eq principal-input tx-sender))
        (not (is-eq principal-input (as-contract tx-sender)))))

;; ENHANCED VALIDATION FUNCTIONS

(define-private (validate-document-id (document-identifier (buff 32)))
    (if (is-valid-buffer-length document-identifier)
        (ok document-identifier)
        ERR-INVALID-DOCUMENT-ID))

(define-private (validate-content-hash (hash-input (buff 32)))
    (if (is-valid-buffer-length hash-input)
        (ok hash-input)
        ERR-INVALID-HASH-FORMAT))

(define-private (validate-metadata (metadata-input (string-utf8 256)))
    (if (is-valid-metadata-length metadata-input)
        (ok metadata-input)
        ERR-INVALID-METADATA-FORMAT))

(define-private (validate-verifier-principal (verifier-input principal))
    (if (is-valid-principal verifier-input)
        (ok verifier-input)
        ERR-INVALID-VERIFIER-ADDRESS))

;; SAFE VALIDATION HELPERS

(define-private (safely-validate-document-identifier (document-id (buff 32)))
    (begin
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (validate-document-id document-id)))

(define-private (safely-validate-metadata-content (metadata-string (string-utf8 256)))
    (begin
        (asserts! (is-valid-metadata-length metadata-string) ERR-INVALID-METADATA-FORMAT)
        (validate-metadata metadata-string)))

(define-private (safely-validate-verifier-address (verifier-principal principal))
    (begin
        (asserts! (is-valid-principal verifier-principal) ERR-INVALID-VERIFIER-ADDRESS)
        (validate-verifier-principal verifier-principal)))

;; DOCUMENT RETRIEVAL FUNCTIONS

(define-private (get-document-record-safely (document-id (buff 32)))
    (begin
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (let ((validated-id-result (validate-document-id document-id)))
            (match validated-id-result
                validated-document-id 
                (match (map-get? document-registry { document-id: validated-document-id })
                    document-record (ok document-record)
                    ERR-DOCUMENT-NOT-FOUND)
                validation-error (err validation-error)))))

(define-private (check-document-ownership (document-id (buff 32)) (caller-principal principal))
    (match (get-document-record-safely document-id)
        document-record 
        (ok (is-eq (get owner-address document-record) caller-principal))
        error-result (err error-result)))

;; READ-ONLY FUNCTIONS

(define-read-only (get-document-details (document-id (buff 32)))
    (begin
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (get-document-record-safely document-id)))

(define-read-only (get-verifier-permissions (document-id (buff 32)) (verifier-address principal))
    (begin
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (is-valid-principal verifier-address) ERR-INVALID-VERIFIER-ADDRESS)
        (let ((validated-id-result (safely-validate-document-identifier document-id))
              (validated-verifier-result (safely-validate-verifier-address verifier-address)))
            (match validated-id-result
                validated-document-id 
                (match validated-verifier-result
                    validated-verifier-principal 
                    (match (map-get? access-permissions 
                        { document-id: validated-document-id, verifier-principal: validated-verifier-principal })
                        permission-record (ok permission-record)
                        (ok { can-view: false, can-verify: false }))
                    validation-error (err validation-error))
                validation-error (err validation-error)))))

(define-read-only (check-document-exists (document-id (buff 32)))
    (begin
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (ok (is-some (map-get? document-registry { document-id: document-id })))))

;; DOCUMENT REGISTRATION FUNCTIONS

(define-public (register-new-document 
    (document-id (buff 32))
    (content-hash (buff 32))
    (metadata-info (string-utf8 256)))
    (begin
        ;; Validate all input parameters
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (is-valid-buffer-length content-hash) ERR-INVALID-HASH-FORMAT)
        (asserts! (is-valid-metadata-length metadata-info) ERR-INVALID-METADATA-FORMAT)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id))
              (validated-hash-result (validate-content-hash content-hash))
              (validated-metadata-result (safely-validate-metadata-content metadata-info)))
            (match validated-id-result
                validated-document-id 
                (match validated-hash-result
                    validated-content-hash 
                    (match validated-metadata-result
                        validated-metadata-content 
                        (match (map-get? document-registry { document-id: validated-document-id })
                            existing-record ERR-DOCUMENT-ALREADY-EXISTS
                            (ok (map-set document-registry
                                { document-id: validated-document-id }
                                {
                                    owner-address: tx-sender,
                                    content-hash: validated-content-hash,
                                    timestamp-created: block-height,
                                    verification-status: verification-status-pending,
                                    verifier-address: none,
                                    metadata-content: validated-metadata-content,
                                    revision-count: u1,
                                    is-finalized: false
                                })))
                        validation-error (err validation-error))
                    validation-error (err validation-error))
                validation-error (err validation-error)))))

;; DOCUMENT MODIFICATION FUNCTIONS

(define-public (update-document-revision
    (document-id (buff 32))
    (new-content-hash (buff 32))
    (updated-metadata (string-utf8 256)))
    (begin
        ;; Validate all input parameters
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (is-valid-buffer-length new-content-hash) ERR-INVALID-HASH-FORMAT)
        (asserts! (is-valid-metadata-length updated-metadata) ERR-INVALID-METADATA-FORMAT)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id))
              (validated-hash-result (validate-content-hash new-content-hash))
              (validated-metadata-result (safely-validate-metadata-content updated-metadata)))
            (match validated-id-result
                validated-document-id 
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-document-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-record (unwrap-panic (map-get? document-registry { document-id: validated-document-id }))))
                        (match validated-hash-result
                            validated-new-hash 
                            (match validated-metadata-result
                                validated-metadata-content 
                                (begin
                                    (asserts! (is-eq (get owner-address current-record) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get is-finalized current-record)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set document-registry
                                        { document-id: validated-document-id }
                                        (merge current-record
                                            {
                                                content-hash: validated-new-hash,
                                                metadata-content: validated-metadata-content,
                                                timestamp-created: block-height,
                                                revision-count: (+ (get revision-count current-record) u1),
                                                verification-status: verification-status-pending,
                                                is-finalized: false
                                            }))))
                                validation-error (err validation-error))
                            validation-error (err validation-error))))
                validation-error (err validation-error)))))

;; DOCUMENT VERIFICATION FUNCTIONS

(define-public (verify-document (document-id (buff 32)))
    (begin
        ;; Validate input parameter
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id)))
            (match validated-id-result
                validated-document-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-document-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-record (unwrap-panic (map-get? document-registry { document-id: validated-document-id }))))
                        (let ((permission-result (get-verifier-permissions validated-document-id tx-sender)))
                            (match permission-result
                                permission-record
                                (begin
                                    (asserts! (get can-verify permission-record) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get is-finalized current-record)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set document-registry
                                        { document-id: validated-document-id }
                                        (merge current-record
                                            {
                                                verification-status: verification-status-verified,
                                                verifier-address: (some tx-sender),
                                                is-finalized: true
                                            }))))
                                permission-error ERR-UNAUTHORIZED-ACCESS))))
                validation-error (err validation-error)))))

(define-public (reject-document (document-id (buff 32)))
    (begin
        ;; Validate input parameter
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id)))
            (match validated-id-result
                validated-document-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-document-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-record (unwrap-panic (map-get? document-registry { document-id: validated-document-id }))))
                        (let ((permission-result (get-verifier-permissions validated-document-id tx-sender)))
                            (match permission-result
                                permission-record
                                (begin
                                    (asserts! (get can-verify permission-record) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get is-finalized current-record)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set document-registry
                                        { document-id: validated-document-id }
                                        (merge current-record
                                            {
                                                verification-status: verification-status-rejected,
                                                verifier-address: (some tx-sender),
                                                is-finalized: true
                                            }))))
                                permission-error ERR-UNAUTHORIZED-ACCESS))))
                validation-error (err validation-error)))))

;; ACCESS CONTROL MANAGEMENT FUNCTIONS

(define-public (grant-verifier-access
    (document-id (buff 32))
    (verifier-principal principal)
    (can-view-document bool)
    (can-verify-document bool))
    (begin
        ;; Validate all input parameters
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (is-valid-principal verifier-principal) ERR-INVALID-VERIFIER-ADDRESS)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id))
              (validated-verifier-result (safely-validate-verifier-address verifier-principal)))
            (match validated-id-result
                validated-document-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-document-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-record (unwrap-panic (map-get? document-registry { document-id: validated-document-id }))))
                        (match validated-verifier-result
                            validated-verifier-principal
                            (begin
                                (asserts! (is-eq (get owner-address current-record) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                (ok (map-set access-permissions
                                    { document-id: validated-document-id, verifier-principal: validated-verifier-principal }
                                    { 
                                        can-view: can-view-document, 
                                        can-verify: can-verify-document 
                                    })))
                            validation-error (err validation-error))))
                validation-error (err validation-error)))))

(define-public (revoke-verifier-access
    (document-id (buff 32))
    (verifier-principal principal))
    (begin
        ;; Validate all input parameters
        (asserts! (is-valid-buffer-length document-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (is-valid-principal verifier-principal) ERR-INVALID-VERIFIER-ADDRESS)
        
        (let ((validated-id-result (safely-validate-document-identifier document-id))
              (validated-verifier-result (safely-validate-verifier-address verifier-principal)))
            (match validated-id-result
                validated-document-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-document-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-record (unwrap-panic (map-get? document-registry { document-id: validated-document-id }))))
                        (match validated-verifier-result
                            validated-verifier-principal
                            (begin
                                (asserts! (is-eq (get owner-address current-record) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                (ok (map-delete access-permissions
                                    { document-id: validated-document-id, verifier-principal: validated-verifier-principal })))
                            validation-error (err validation-error))))
                validation-error (err validation-error)))))