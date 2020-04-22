import Foundation

public class DIDDocumentBuilder {
    private var document: DIDDocument?

    init(_ did: DID, _ store: DIDStore) {
        self.document = DIDDocument(did)
        self.document!.getMeta().setStore(store)
    }

    init(_ doc: DIDDocument) { // Make a copy
        self.document = DIDDocument(doc)
    }

    private func getSubject() throws -> DID {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        return document!.subject
    }

    private func appendPublicKey(_ id: DIDURL,
                                _ controller: DID,
                                _ keyBase58: String) throws -> DIDDocumentBuilder {

        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard Base58.bytesFromBase58(keyBase58).count == HDKey.PUBLICKEY_BYTES else {
            throw DIDError.illegalArgument("Invalid public key.")
        }

        let publicKey = PublicKey(id, controller, keyBase58)
        guard document!.appendPublicKey(publicKey) else {
            throw DIDError.illegalArgument("append PublicKey failed")
        }

        return self
    }

    /// Add public key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding public key failed
    /// - Returns: DIDDocumentBuilder
    public func appendPublicKey(with id: DIDURL,
                             controller: String,
                              keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id, DID(controller), keyBase58)
    }

    /// Add public key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding public key faile
    /// - Returns: DIDDocumentBuilder
    public func appendPublicKey(with id: String,
                             controller: String,
                              keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendPublicKey(DIDURL(getSubject(), id), DID(controller), keyBase58)
    }

    private func removePublicKey(_ id: DIDURL,
                                 _ force: Bool) throws -> DIDDocumentBuilder {
    
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard try document!.removePublicKey(id, force) else {
            throw DIDError.illegalArgument("Failed to remove public key")
        }

        return self
    }

    /// Remove public key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - force: Whether to forcibly delete the public key
    /// - Throws: Throws an error when the removal of the public key fails
    /// - Returns: DIDDocumentBuilder
    public func removePublicKey(with id: DIDURL,
                               _ force: Bool) throws -> DIDDocumentBuilder {
        return try removePublicKey(id, force)
    }

    /// Remove public key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - force: Whether to forcibly delete the public key
    /// - Throws: Throws an error when the removal of the public key fails
    /// - Returns: DIDDocumentBuilder
    public func removePublicKey(with id: String,
                               _ force: Bool) throws -> DIDDocumentBuilder {
        return try removePublicKey(DIDURL(getSubject(), id), force)
    }

    /// Remove public key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the public key fails
    /// - Returns: DIDDocumentBuilder
    public func removePublicKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removePublicKey(id, false)
    }

    /// Remove public key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the public key fails
    /// - Returns: DIDDocumentBuilder
    public func removePublicKey(with id: String) throws -> DIDDocumentBuilder {
        return try removePublicKey(DIDURL(getSubject(), id), false)
    }

    // authenticationKey scope
    private func appendAuthenticationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        let key = document!.publicKey(ofId: id)
        guard let _ = key else {
            throw DIDError.illegalArgument("PublicKey '\(id)' not exists.")
        }
        guard document!.appendAuthenticationKey(id) else {
            throw DIDError.illegalArgument("Key cannot used for authentication.")
        }

        return self
    }

    /// Append authentication key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Error thrown when adding authentication key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthenticationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(id)
    }

    /// Append authentication key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Error thrown when adding authentication key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthenticationKey(with id: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(DIDURL(getSubject(), id))
    }

    private func appendAuthenticationKey(_ id: DIDURL,
                                         _ keyBase58: String) throws -> DIDDocumentBuilder {

        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard Base58.bytesFromBase58(keyBase58).count == HDKey.PUBLICKEY_BYTES else {
            throw DIDError.illegalArgument("Invalid public key.")
        }

        let key = PublicKey(id, try getSubject(), keyBase58)
        key.setAuthenticationKey(true)
        guard document!.appendPublicKey(key) else {
            throw DIDError.illegalArgument("append public key failed.")
        }

        return self
    }

    /// Append authentication key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authentication key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthenticationKey(with id: DIDURL,
                                      keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(id, keyBase58)
    }

    /// Append authentication key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authentication key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthenticationKey(with id: String,
                                      keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(DIDURL(getSubject(), id), keyBase58)
    }

    private func removeAuthenticationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.removeAuthenticationKey(id) else {
            throw DIDError.illegalArgument("PublicKey id '\(id)' not exist. or Cannot remove the default PublicKey from authentication.")
        }

        return self
    }

    /// Remove authentication key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the authentication key fails
    /// - Returns: DIDDocumentBuilder
    public func removeAuthenticationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeAuthenticationKey(id)
    }

    /// Remove authentication key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the authentication key fails
    /// - Returns: DIDDocumentBuilder
    public func removeAuthenticationKey(with id: String) throws -> DIDDocumentBuilder {
        return try removeAuthenticationKey(DIDURL(getSubject(), id))
    }

    private func appendAuthorizationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        let key = document!.publicKey(ofId: id)
        guard let _ = key else {
            throw DIDError.illegalArgument("PublicKey '\(id)' not exists.")
        }
        // use the ref "key" rather than parameter "id".
        guard document!.appendAuthorizationKey(id) else {
            throw DIDError.illegalArgument("Make sure that controller should be current DID subject.")
        }

        return self
    }

    /// Append authorization key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try appendAuthorizationKey(id)
    }

    /// Append authorization key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(with id: String) throws -> DIDDocumentBuilder  {
        return try appendAuthorizationKey(DIDURL(getSubject(), id))
    }

    /// Append authorization key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(_ id: DIDURL,
                                       _ controller: DID,
                                       _ keyBase58: String) throws -> DIDDocumentBuilder {

        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard Base58.bytesFromBase58(keyBase58).count == HDKey.PUBLICKEY_BYTES else {
            throw DIDError.illegalArgument("Invalid public key.")
        }

        let key = PublicKey(id, controller, keyBase58)
        key.setAthorizationKey(true)
        _ = document!.appendPublicKey(key)

        return self
    }

    /// Append authorization key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(with id: DIDURL,
                                    controller: DID,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(id, controller, keyBase58)
    }

    /// Append authorization key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(with id: String,
                                    controller: String,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(DIDURL(getSubject(), id), DID(controller), keyBase58)
    }

    /// Append authorization key
    /// - Parameters:
    ///   - id: The DID identifier and a custom URI fragment constitute
    ///   - controller: DID of the corresponding private key controller
    ///   - keyBase58: Base58 encoded public key
    /// - Throws: Error thrown when adding authorization key faile
    /// - Returns: DIDDocumentBuilder
    public func appendAuthorizationKey(with id: String,
                                    controller: DID,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(DIDURL(getSubject(), id), controller, keyBase58)
    }

    private func authorizationDid(_ id: DIDURL,
                                  _ controller: DID,
                                  _ key: DIDURL?) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard try controller != getSubject() else {
            throw DIDError.illegalArgument("Invalid controller.")
        }

        let controllerDoc: DIDDocument
        do {
            controllerDoc = try controller.resolve()
        } catch {
            throw DIDError.didResolveError("Can not resolve \(controller) DID.")
        }

        var usedKey: DIDURL? = key
        if  usedKey == nil {
            usedKey = controllerDoc.defaultPublicKey
        }

        // Check the key should be a authentication key
        let targetKey = controllerDoc.authenticationKey(ofId: usedKey!)
        guard let _ = targetKey else {
            throw DIDError.illegalArgument("the key '\(key!.toString())' should be a authentication key")
        }

        let pk = PublicKey(id, targetKey!.getType(), controller, targetKey!.publicKeyBase58)
        pk.setAthorizationKey(true)
        _ = document!.appendPublicKey(pk)

        return self
    }

    /// <#Description#>
    /// - Parameters:
    ///   - id: <#id description#>
    ///   - controller: <#controller description#>
    ///   - key: <#key description#>
    /// - Throws: <#description#>
    /// - Returns: <#description#>
    public func authorizationDid(with id: DIDURL,
                              controller: DID,
                                     key: DIDURL) throws -> DIDDocumentBuilder {

        return try authorizationDid(id, controller, key)
    }

    /// <#Description#>
    /// - Parameters:
    ///   - id: <#id description#>
    ///   - controller: <#controller description#>
    /// - Throws: <#description#>
    /// - Returns: <#description#>
    public func authorizationDid(with id: DIDURL,
                              controller: DID) throws -> DIDDocumentBuilder {

        return try authorizationDid(id, controller, nil)
    }

    /// <#Description#>
    /// - Parameters:
    ///   - id: <#id description#>
    ///   - controller: <#controller description#>
    ///   - key: <#key description#>
    /// - Throws: <#description#>
    /// - Returns: <#description#>
    public func authorizationDid(with id: String,
                              controller: String,
                                     key: String) throws -> DIDDocumentBuilder {
        let controllerId = try DID(controller)
        let usedKey:DIDURL = try DIDURL(controllerId, key)

        return try authorizationDid(DIDURL(getSubject(), id), controllerId, usedKey)
    }

    /// <#Description#>
    /// - Parameters:
    ///   - id: <#id description#>
    ///   - controller: <#controller description#>
    /// - Throws: <#description#>
    /// - Returns: <#description#>
    public func authorizationDid(with id: String,
                              controller: String) throws -> DIDDocumentBuilder {

        return try authorizationDid(DIDURL(getSubject(), id), DID(controller), nil)
    }

    private func removeAuthorizationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.removeAuthorizationKey(id) else {
            throw DIDError.illegalArgument("remove authorizationKey fails")
        }

        return self
    }

    /// Remove authorization key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the authorization key fails
    /// - Returns: DIDDocumentBuilder
    public func removeAuthorizationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeAuthorizationKey(id)
    }

    /// Remove authorization key
    /// - Parameter id: The DID identifier and a custom URI fragment constitute
    /// - Throws: Throws an error when the removal of the authorization key fails
    /// - Returns: DIDDocumentBuilder
    public func removeAuthorizationKey(with id: String) throws -> DIDDocumentBuilder {
        return try removeAuthorizationKey(DIDURL(getSubject(), id))
    }

    /// Append credential
    /// - Parameter credential: A verifiable credential
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with credential: VerifiableCredential) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.appendCredential(credential) else {
            throw DIDError.illegalArgument("Credential already exist. or Credential not owned by self.")
        }

        return self
    }

    private func appendCredential(_ id: DIDURL,
                                  _ types: Array<String>?,
                                  _ subject: Dictionary<String, String>,
                                  _ expirationDate: Date?,
                                  _ storePassword: String) throws -> DIDDocumentBuilder  {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        guard !subject.isEmpty && !storePassword.isEmpty else {
            throw DIDError.illegalArgument("storePassword is empty or subject is empty.")
        }

        let realTypes: Array<String>
        if let _ = types {
            realTypes = types!
        } else {
            realTypes = Array<String>(["SelfProclaimedCredential"])
        }

        let realExpires: Date
        if let _ = expirationDate {
            realExpires = expirationDate!
        } else {
            realExpires = document!.expirationDate!
        }

        let issuer  = try VerifiableCredentialIssuer(document!)
        let builder = issuer.editingVerifiableCredentialFor(did: document!.subject)

        let credential = try builder.withId(id)
            .withTypes(realTypes)
            .withProperties(subject)
            .withExpirationDate(realExpires)
            .sealed(using: storePassword)
        _ =  document!.appendCredential(credential)

        return self
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - subject: assertion about the subject of the credential
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, types, subject, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - subject: assertion about the subject of the credential
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, subject, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - subject: assertion about the subject of the credential
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, subject, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - subject: assertion about the subject of the credential
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, subject, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - subject: assertion about the subject of the credential
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, types, subject, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - subject: assertion about the subject of the credential
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, subject, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - subject: assertion about the subject of the credential
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, nil, subject, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - subject: assertion about the subject of the credential
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, subject, nil, storePassword)
    }

    private func appendCredential(_ id: DIDURL,
                                  _ types: Array<String>?,
                                  _ json: String,
                                  _ expirationDate: Date?,
                                  _ storePassword: String) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        guard !json.isEmpty && !storePassword.isEmpty else {
            throw DIDError.illegalArgument("storePassword is empty or json is empty.")
        }

        let realTypes: Array<String>
        if let _ = types {
            realTypes = types!
        } else {
            realTypes = Array<String>(["SelfProclaimedCredential"])
        }

        let realExpires: Date
        if let _ = expirationDate {
            realExpires = expirationDate!
        } else {
            realExpires = document!.expirationDate!
        }

        let issuer  = try VerifiableCredentialIssuer(document!)
        let builder = issuer.editingVerifiableCredentialFor(did: document!.subject)

        let credential = try builder.withId(id)
            .withTypes(realTypes)
            .withProperties(json)
            .withExpirationDate(realExpires)
            .sealed(using: storePassword)
        _ =  document!.appendCredential(credential)

        return self
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, types, json, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, json, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, json, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - expirationDate: when the credential will expire
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, json, expirationDate, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, types, json, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - types: the credential types, which declare what data to expect in the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, json, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: DIDURL,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, json, nil, storePassword)
    }

    /// Append credential
    /// - Parameters:
    ///   - id: specify the identifier for the credential
    ///   - json: assertion about the subject of the credential with json format
    ///   - storePassword: Locally encrypted password
    /// - Throws: Error thrown when adding credential key faile
    /// - Returns: DIDDocumentBuilder
    public func appendCredential(with id: String,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, json, nil, storePassword)
    }

    private func removeCredential(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.removeCredential(id) else {
            throw DIDError.illegalArgument("Credential of id \(id) not exists.")
        }

        return self
    }

    /// Remove credential
    /// - Parameter id: specify the identifier for the credential
    /// - Throws: Throws an error when the removal of the credential key fails
    /// - Returns: DIDDocumentBuilder
    public func removeCredential(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeCredential(id)
    }

    /// Remove credential
    /// - Parameter id: specify the identifier for the credential
    /// - Throws: Throws an error when the removal of the credential key fails
    /// - Returns: DIDDocumentBuilder
    public func removeCredential(with id: String) throws -> DIDDocumentBuilder {
        return try removeCredential(DIDURL(getSubject(), id))
    }

    private func appendService(_ id: DIDURL,
                               _ type: String,
                               _ endpoint: String) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.appendService(Service(id, type, endpoint)) else {
            throw DIDError.illegalArgument("append service failed.")
        }

        return self
    }

    /// Append service
    /// - Parameters:
    ///   - id: specify the identifier for the service
    ///   - type: the service type, which declares the entry type of the service
    ///   - endpoint: must be a valid URI in accordance with RFC3986
    /// - Throws: Error thrown when adding service faile
    /// - Returns: DIDDocumentBuilder
    public func appendService(with id: DIDURL,
                                 type: String,
                             endpoint: String) throws -> DIDDocumentBuilder {
        return try appendService(id, type, endpoint)
    }

    /// Append service
    /// - Parameters:
    ///   - id: specify the identifier for the service
    ///   - type: the service type, which declares the entry type of the service
    ///   - endpoint: must be a valid URI in accordance with RFC3986
    /// - Throws: Error thrown when adding service faile
    /// - Returns: DIDDocumentBuilder
    public func appendService(with id: String,
                                 type: String,
                             endpoint: String) throws -> DIDDocumentBuilder {
        return try appendService(DIDURL(getSubject(), id), type, endpoint)
    }

    private func removeService(_ id: DIDURL) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard document!.removeService(id) else {
            throw DIDError.illegalArgument("remove service failed.")
        }

        return self
    }

    /// Remove service
    /// - Parameter id: specify the identifier for the service
    /// - Throws: Throws an error when the removal of the service fails
    /// - Returns: DIDDocumentBuilder
    public func removeService(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeService(id)
    }

    /// Remove service
    /// - Parameter id: specify the identifier for the service
    /// - Throws: Throws an error when the removal of the service fails
    /// - Returns: DIDDocumentBuilder
    public func removeService(with id: String) throws -> DIDDocumentBuilder {
        return try removeService(DIDURL(getSubject(), id))
    }

    /// Set the default expiration date
    /// - Throws: Throws an error when the DIDDocument does not exist
    /// - Returns: DIDDocumentBuilder
    public func withDefaultExpiresDate() throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        document!.setExpirationDate(DateHelper.maxExpirationDate())
        return self
    }

    /// Set DIDDocument expiration date
    /// - Parameter expiresDate: DIDDocument expiration date
    /// - Throws: Throws an error when Set DIDDocument expiration date fails
    /// - Returns: DIDDocumentBuilder
    public func withExpiresDate(_ expiresDate: Date) throws -> DIDDocumentBuilder {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }

        let maxExpirationDate = DateHelper.maxExpirationDate()
        guard !DateHelper.isExpired(expiresDate, maxExpirationDate) else {
            throw DIDError.illegalArgument("Invalid date.")
        }

        document!.setExpirationDate(expiresDate)
        return self
    }

    /// Integrate edited documents into DIDDocument
    /// - Parameter storePassword: Locally encrypted password
    /// - Throws: Throws an error when the document does not exist, the password is empty,
    ///           the document conversion error or the signature error
    /// - Returns: DIDDocument
    public func sealed(using storePassword: String) throws -> DIDDocument {
        guard let _ = document else {
            throw DIDError.invalidState(Errors.DOCUMENT_ALREADY_SEALED)
        }
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument("password is empty")
        }
        if  document!.expirationDate == nil {
            document!.setExpirationDate(DateHelper.maxExpirationDate())
        }

        let signKey = document!.defaultPublicKey
        let data: Data = try document!.toJson(true, true)
        let signature = try document!.sign(signKey, storePassword, [data])

        document!.setProof(DIDDocumentProof(signKey, signature))

        // invalidate builder.
        let doc = self.document!
        self.document = nil

        return doc
    }
}
