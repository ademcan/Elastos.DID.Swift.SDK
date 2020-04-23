import Foundation

public class VerifiableCredentialBuilder {
    private var _target: DID
    private var _signKey: DIDURL
    private var _forDoc: DIDDocument

    private var credential: VerifiableCredential?

    init(_ target: DID, _ doc: DIDDocument, _ signKey: DIDURL) {
        self._target  = target
        self._forDoc  = doc
        self._signKey = signKey

        self.credential = VerifiableCredential()
        self.credential!.setIssuer(doc.subject)
    }

    /// Specify an id for credential
    /// - Parameter id: specify the identifier for the credential
    /// - Throws: Throw an error when credential is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withId(_ id: DIDURL) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }

        credential!.setId(id)
        return self
    }

    /// Specify an id for credential
    /// - Parameter id: specify the identifier for the credential
    /// - Throws: Throw an error when credential is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withId(_ id: String) throws -> VerifiableCredentialBuilder {
        guard !id.isEmpty else {
            throw DIDError.illegalArgument("id is empty")
        }

        return try withId(DIDURL(_target, id))
    }

    /// Specify a type for credential
    /// - Parameter types: the credential types, which declare what data to expect in the credential
    /// - Throws: Throw an error when credential is nil , or types is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withTypes(_ types: String...) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }
        guard types.count > 0 else {
            throw DIDError.illegalArgument("types is empty")
        }

        credential!.setType(types)
        return self
    }
    
    /// Specify a type for credential
    /// - Parameter types: the credential types, which declare what data to expect in the credential
    /// - Throws: Throw an error when credential is nil , or types is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withTypes(_ types: Array<String>) throws -> VerifiableCredentialBuilder {
         guard let _ = credential else {
             throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
         }
         guard types.count > 0 else {
             throw DIDError.illegalArgument("types is empty")
         }

         credential!.setType(types)
         return self
     }

    /// Set credential default expiration date
    /// - Throws: Throw an error when credential is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withDefaultExpirationDate() throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }

        credential!.setExpirationDate(maxExpirationDate())
        return self
    }

    /// Set credential expiration date
    /// - Parameter expirationDate: when the credential will expire
    /// - Throws: Throw an error when credential is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withExpirationDate(_ expirationDate: Date) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }

        var exp = expirationDate
        if DateHelper.isExpired(exp, maxExpirationDate()) {
            exp = maxExpirationDate()
        }

        // TODO: check
        credential!.setExpirationDate(exp)
        return self
    }

    /// Set claims about the subject of the credential
    /// - Parameter properites: Credential dictionary data
    /// - Throws: Throw an error when credential is nil or properites is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withProperties(_ properites: [String: Any]) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }
        guard !properites.isEmpty else {
            throw DIDError.illegalArgument("properites is empty")
        }
        // TODO: CHECK
        let jsonNode = JsonNode(properites)
        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(jsonNode)
        credential!.setSubject(subject)
        
        return self
    }

    /// Set claims about the subject of the credential
    /// - Parameter json: Credential dictionary string
    /// - Throws: Throw an error when credential is nil or properites is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withProperties(_ json: String) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }
        guard !json.isEmpty else {
            throw DIDError.illegalArgument("properites is empty")
        }
        // TODO: CHECK
        let dic = try (JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: [JSONSerialization.ReadingOptions.init(rawValue: 0)]) as? [String: Any])
        guard let _ = dic else {
            throw DIDError.malformedCredential("properties data formed error.")
        }
        let jsonNode = JsonNode(dic!)
        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(jsonNode)
        credential!.setSubject(subject)
        
        return self
    }

    /// Set claims about the subject of the credential
    /// - Parameter properties: Credential dictionary JsonNode
    /// - Throws: Throw an error when credential is nil or properites is nil
    /// - Returns: VerifiableCredentialBuilder
    public func withProperties(_ properties: JsonNode) throws -> VerifiableCredentialBuilder {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }
        guard properties.count > 0 else {
            throw DIDError.illegalArgument("properites is empty")
        }

        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(properties)

        credential!.setSubject(subject)
        return self
    }

    /// The edited credential attribute is integrated into the VerifiableCredential whole
    /// - Parameter storePassword: Locally encrypted password
    /// - Throws: Throws an error when the signature fails
    /// - Returns: VerifiableCredential
    public func sealed(using storePassword: String) throws -> VerifiableCredential {
        guard let _ = credential else {
            throw DIDError.invalidState(Errors.CREDENTIAL_ALREADY_SEALED)
        }
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument("storePassword is empty")
        }
        guard credential!.checkIntegrity() else {
            throw DIDError.malformedCredential("imcomplete credential")
        }

        credential!.setIssuanceDate(DateHelper.currentDate())
        if credential!.getExpirationDate() == nil {
            _ = try withDefaultExpirationDate()
        }

        guard let data = credential!.toJson(true, true).data(using: .utf8) else {
            throw DIDError.illegalArgument("credential is nil")
        }
        let signature = try _forDoc.sign(_signKey, storePassword, [data])
        let proof = VerifiableCredentialProof(Constants.DEFAULT_PUBLICKEY_TYPE, _signKey, signature)

        credential!.setProof(proof)

        // invalidate builder
        let sealed = self.credential!
        self.credential = nil

        return sealed
    }

    private func maxExpirationDate() -> Date {
        guard credential?.getIssuanceDate() == nil else {
            return DateFormatter.convertToWantDate(credential!.issuanceDate, Constants.MAX_VALID_YEARS)
        }
        return DateFormatter.convertToWantDate(Date(), Constants.MAX_VALID_YEARS)
    }
}
