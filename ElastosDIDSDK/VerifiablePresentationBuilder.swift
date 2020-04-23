import Foundation

public class VerifiablePresentationBuilder {
    private let _signer: DIDDocument
    private let _signKey: DIDURL
    private var _realm: String?
    private var _nonce: String?

    private var presentation: VerifiablePresentation?

    init(_ signer: DIDDocument, _ signKey: DIDURL) {
        self._signer = signer
        self._signKey = signKey

        self.presentation = VerifiablePresentation()
    }

    /// Add verifiable credentials
    /// - Parameter credentials: Verifiable credentials
    /// - Throws: Error thrown when adding verifiable credentials failed
    /// - Returns: VerifiablePresentationBuilder
    public func withCredentials(_ credentials: VerifiableCredential...) throws
        -> VerifiablePresentationBuilder {

        return try withCredentials(credentials)
    }

    /// Add verifiable credentials
    /// - Parameter credentials: credentials array
    /// - Throws: Error thrown when adding verifiable credentials failed
    /// - Returns: VerifiablePresentationBuilder
    public func withCredentials(_ credentials: Array<VerifiableCredential>) throws
        -> VerifiablePresentationBuilder {

        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }

        for credential in credentials {
            // Presentation should be signed by the subject of Credentials
            guard credential.subject.did == self._signer.subject else {
                throw DIDError.illegalArgument(
                    "Credential \(credential.getId()) not match with requested id")
            }
            guard credential.checkIntegrity() else {
                throw DIDError.illegalArgument("incomplete credential \(credential.toString())")
            }

            presentation!.appendCredential(credential)
        }
        return self
    }

    /// Add realm
    /// - Parameter realm: Target areas to which the expression applies, such as website domain names, application names, etc.
    /// - Throws: Error thrown when adding realm failed
    /// - Returns: VerifiablePresentationBuilder
    public func withRealm(_ realm: String) throws -> VerifiablePresentationBuilder {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !realm.isEmpty else {
            throw DIDError.illegalArgument("realm is empty")
        }

        self._realm = realm
        return self
    }

    /// Add nonce
    /// - Parameter nonce: Random value used for signature operation
    /// - Throws: Error thrown when adding nonce failed
    /// - Returns: VerifiablePresentationBuilder
    public func withNonce(_ nonce: String) throws -> VerifiablePresentationBuilder {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !nonce.isEmpty else {
            throw DIDError.illegalArgument("nonce is empty")
        }

        self._nonce = nonce
        return self
    }

    /// Integrate edited verifiable credentials into VerifiablePresentation
    /// - Parameter storePassword: Locally encrypted password
    /// - Throws: Throws an error when the signature fails
    /// - Returns: VerifiablePresentation
    public func sealed(using storePassword: String) throws -> VerifiablePresentation {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument("storePassword is empty")
        }
        guard presentation!.cedentialCount > 0 else {
            throw DIDError.illegalArgument("presentation.cedentialCount is empty")
        }
        guard _realm != nil && _nonce != nil else {
            throw DIDError.invalidState("Missing realm and nonce")
        }

        var data: [Data] = []
        data.append(presentation!.toJson(true))
        if let realm = _realm {
            data.append(realm.data(using: .utf8)!)
        }
        if let nonce = _nonce {
            data.append(nonce.data(using: .utf8)!)
        }
        let signature = try _signer.sign(_signKey, storePassword, data)

        let proof = VerifiablePresentationProof(_signKey, _realm!, _nonce!, signature)
        presentation!.setProof(proof)

        // invalidate builder.
        let sealed = self.presentation!
        self.presentation = nil

        return sealed
    }
}
