import Foundation
import PromiseKit

public class DID {
    private static let TAG = "DID"

    private var _method: String?
    private var _methodSpecificId: String?
    private var _meta: DIDMeta?

    public static let METHOD: String = "elastos"

    init() {}
    
    init(_ method: String, _ methodSpecificId: String) {
        self._method = method
        self._methodSpecificId = methodSpecificId
    }

    /// Initialize DID
    /// - Parameter did: Complete didstring
    /// - Throws: Throw an error the format of didstring is wrong
    public init(_ did: String) throws {
        guard !did.isEmpty else {
            throw DIDError.illegalArgument("empty did string")
        }

        do {
            try ParserHelper.parse(did, true, DID.Listener(self))
        } catch {
            Log.e(DID.TAG, "Parsing did error: malformed did string \(did)")
            throw DIDError.malformedDID(did)
        }
    }

    /// Method is fixed to ”elastos“
    public var method: String {
        return _method!
    }

    func setMethod(_ method: String) {
        self._method = method
    }

    /// Elastos DID uses the description fromat defined in the W3C DID specification discussion draft,
    /// Which is a URI that conforms to the RFC3986 standard.
    /// It consists of a DID followed by an optional path or segment.
    public var methodSpecificId: String {
        return _methodSpecificId!
    }

    func setMethodSpecificId(_ methodSpecificId: String) {
        self._methodSpecificId = methodSpecificId
    }

    func getMeta() -> DIDMeta {
        if  self._meta == nil {
            self._meta = DIDMeta()
        }
        return _meta!
    }

    func setMeta(_ newValue: DIDMeta) {
        self._meta = newValue
    }

    /// Set custom properties
    /// - Parameters:
    ///   - value: Custom attribute value
    ///   - name: Custom attribute key
    /// - Throws: Throw an error setting a custom property fails
    public func setExtra(value: String, forName name: String) throws {
        guard !name.isEmpty else {
            throw DIDError.illegalArgument()
        }

        getMeta().setExtra(value, name)
        try getMeta().store?.storeDidMeta(getMeta(), for: self)
    }

    /// Get custom properties
    /// - Parameter name: Custom attribute key
    /// - Returns: Custom attribute value
    public func getExtra(forName name: String) -> String? {
        return getMeta().getExtra(name)
    }

    /// Custom attribute key
    public var aliasName: String {
        return _meta?.aliasName ?? ""
    }

    // Clean alias Name when newValue is nil.
    private func setAliasName(_ newValue: String?) throws {
        getMeta().setAlias(newValue)
        try getMeta().store?.storeDidMeta(getMeta(), for: self)
    }

    /// Set custom properties
    /// - Parameter newValue: Custom attribute value
    /// - Throws: Throw an error when setting a custom property fails
    public func setAlias(_ newValue: String) throws {
        guard !newValue.isEmpty else {
            throw DIDError.illegalArgument()
        }

        try setAliasName(newValue)
    }

    /// Custom attribute is nil
    /// - Throws: Throw an error when setting a custom property fails
    public func unsetAlias() throws {
        try setAliasName(nil)
    }

    /// Transaction id of the current ID transaction
    public var transactionId: String? {
        return getMeta().transactionId
    }

    /// Updated date
    public var updatedDate: Date? {
        return getMeta().updatedDate
    }

    /// Is deactivated
    public var isDeactivated: Bool {
        return getMeta().isDeactivated
    }

    /// Get DIDDocument from ID side chain
    /// - Parameter force: Whether to get DIDDocument from cache
    /// - Throws: Throw an error when get DIDDocument failed
    /// - Returns: DIDDocument
    public func resolve(_ force: Bool) throws -> DIDDocument {
        let doc = try DIDBackend.resolve(self, force)
        guard let _ = doc else {
            throw DIDError.notFoundError()
        }

        setMeta(doc!.getMeta())
        return doc!
    }
    
    /// Get DIDDocument from ID side chain
    /// - Throws: Throw an error when get DIDDocument failed
    /// - Returns: DIDDocument
    public func resolve() throws -> DIDDocument {
        return try resolve(false)
    }

    /// Get DIDDocument asynchronously from ID side chain
    /// - Parameter force: Whether to get DIDDocument from cache
    /// - Returns: DIDDocument
    public func resolveAsync(_ force: Bool) -> Promise<DIDDocument> {
        return Promise<DIDDocument> { resolver in
            do {
                resolver.fulfill(try resolve(force))
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    /// Get DIDDocument asynchronously from ID side chain
    /// - Returns: DIDDocument
    public func resolveAsync() -> Promise<DIDDocument> {
        return resolveAsync(false)
    }

    /// Get all the historical operations of the DID
    /// - Throws: Throw error when get failed
    /// - Returns: Return all did on the side chain
    public func resolveHistory() throws -> DIDHistory {
        return try DIDBackend.resolveHistory(self)
    }

    /// Asynchronously obtain all historical operations of the DID
    /// - Returns: Return all did on the side chain
    public func resolveHistoryAsync() -> Promise<DIDHistory> {
        return Promise<DIDHistory> { resolver in
            do {
                resolver.fulfill(try resolveHistory())
            } catch let error  {
                resolver.reject(error)
            }
        }
    }
}

extension DID: CustomStringConvertible {
    func toString() -> String {
        return String("did:\(_method!):\(_methodSpecificId!)")
    }

    public var description: String {
        return toString()
    }
}

extension DID: Equatable {
    func equalsTo(_ other: DID) -> Bool {
        return aliasName == other.aliasName &&
               methodSpecificId == other.methodSpecificId
    }

    func equalsTo(_ other: String) -> Bool {
        return toString() == other
    }

    public static func == (lhs: DID, rhs: DID) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: DID, rhs: DID) -> Bool {
        return !lhs.equalsTo(rhs)
    }
}

extension DID: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.toString())
    }
}

// Parse Listener
extension DID {
    private class Listener: DIDURLBaseListener {
        private var did: DID

        init(_ did: DID) {
            self.did = did
            super.init()
        }

        public override func exitMethod(_ ctx: DIDURLParser.MethodContext) {
            let method = ctx.getText()
            if (method != Constants.METHOD){
                // can't throw , print...
                Log.e(DID.TAG, "unsupported method: \(method)")
            }
            self.did._method = Constants.METHOD
        }

        public override func exitMethodSpecificString(
                            _ ctx: DIDURLParser.MethodSpecificStringContext) {
            self.did._methodSpecificId = ctx.getText()
        }
    }
}
