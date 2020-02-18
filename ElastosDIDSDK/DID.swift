import Foundation

public class DID {
    private var _method: String?
    private var _methodSpecificId: String?
    private var _meta: DIDMeta?

    init() {}

    init(_ method: String, _ methodSpecificId: String) {
        self._method = method
        self._methodSpecificId = methodSpecificId
    }

    public init(_ did: String) throws {
        guard !did.isEmpty else {
            throw DIDError.illegalArgument()
        }

        do {
            try ParserHelper.parse(did, true, DID.Listener(self))
        } catch {
            throw DIDError.malformedDID(did)
        }
    }

    public var method: String {
        return self._method!
    }

    func setMethod(_ method: String) {
        self._method = method
    }

    public var methodSpecificId: String {
        return self._methodSpecificId!
    }

    func setMethodSpecificId(_ methodSpecificId: String) {
        self._methodSpecificId = methodSpecificId
    }

    func getMeta() -> DIDMeta {
        if self._meta == nil {
            self._meta = DIDMeta()
        }
        return self._meta!
    }

    func setMeta(_ newValue: DIDMeta) {
        self._meta = newValue
    }

    public func setExtra(value: String, forName name: String) throws {
        guard !name.isEmpty else {
            throw DIDError.illegalArgument()
        }

        getMeta().setExtra(value, name)
        if getMeta().attachedStore {
            try getMeta().store!.storeDidMeta(getMeta(), for: self)
        }
    }

    public func getExtra(forName name: String) -> String? {
        return getMeta().getExtra(name)
    }

    public var aliasName: String {
        return self._meta?.aliasName ?? ""
    }

    // Clean alias Name when newValue is nil.
    private func setAliasName(_ newValue: String?) throws {
        getMeta().setAlias(newValue)
        try getMeta().store?.storeDidMeta(getMeta(), for: self)
    }

    public func setAlias(_ newValue: String) throws {
        try setAliasName(newValue)
    }

    public func unsetAlias() throws {
        try setAliasName(nil)
    }

    public var transactionId: String? {
        return getMeta().transactionId
    }

    public var updatedDate: Date? {
        return getMeta().updatedDate
    }

    public var isDeactivated: Bool {
        return getMeta().isDeactivated
    }

    public func resolve(_ force: Bool) throws -> DIDDocument? {
        let doc = try DIDBackend.shareInstance()?.resolve(self, force)
        if let _ = doc {
            setMeta(doc!.getMeta())
        }
        return doc
    }
    
    public func resolve() throws -> DIDDocument? {
        return try resolve(false)
    }
}

extension DID: CustomStringConvertible {
    func toString() -> String {
        return String("did:\(self._method):\(self._methodSpecificId)")
    }

    public var description: String {
        return toString()
    }
}

extension DID: Equatable {
    func equalsTo(_ other: DID) -> Bool {
        return self == other ||
              (self.aliasName == other.aliasName &&
               self.methodSpecificId == other.methodSpecificId)
    }

    func equalsTo(_ other: String) -> Bool {
        return self.toString() == other
    }

    public static func == (lhs: DID, rhs: DID) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: DID, rhs: DID) -> Bool {
        return !lhs.equalsTo(rhs)
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
            let method: String = ctx.getText()
            if (method != Constants.METHOD){
                // can't throw , print...
                print(DIDError.unknownFailure("Unknown method: \(method)"))
            }
            self.did._method = Constants.METHOD
        }

        public override func exitMethodSpecificString(
                            _ ctx: DIDURLParser.MethodSpecificStringContext) {
            self.did._methodSpecificId = ctx.getText()
        }
    }
}