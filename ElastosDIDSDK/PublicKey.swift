import Foundation

public class PublicKey: DIDObject {
    private var _controller: DID
    private var _keyBase58: String

    init(_ id: DIDURL, _ type: String, _ controller: DID, _ keyBase58: String) {
        self._controller = controller
        self._keyBase58 = keyBase58
        super.init(id, type)
    }

    convenience init(_ id: DIDURL, _ controller: DID, _ keyBase58: String) {
        self.init(id, Constants.DEFAULT_PUBLICKEY_TYPE, controller, keyBase58)
    }

    public var controller: DID {
        return self._controller
    }

    public var publicKeyBase58: String {
        return self._keyBase58
    }

    public var publicKeyBytes: [UInt8] {
        return Base58.bytesFromBase58(self._keyBase58)
    }

    public var publicKeyInData: Data {
        return self._keyBase58.data(using: .utf8)!
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> PublicKey {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withRef(ref)
                                .withHint("publicKey id")
        let id = try serializer.getDIDURL(Constants.ID, options)

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
                                .withHint("publicKey type")
        let type = try serializer.getString(Constants.TYPE, options)

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(ref)
                                .withHint("publicKey controller")
        let controller = try serializer.getDID(Constants.CONTROLLER, options)

        options = JsonSerializer.Options()
                                .withHint("publicKeyBase58")
        let keybase58 = try serializer.getString(Constants.PUBLICKEY_BASE58, options)

        return PublicKey(id!, type, controller, keybase58)
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        generator.writeStartObject()
        generator.writeFieldName(Constants.ID)
        generator.writeString(IDGetter(getId(), ref).value(normalized))

        // type
        if normalized || !isDefType() {
            generator.writeStringField(Constants.TYPE, getType())
        }

        // controller
        if normalized || ref == nil || ref != self.controller {
            generator.writeFieldName(Constants.CONTROLLER);
            generator.writeString(self.controller.toString())
        }

        // publicKeyBase58
        generator.writeFieldName(Constants.PUBLICKEY_BASE58)
        generator.writeString(self.publicKeyBase58)
        generator.writeEndObject()
    }

    override func equalsTo(_ other: DIDObject) -> Bool {
        guard other is PublicKey else {
            return false
        }

        let publicKey = other as! PublicKey
        return super.equalsTo(other) &&
               self.controller == publicKey.controller &&
               self.publicKeyBase58 == publicKey.publicKeyBase58
    }
}

extension PublicKey {
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return !lhs.equalsTo(rhs)
    }
}
