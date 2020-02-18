import Foundation

class IDChainRequest: NSObject {
    static let CURRENT_SPECIFICATION = "elastos/did/1.0"
    
    // header
    private var _specification: String                // must have value
    private var _operation: IDChainRequestOperation   // must have value
    private var _previousTransactionId: String?

    // payload
    private var _did: DID?
    private var _doc: DIDDocument?
    private var _payload: String?
    
    // signature
    private var _keyType: String?
    private var _signKey: DIDURL?
    private var _signature: String?
    
    private init(_ operation: IDChainRequestOperation) {
        self._specification = IDChainRequest.CURRENT_SPECIFICATION
        self._operation = operation
    }
    
    class func create(_ doc: DIDDocument,
                      _ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        return try IDChainRequest(.CREATE)
                .setPayload(doc)
                .seal(signKey, storePass)
    }
    
    class func update(_ doc: DIDDocument,
                      _ previousTransactionId: String,
                      _ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        return try IDChainRequest(.UPDATE)
                .setPreviousTransactionId(previousTransactionId)
                .setPayload(doc)
                .seal(signKey, storePass)
    }
    
    class func deactivate(_ doc: DIDDocument,
                      _ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        return try IDChainRequest(.DEACTIVATE)
                .setPayload(doc)
                .seal(signKey, storePass)
    }
    
    class func deactivate(_ target: DID,
                      _ targetSignKey: DIDURL,
                      _ doc: DIDDocument,
                      _ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        return try IDChainRequest(.DEACTIVATE)
                .setPayload(target)
                .seal(targetSignKey, doc, signKey, storePass)
    }

    var operation: IDChainRequestOperation {
        return self._operation
    }

    var previousTransactionId: String? {
        return self._previousTransactionId
    }

    var payload: String? {
        return self._payload
    }

    var did: DID? {
        return self._did
    }

    var document: DIDDocument? {
        return self._doc
    }

    private func setPreviousTransactionId(_ transactionId: String) -> IDChainRequest {
        self._previousTransactionId = transactionId
        return self
    }
    
    private func setPayload(_ did: DID) -> IDChainRequest {
        self._did = did
        self._doc = nil
        self._payload = did.description

        return self
    }
    
    private func setPayload(_ doc: DIDDocument) throws -> IDChainRequest {
        self._did = doc.subject
        self._doc = doc

        if self._operation != .DEACTIVATE {
            let json = try doc.toJson(false)
            self._payload = json.base64EncodedString // TODO: checkMe.
        } else {
            self._payload = doc.subject.description
        }

        return self
    }
    
    private func setPayload(_ payload: String) throws  -> IDChainRequest {
        do {
            if self._operation != .DEACTIVATE {
                let json = payload.base64DecodedString  // TODO: checkMe

                self._doc = try DIDDocument.convertToDIDDocument(fromJson: json!)
                self._did = self._doc!.subject
            } else {
                self._doc = nil
                self._did = try DID(payload)
            }
        } catch {
            throw DIDError.didResolveError("Parse playload error.")
        }

        self._payload = payload
        return self
    }
    
    private func setProof(_ keyType: String,
                          _ signKey: DIDURL,
                          _ signature: String) -> IDChainRequest {

        self._keyType = keyType
        self._signKey = signKey
        self._signature = signature
        return self
    }
    
    private func seal(_ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        let prevTxid = self._operation == .UPDATE ? self._previousTransactionId! : ""
        var inputs: [Data] = []

        inputs.append(self._specification.data(using: .utf8)!)
        inputs.append(self._operation.description.data(using: .utf8)!)
        inputs.append(prevTxid.description.data(using: .utf8)!)
        inputs.append(self._payload!.data(using: .utf8)!)

        self._signature = try self._doc!.signEx(signKey, storePass, inputs)
        self._signKey = signKey
        self._keyType = Constants.DEFAULT_PUBLICKEY_TYPE

        return self
    }
    
    private func seal(_ targetSignKey: DIDURL,
                      _ doc: DIDDocument,
                      _ signKey: DIDURL,
                      _ storePass: String) throws -> IDChainRequest {

        let prevTxid = self._operation == .UPDATE ? self._previousTransactionId! : ""
        var inputs: [Data] = []

        inputs.append(self._specification.data(using: .utf8)!)
        inputs.append(self._operation.description.data(using: .utf8)!)
        inputs.append(self._payload!.data(using: .utf8)!)
        inputs.append(prevTxid.data(using: .utf8)!)

        self._signature = try self._doc!.signEx(signKey, storePass, inputs)
        self._signKey = targetSignKey
        self._keyType = Constants.DEFAULT_PUBLICKEY_TYPE

        return self
    }
    
    private func checkValid() throws -> Bool {
        // internally using builder pattern "create/update/deactivate" to create
        // new IDChainRequest object.
        // Always be sure have "_doc/_signKey/_storePass" in the object.
        var doc: DIDDocument
        if self._operation != .DEACTIVATE {
            doc = self._doc!
            guard doc.containsAuthenticationKey(forId: self._signKey!) else {
                return false
            }
        } else {
            doc = try self._did!.resolve()!
            guard doc.containsAuthenticationKey(forId: self._signKey!) ||
                  doc.containsAuthorizationKey (forId: self._signKey!) else {
                return false
            }
        }

        let prevTxid = self.operation == .UPDATE ? self._previousTransactionId!: ""
        var inputs: [Data] = [];

        inputs.append(self._specification.data(using: .utf8)!)
        inputs.append(self._operation.description.data(using: .utf8)!)
        inputs.append(self._payload!.data(using: .utf8)!)
        inputs.append(prevTxid.data(using: .utf8)!)

        return try doc.verifyEx(self._signKey!, self._signature!, inputs)
    }

    var isValid: Bool {
        do {
            return try self.checkValid()
        } catch {
            return false
        }
    }

    class func fromJson(_ node: JsonNode) throws -> IDChainRequest {
        guard !node.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let error = { (des: String) -> DIDError in
            return DIDError.didResolveError(des)
        }

        var subNode = node.getNode(Constants.HEADER)
        guard let _ = subNode else {
            throw DIDError.didResolveError("Missing header")
        }

        var serializer = JsonSerializer(subNode!)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withHint(Constants.SPECIFICATION)
                                .withError(error)
        let specs = try serializer.getString(Constants.SPECIFICATION, options)
        guard specs == IDChainRequest.CURRENT_SPECIFICATION else {
            throw DIDError.didResolveError("Unkown DID specification.")
        }

        options = JsonSerializer.Options()
                                .withHint(Constants.OPERATION)
                                .withError(error)
        let opstr = try serializer.getString(Constants.OPERATION, options)
        let operation = IDChainRequestOperation.valueOf(opstr)

        let request = IDChainRequest(operation)
        if operation == .UPDATE {
            options = JsonSerializer.Options()
                                .withHint(Constants.PREVIOUS_TXID)
                                .withError(error)
            let transactionId = try serializer.getString(Constants.PREVIOUS_TXID, options)
            _ = request.setPreviousTransactionId(transactionId)
        }

        serializer = JsonSerializer(node)
        options = JsonSerializer.Options()
                                .withHint(Constants.PAYLOAD)
                                .withError(error)
        let payload = try serializer.getString(Constants.PAYLOAD, options)
        _  = try request.setPayload(payload)

        subNode = node.getNode(Constants.PROOF)
        guard let _ = subNode else {
            throw DIDError.didResolveError("missing proof.")
        }

        serializer = JsonSerializer(subNode!)
        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
                                .withHint(Constants.KEY_TYPE)
                                .withError(error)
        let keyType = try serializer.getString(Constants.KEY_TYPE, options)
        guard keyType == Constants.DEFAULT_PUBLICKEY_TYPE else {
            throw DIDError.didResolveError("Unkown signature key type")
        }

        options = JsonSerializer.Options()
                                .withRef(request.did)
                                .withHint(Constants.VERIFICATION_METHOD)
                                .withError(error)
        let signKey = try serializer.getDIDURL(Constants.VERIFICATION_METHOD, options)

        options = JsonSerializer.Options()
                                .withHint(Constants.SIGNATURE)
                                .withError(error)
        let signature = try serializer.getString(Constants.SIGNATURE, options)

        _ = request.setProof(keyType, signKey!, signature)
        return request
    }

    class func fromJson(_ json: Data) throws -> IDChainRequest {
        guard !json.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let data: Dictionary<String, Any>
        do {
            data = try JSONSerialization.jsonObject(with: json, options: []) as! Dictionary<String, Any>
        } catch {
            throw DIDError.didResolveError("Parse resolve result error")
        }
        return try fromJson(JsonNode(data))
    }

    class func fromJson(_ json: String) throws -> IDChainRequest {
        return try fromJson(json.data(using: .utf8)!)
    }

    func toJson(_ generator: JsonGenerator, _ normalized: Bool) {
        generator.writeStartObject()

        // header
        generator.writeFieldName(Constants.HEADER)

        generator.writeStartObject()
        generator.writeStringField(Constants.SPECIFICATION, self._specification)
        generator.writeStringField(Constants.OPERATION, self.operation.toString())
        if self._operation == .UPDATE {
            generator.writeFieldName(Constants.PREVIOUS_TXID)
            generator.writeString(self.previousTransactionId!)
        }
        generator.writeEndObject() // end of header.

        // payload
        generator.writeStringField(Constants.PAYLOAD, self.payload!)

        // signature
        generator.writeFieldName(Constants.PROOF)
        generator.writeStartObject()

        var keyId: String
        if normalized {
            generator.writeStringField(Constants.KEY_TYPE, self._keyType!)
            keyId = self._signKey!.description
        } else {
            keyId = "#" + self._signKey!.fragment!
        }
        generator.writeStringField(Constants.VERIFICATION_METHOD, keyId)
        generator.writeStringField(Constants.SIGNATURE, self._signature!)

        generator.writeEndObject()  // end of signature.

        generator.writeEndObject()
    }

    func toJson(_ normalized: Bool) -> String {
        // TODO
        return "TODO"
    }
}