import Foundation

public class Proof {
    var type: String!
    var verificationMethod: DIDURL!
    var signature: String!
    
    init(_ type: String, _ method: DIDURL, _ signature: String) {
        self.type = type
        self.verificationMethod = method
        self.signature = signature
    }
    
    func toJson(_ ref: DID, _ compact: Bool) -> Dictionary<String, Any> {
        var dic: Dictionary<String, Any> = [: ]
        var value: String
        //type:
        if !compact || !(type == Constants.defaultPublicKeyType) {
            dic[Constants.type] = type
        }
        
        // method:
        if compact && verificationMethod.did.isEqual(ref) {
            value = "#" + verificationMethod.fragment
        }
        else {
            value = verificationMethod.fragment
        }
        dic[Constants.verificationMethod] = value
        
        // signature:
        dic[Constants.signature] = signature
        return dic
    }
    
    class func fromJson(_ md: Dictionary<String, Any>, _ ref: DID) throws -> Proof {
        let type: String = try JsonHelper.getString(md, Constants.type, true, Constants.defaultPublicKeyType, "crendential proof type")
        let method: DIDURL = try JsonHelper.getDidUrl(md, Constants.verificationMethod, ref, "crendential proof verificationMethod")
        let signature: String = try JsonHelper.getString(md, Constants.signature, false, nil, "crendential proof signature")
        return Proof(type, method, signature)
    }
}