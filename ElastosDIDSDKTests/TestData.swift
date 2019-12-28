
import XCTest
import ElastosDIDSDK

class TestData: XCTestCase {
    private static var dummyAdapter: DummyAdapter?
    private static var spvAdapter: DIDAdapter?
    private static var rootKey: HDKey?
    private static var index: Int?
    
    private var testIssuer: DIDDocument?
    private var issuerCompactJson: String?
    private var issuerNormalizedJson: String?
    private var testDocument: DIDDocument?
    private var testCompactJson: String?
    private var testNormalizedJson: String?
    private var profileVc: VerifiableCredential?
    private var profileVcCompactJson: String?
    private var profileVcNormalizedJson: String?
    private var emailVc: VerifiableCredential?
    private var emailVcCompactJson: String?
    private var emailVcNormalizedJson: String?
    private var passportVc: VerifiableCredential?
    private var passportVcCompactJson: String?
    private var passportVcNormalizedJson: String?
    private var twitterVc: VerifiableCredential?
    private var twitterVcCompactJson: String?
    private var twitterVcNormalizedJson: String?
    private var testVp: VerifiablePresentation?
    private var testVpNormalizedJson: String?
    private var restoreMnemonic: String?
    
    private var store: DIDStore!


    public func setupStore(_ dummyBackend: Bool) throws -> DIDStore {
        var adapter: DIDAdapter = DummyAdapter()
        if dummyBackend {
            if TestData.dummyAdapter == nil {
                TestData.dummyAdapter = DummyAdapter()
                adapter = TestData.dummyAdapter!
            }
            else {
                TestData.dummyAdapter!.reset()
            }
            adapter = TestData.dummyAdapter!
        }
        else {
            if TestData.spvAdapter == nil {
                let cblock: PasswordCallback = ({(walletDir, walletId) -> String in return "test111111"})
                TestData.spvAdapter = SPVAdaptor(walletDir, walletId, networkConfig, resolver, cblock)
            }
            adapter = TestData.spvAdapter!
        }
        DIDBackend.creatInstance(adapter)
        TestData.deleteFile(storePath)
        store = try DIDStore.open("filesystem", storePath)
        return store
    }
    
    public func initIdentity() throws -> String {
        let mnemonic: String = HDKey.generateMnemonic(0)
        try store.initPrivateIdentity(0, mnemonic, passphrase, storePass, true)
        return mnemonic
    }
    
    func loadDIDDocument(_ fileName: String, _ type_: String) throws -> DIDDocument {
        let bundle = Bundle(for: type(of: self))
        let jsonPath = bundle.path(forResource: fileName, ofType: type_)
        let doc: DIDDocument = try DIDDocument.fromJson(path: jsonPath!)
        
        if store != nil {
            try store.storeDid(doc)
        }
        return doc
    }
    
    func importPrivateKey(_ id: DIDURL, _ fileName: String, _ type: String) throws {
        let skBase58: String = try loadText(fileName, type)
        let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: 1024)
        let cp = skBase58.toUnsafePointerInt8()
        let re = base58_decode(buffer, cp)
        print(re)
        let temp = UnsafeRawPointer(buffer)
        .bindMemory(to: UInt8.self, capacity: re)
        
        let data = Data(bytes: temp, count: re)
        let intArray = [UInt8](data).map { Int8(bitPattern: $0) }
        print(intArray)

        try store.storePrivateKey(id.did, id, data, storePass)
    }
    
    func loadTestIssuer() throws -> DIDDocument {
        if testIssuer == nil {
            testIssuer = try loadDIDDocument("issuer", "json")
            try importPrivateKey((testIssuer?.getDefaultPublicKey())!, "issuer.primary", "sk")
        }
        return testIssuer!
    }
    
    func loadTestDocument() throws -> DIDDocument {
        _ = try loadTestIssuer()
        if testDocument == nil {
            testDocument = try loadDIDDocument("document", "json")
        }
        try importPrivateKey((testDocument?.getDefaultPublicKey())!, "document.primary", "sk")
        try importPrivateKey(testDocument!.getPublicKey("key2")!.id, "document.key2", "sk")
        try importPrivateKey(testDocument!.getPublicKey("key3")!.id, "document.key3", "sk")
        return testDocument!
    }
    
    func loadCredential(_ fileName: String, _ type_: String) throws -> VerifiableCredential {
        let buldle = Bundle(for: type(of: self))
        let filepath = buldle.path(forResource: fileName, ofType: type_)
        let json = try! String(contentsOf: URL(fileURLWithPath: filepath!), encoding: .utf8)
        let vc: VerifiableCredential = try VerifiableCredential.fromJson(json)
        if store != nil {
            try store.storeCredential(vc)
        }
        return vc
    }
    
    public func loadProfileCredential() throws -> VerifiableCredential? {
        if profileVc == nil {
            profileVc = try loadCredential("vc-profile", "json")
        }
        return profileVc
    }
    
    public func loadEmailCredential() throws -> VerifiableCredential {
        if emailVc == nil {
            emailVc = try loadCredential("vc-email", "json")
        }
        return emailVc!
    }
    
    public func loadPassportCredential() throws -> VerifiableCredential? {
        if passportVc == nil {
            passportVc = try loadCredential("vc-passport", "json")
        }
        return passportVc
    }
    
    public func loadTwitterCredential() throws -> VerifiableCredential {
        if twitterVc == nil {
            twitterVc = try loadCredential("vc-twitter", "json")
        }
        return twitterVc!
    }
    
    public func loadPresentation() throws -> VerifiablePresentation {
        if testVp == nil {
            let bl = Bundle(for: type(of: self))
            let path = bl.path(forResource: "vp", ofType: "json")
            let urlPath = URL(fileURLWithPath: path!)
            let json = try String(contentsOf: urlPath)
            var jsonString = json.replacingOccurrences(of: " ", with: "")
            jsonString = jsonString.replacingOccurrences(of: "\n", with: "")
            testVp = try VerifiablePresentation.fromJson(jsonString)
        }
        return testVp!
    }
    
    func loadText(_ fileName: String, _ type_: String) throws -> String {
        let bl = Bundle(for: type(of: self))
        let filepath = bl.path(forResource: fileName, ofType: type_)
        let json = try! String(contentsOf: URL(fileURLWithPath: filepath!), encoding: .utf8)

        return json
    }
    
    public func loadIssuerCompactJson() throws -> String {
        if issuerCompactJson == nil {
            issuerCompactJson = try loadText("issuer.compact", "json")
        }
        return issuerCompactJson!
    }
    
    public func loadIssuerNormalizedJson() throws -> String {
        if issuerNormalizedJson == nil {
            issuerNormalizedJson = try loadText("issuer.normalized", "json")
        }
        return issuerNormalizedJson!
    }
    
    public func loadTestCompactJson() throws -> String {
        if testCompactJson == nil {
            testCompactJson = try loadText("document.compact", "json")
        }
        return testCompactJson!
    }
    
    public func loadTestNormalizedJson() throws -> String {
        if testNormalizedJson == nil {
            testNormalizedJson = try loadText("document.normalized", "json")
        }
        return testNormalizedJson!
    }
    
    public func loadProfileVcCompactJson() throws -> String {
        if profileVcCompactJson == nil {
            profileVcCompactJson = try loadText("vc-profile.compact", "json")
        }
        return profileVcCompactJson!
    }
    
    public func loadProfileVcNormalizedJson() throws -> String {
        if profileVcNormalizedJson == nil {
            profileVcNormalizedJson = try loadText("vc-profile.normalized", "json")
        }
        return profileVcNormalizedJson!
    }
    
    public func loadEmailVcCompactJson() throws -> String {
        if emailVcCompactJson == nil {
            emailVcCompactJson = try loadText("vc-email.compact", "json")
        }
        return emailVcCompactJson!
    }
    
    public func loadEmailVcNormalizedJson() throws -> String {
        if emailVcNormalizedJson == nil {
            emailVcNormalizedJson = try loadText("vc-email.normalized", "json")
        }
        return emailVcNormalizedJson!
    }
    
    public func loadPassportVcCompactJson() throws -> String {
        if passportVcCompactJson == nil {
            passportVcCompactJson = try loadText("vc-passport.compact", "json")
        }
        return passportVcCompactJson!
    }
    
    public func loadPassportVcNormalizedJson() throws -> String {
        if passportVcNormalizedJson == nil {
            passportVcNormalizedJson = try loadText("vc-passport.normalized", "json")
        }
        return passportVcNormalizedJson!
    }
    
    public func loadTwitterVcCompactJson() throws -> String {
        if twitterVcCompactJson == nil {
            twitterVcCompactJson = try loadText("vc-twitter.compact", "json")
        }
        return twitterVcCompactJson!
    }
    
    public func loadTwitterVcNormalizedJson() throws -> String {
        if twitterVcNormalizedJson == nil {
            twitterVcNormalizedJson = try loadText("vc-twitter.normalized", "json")
        }
        return twitterVcNormalizedJson!
    }
    
    public func loadPresentationNormalizedJson() throws -> String {
        if testVpNormalizedJson == nil {
            testVpNormalizedJson = try loadText("vp.normalized", "json")
        }
        return testVpNormalizedJson!
    }
    
    public func loadRestoreMnemonic() throws -> String {
        if restoreMnemonic == nil {
            // TODO: load test
            restoreMnemonic = try loadText("mnemonic", "restore")
        }
        return restoreMnemonic!
    }
    
    public func deleteFile() throws -> String {
        if restoreMnemonic == nil {
            // TODO: load test
            restoreMnemonic = try loadText("mnemonic", "restore")
        }
        return restoreMnemonic!
    }
    
    public class func generateKeypair() throws -> DerivedKey {
        if TestData.rootKey == nil {
            let mnemonic: String = HDKey.generateMnemonic(0)
            TestData.rootKey = try HDKey.fromMnemonic(mnemonic, "")
            TestData.index = 0
        }
        TestData.index = TestData.index! + 1
        return try TestData.rootKey!.derive(TestData.index!)
    }

   class func deleteFile(_ path: String) {
        do {
            let filemanager: FileManager = FileManager.default
            var isdir = ObjCBool.init(false)
            let fileExists = filemanager.fileExists(atPath: path, isDirectory: &isdir)
            if fileExists && isdir.boolValue {
                if let dircontents = filemanager.enumerator(atPath: path) {
                    for case let url as URL in dircontents {
                        deleteFile(url.absoluteString)
                    }
                }
            }
            guard fileExists else {
                return
            }
            try filemanager.removeItem(atPath: path)
        } catch {
            print("deleteFile error: \(error)")
        }
    }
    
    func exists(_ dirPath: String) -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        if fileManager.fileExists(atPath: dirPath, isDirectory:&isDir) {
            if isDir.boolValue {
                return true
            }
        }
        return false
    }
    
    func existsFile(_ path: String) -> Bool {
        var isDirectory = ObjCBool.init(false)
        let fileExists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
        return !isDirectory.boolValue && fileExists
    }
    
    func currentDateToWantDate(_ year: Int)-> Date {
        let current = Date()
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(abbreviation: "UTC")!
        var comps:DateComponents?
        
        comps = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: current)
        comps?.year = Constants.MAX_VALID_YEARS
        comps?.month = 0
        comps?.day = 0
        comps?.hour = 0
        comps?.minute = 0
        comps?.second = 0
        comps?.nanosecond = 0
        let realDate = calendar.date(byAdding: comps!, to: current) ?? Date()
        let hour = calendar.component(.hour, from: realDate)
        let useDate = calendar.date(bySettingHour: hour, minute: 00, second: 00, of: realDate) ?? Date()
        
        return useDate
    }
}

extension String {
    var asciiArray: [UInt32] {
        return unicodeScalars.filter{$0.isASCII}.map{$0.value}
    }
    
    func toUnsafePointerUInt8() -> UnsafePointer<UInt8>? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        let stream = OutputStream(toBuffer: buffer, capacity: data.count)
        stream.open()
        let value = data.withUnsafeBytes {
            $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }
        guard let val = value else {
            return nil
        }
        stream.write(val, maxLength: data.count)
        stream.close()
        
        return UnsafePointer<UInt8>(buffer)
    }
    
    func toUnsafePointerInt8() -> UnsafePointer<Int8>? {
        let str: NSString = self as NSString
        let strUnsafe = str.utf8String
        return strUnsafe
    }
    
    func toUnsafeMutablePointerInt8() -> UnsafeMutablePointer<Int8>? {
        return strdup(self)
    }
}
