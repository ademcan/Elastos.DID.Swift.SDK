import Foundation

public class Mnemonic {
    public static let CHINESE_SIMPLIFIED = "chinese_simplified"
    public static let CHINESE_TRADITIONAL = "chinese_traditional";
    public static let CZECH = "Czech";
    public static let ENGLISH = "english";
    public static let FRENCH = "French";
    public static let ITALIAN = "Italian";
    public static let JAPANESE = "japanese";
    public static let KOREAN = "Korean";
    public static let SPANISH = "Spanish";

    /// Generate mnemonic string
    /// - Parameter language: Language for generating mnemonics
    /// - Throws: Failure to generate mnemonic will throw error
    /// - Returns: Genetate mnemonic string
    public class func generate(_ language: String) throws -> String {
        guard !language.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let result = language.withCString { (clanuage) in
            return HDKey_GenerateMnemonic(clanuage)
        }

        guard let _ = result else {
            throw DIDError.illegalArgument()
        }

        return String(cString: result!)
    }
    
    /// Verify that the mnemonic is vaid
    /// - Parameters:
    ///   - language: Language for generating mnemonics
    ///   - mnemonic: Verified mnemonic
    /// - Throws: Errors are thrown when the language and mnemonics are empty
    /// - Returns: The mnemocin valid returns true，else returns false
    public class func isValid(_ language: String, _ mnemonic: String) throws -> Bool {
        guard !language.isEmpty, !mnemonic.isEmpty else {
            throw DIDError.illegalArgument()
        }

        return language.withCString { (clang) in
            return mnemonic.withCString { (cmnemonic) in
                return HDKey_MnemonicIsValid(cmnemonic, clang)
            }
        }
    }
}
