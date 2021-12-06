import Foundation
import Swift

// https://developer.apple.com/documentation/security/code_signing_services
// https://opensource.apple.com/source/Security/Security-59754.120.12/OSX/libsecurity_codesigning/lib/

public struct CodeSign {
    
    public enum Error: Swift.Error {
        case osStatus(OSStatus)
    }
    
    public static let defaultStaticCheckFlags = SecCSFlags.init(
        rawValue:
            kSecCSCheckAllArchitectures |
            kSecCSCheckNestedCode |
            kSecCSDoNotValidateResources)
    public static let defaultStaticSigningInformationFlags = SecCSFlags.init(
        rawValue: kSecCSSigningInformation)
    public static let defaultDynamicSigningInformationFlags = SecCSFlags(
        rawValue: kSecCSDynamicInformation)
    
    public static func createCode(
        with pid: pid_t,
        _ flags: SecCSFlags = []
    ) -> Result<SecCode, Error> {
        return copyGuest(nil, [kSecGuestAttributePid: pid], flags)
    }
    
    public static func createCode(
        with auditToken: Data,
        _ flags: SecCSFlags = []
    ) -> Result<SecCode, Error> {
        return copyGuest(nil, [kSecGuestAttributeAudit: auditToken], flags)
    }
    
    public static func createCode(
        with path: URL,
        _ flags: SecCSFlags = []
    ) -> Result<SecStaticCode, Error> {
        var secStaticCode: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(
            path as CFURL,
            flags,
            &secStaticCode
        )
        return status == errSecSuccess ?
            .success(secStaticCode!) : .failure(.osStatus(status))
    }
    
    public static func createCode(
        _ flags: SecCSFlags = []
    ) -> Result<SecCode, Error> {
        var secCode: SecCode?
        let status = SecCodeCopySelf(flags, &secCode)
        return status == errSecSuccess ?
            .success(secCode!) : .failure(.osStatus(status))
    }
    
    public static func copyGuest(
        _ host: SecCode? = nil,
        _ attributes: [CFString: Any]? = nil,
        _ flags: SecCSFlags = []
    ) -> Result<SecCode, Error> {
        var secCode: SecCode?
        let status = SecCodeCopyGuestWithAttributes(
            host,
            attributes as CFDictionary?,
            flags,
            &secCode
        )
        return status == errSecSuccess ?
            .success(secCode!) : .failure(.osStatus(status))
    }
    
    public static func checkValidity(
        for code: SecCode,
        flags: SecCSFlags = [],
        requirement: SecRequirement? = nil
    ) -> Result<Void, Error> {
        let status = SecCodeCheckValidity(code, flags, requirement)
        return status == errSecSuccess ?
            .success(()) : .failure(.osStatus(status))
    }
    
    public static func checkValidity(
        for staticCode: SecStaticCode,
        flags: SecCSFlags = defaultStaticCheckFlags,
        requirement: SecRequirement? = nil
    ) -> Result<Void, Error> {
        let status = SecStaticCodeCheckValidity(staticCode, flags, requirement)
        return status == errSecSuccess ?
            .success(()) : .failure(.osStatus(status))
    }
    
    public static func createRequirement(
        with string: String,
        _ flags: SecCSFlags = []
    ) -> Result<SecRequirement, Error> {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            string as CFString,
            flags,
            &requirement
        )
        return status == errSecSuccess ?
            .success(requirement!) : .failure(.osStatus(status))
    }
    
    public static func copySigningInformation(
        from staticCode: SecStaticCode,
        _ flags: SecCSFlags = defaultStaticSigningInformationFlags
    ) -> Result<[String: Any], Error> {
        var information: CFDictionary?
        let status = SecCodeCopySigningInformation(
            staticCode,
            flags,
            &information
        )
        return status == errSecSuccess ?
            .success(information as! [String: Any]) :
            .failure(.osStatus(status))
    }
    
    public static func copySigningInformation(
        from code: SecCode,
        _ flags: SecCSFlags = defaultDynamicSigningInformationFlags
    ) -> Result<[String: Any], Error> {
        switch copyStaticCode(from: code) {
        case .success(let staticCode):
            return copySigningInformation(from: staticCode, flags)
        case .failure(let err):
            return .failure(err)
        }
    }
    
    public static func copyStaticCode(
        from code: SecCode,
        _ flags: SecCSFlags = []
    ) -> Result<SecStaticCode, Error> {
        var secStaticCode: SecStaticCode?
        let status = SecCodeCopyStaticCode(code, flags, &secStaticCode)
        return status == errSecSuccess ?
            .success(secStaticCode!) : .failure(.osStatus(status))
    }
    
    public static func copyPath(
        from staticCode: SecStaticCode,
        _ flags: SecCSFlags = []
    ) -> Result<URL, Error> {
        var path: CFURL?
        let status = SecCodeCopyPath(staticCode, flags, &path)
        return status == errSecSuccess ?
            .success(path! as URL) : .failure(.osStatus(status))
    }
    
    public static func copyPath(
        from code: SecCode,
        _ flags: SecCSFlags = []
    ) -> Result<URL, Error> {
        switch copyStaticCode(from: code) {
        case .success(let staticCode):
            return copyPath(from: staticCode, flags)
        case .failure(let err):
            return .failure(err)
        }
    }
}

public struct CodeSignRequirementString {
    
    public static let apple     = "anchor apple"
    public static let developer = "\(apple) generic"
    public static let appStore  = "\(developer) and certificate leaf [subject.CN] = \"Apple Mac OS Application Signing\""
    
    public static func build(_ bundleID: String, _ subjectCN: String) -> String {
        return "\(developer) and identifier \"\(bundleID)\" and certificate leaf[subject.CN] = \"\(subjectCN)\""
    }
}

// https://github.com/securing/SimpleXPCApp/blob/master/SimpleXPCService/ConnectionVerifier.swift
public struct CodeSignInformationUtils {
    
    public static let hardenedRuntimeFlag: UInt32 = 0x10000
    public static let dangerousEntitlements = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
    ]
    
    public static func hasHardenedRuntime(
        _ information: [String: Any]
    ) -> Bool {
        guard let flags = information[kSecCodeInfoFlags as String] else {
            return false
        }
        return (flags as! UInt32) & hardenedRuntimeFlag == hardenedRuntimeFlag
    }
    
    public static func checkDangerousEntitlements(
        _ information: [String: Any]
    ) -> Bool {
        guard let entitlements =
                information[kSecCodeInfoEntitlementsDict as String]
                as? [String: Any] else {
            return false
        }
        for dangerousEntitlement in dangerousEntitlements {
            if let entitlement = entitlements[dangerousEntitlement] {
                if entitlement as! Int == 1 {
                    return false
                }
            }
        }
        return true
    }
}
