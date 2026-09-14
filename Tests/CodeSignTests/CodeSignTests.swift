    import XCTest
    @testable import CodeSign

    final class CodeSignTests: XCTestCase {
        func testDynamicSigningInformation() throws {
            let code = try CodeSign.createCode().get()
            let information = try CodeSign.copySigningInformation(from: code).get()

            XCTAssertNotNil(information[kSecCodeInfoStatus as String])
        }

        func testDynamicSigningInformationWithExplicitFlags() throws {
            let code = try CodeSign.createCode().get()
            let information = try CodeSign.copySigningInformation(from: code, []).get()

            XCTAssertNil(information[kSecCodeInfoStatus as String])
            XCTAssertNotNil(information[kSecCodeInfoMainExecutable as String])
        }

        func testStaticSigningInformation() throws {
            let code = try CodeSign.createCode(with: URL(fileURLWithPath: "/usr/bin/true")).get()
            let information = try CodeSign.copySigningInformation(from: code).get()

            XCTAssertNotNil(information[kSecCodeInfoIdentifier as String])
            XCTAssertNil(information[kSecCodeInfoStatus as String])
        }

        func testApple() throws {
            let code = try CodeSign.createCode(with: getppid()).get()
            let requirement = try CodeSign.createRequirement(with: CodeSignRequirementString.apple).get()
            try CodeSign.checkValidity(for: code, requirement: requirement).get()
        }
        
        func testNotApple() throws {
            let code = try CodeSign.createCode(with: getpid()).get()
            let requirement = try CodeSign.createRequirement(with: CodeSignRequirementString.apple).get()
            let result: Bool
            switch CodeSign.checkValidity(for: code, requirement: requirement) {
            case .success():  result = false
            case .failure(_): result = true
            }
            assert(result)
        }
    }
