    import XCTest
    @testable import CodeSign

    final class CodeSignTests: XCTestCase {
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
