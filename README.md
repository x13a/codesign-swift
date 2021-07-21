# codesign-swift

Code sign swifty helper.

## Example

To check pid codesign:
```swift
import Darwin
import CodeSign

func main() throws {
    let code = try CodeSign.createCode(with: getpid()).get()
    let requirement = try CodeSign.createRequirement(with: CodeSignRequirementString.apple).get()
    
    // this will throw cause code is not signed by apple
    try CodeSign.checkValidity(for: code, requirement: requirement).get()
}

main()
```
