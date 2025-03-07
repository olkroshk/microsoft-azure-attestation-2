# SEV-SNP Attestation Sample with Azure Attestation

This is a minimal .NET console application that interacts with the Microsoft Azure Attestation (MAA) service for SEV-SNP virtual machine attestation. It sends an attestation request, retrieves a signed token, and allows further validation steps.

## Remote Attestation Flow with SEV-SNP

### 1. Collect Attestation Evidence
The confidential environment undergoing attestation (e.g., a confidential ACI container, SGX enclave, or Azure Confidential VM) generates attestation evidence that reflects its identity, state, and configuration.

### 2. Submit Evidence for Attestation
The attestation evidence is sent to the **Microsoft Azure Attestation (MAA)** service, which verifies the evidence against platform-specific security guarantees. If the attestation succeeds, MAA issues a signed JWT token.

### 3. Validate the Attestation Token
The signed JWT token is provided to a **relying party** that requires trust verification before interacting with the confidential environment (e.g., **Azure Key Vault for secure key release**). The relying party validates the JWT token by:
- Verifying the token signature.
- Optionally inspecting the attestation evidence to confirm MAA's TEE hosting environment.

### 4. Authorization Decision
Based on the validated attestation claims, the relying party makes an authorization decision on whether to trust and engage with the attested environment.

---

## Prerequisites

- **.NET SDK 8.0 or later** installed ([Download .NET](https://dotnet.microsoft.com/download))
- Internet access to reach the attestation endpoint
- An attestation instance URL (e.g., `https://instance.attest.azure.net`)
- **Required Dependencies:** Install the following NuGet packages if not already included:
  ```sh
  dotnet add package Newtonsoft.Json
  dotnet add package System.IdentityModel.Tokens.Jwt
  ```

## Installation and Setup

### Windows Setup

1. **Install .NET SDK** if not already installed.
2. Open **Command Prompt** or **PowerShell**.
3. Navigate to the project directory:
   ```sh
   cd /path/to/project
   ```
4. Install required dependencies:
   ```sh
   dotnet add package Newtonsoft.Json
   dotnet add package System.IdentityModel.Tokens.Jwt
   ```
5. Restore dependencies:
   ```sh
   dotnet restore
   ```
6. Build the project:
   ```sh
   dotnet build
   ```
7. Run the application with an optional SEV-SNP report parameter:
   ```sh
   dotnet run -- "YourBase64EncodedReportHere"
   ```
   If no report is provided, the default report will be used.

### Linux Setup

1. **Install .NET SDK**:
   ```sh
   sudo apt update
   sudo apt install -y dotnet-sdk-8.0
   ```
2. Open a terminal and navigate to the project directory:
   ```sh
   cd /path/to/project
   ```
3. Install required dependencies:
   ```sh
   dotnet add package Newtonsoft.Json
   dotnet add package System.IdentityModel.Tokens.Jwt
   ```
4. Restore dependencies:
   ```sh
   dotnet restore
   ```
5. Build the project:
   ```sh
   dotnet build
   ```
6. Run the application:
   ```sh
   dotnet run -- "YourBase64EncodedReportHere"
   ```

## Debugging and Development

### Using VS Code

1. Install **[VS Code](https://code.visualstudio.com/)**.
2. Install extensions:
   - **C# Dev Kit**
   - **.NET Install Tool**
   - **C# (OmniSharp)**
3. Open **VS Code** and load the project.
4. Add breakpoints in `Program.cs`.
5. Press **F5** to start debugging.

## Expected Output

- If successful, the program will print the attestation token and validation results.
- If there’s an issue, it will display an error message.

Example output:
```sh
Attestation Token: eyJhbGciOiJSUzI1NiIs...
JWT Token is valid.
```

## References

- [Microsoft Azure Attestation API](https://github.com/Azure/azure-rest-api-specs/tree/main/specification/attestation/data-plane/Microsoft.Attestation/stable/2022-08-01)
- [Attestation Request Example](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/attestation/data-plane/Microsoft.Attestation/stable/2022-08-01/examples/AttestSevSnpVm.json)

