# SEV-SNP Attestation Sample with Azure Attestation

This is a minimal .NET console application that interacts with the Microsoft Azure Attestation (MAA) service for SEV-SNP attestation type.

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
- **Clone the Repository**:

  ```sh
  git clone --recursive https://github.com/Azure-Samples/microsoft-azure-attestation.git
  cd microsoft-azure-attestation/cmaa.sevsnp.attest.sample
  ```

## Installation and Setup

### Windows Setup

1. **Install .NET SDK** if not already installed.
2. Open **Command Prompt** or **PowerShell**.
3. Navigate to the project directory:

   ```sh
   cd microsoft-azure-attestation/cmaa.sevsnp.attest.sample
   ```

4. Restore dependencies:

   ```sh
   dotnet restore
   ```

5. Build the project:

   ```sh
   dotnet build
   ```

6. Run the application with an optional SEV-SNP report parameter:

   ```sh
   dotnet run
   ```

### Linux Setup

1. **Install .NET SDK**:

   ```sh
   sudo apt update
   sudo apt install -y dotnet-sdk-8.0
   ```

2. Open a terminal and navigate to the project directory:

   ```sh
   cd microsoft-azure-attestation/cmaa.sevsnp.attest.sample
   ```

3. Restore dependencies:

   ```sh
   dotnet restore
   ```

4. Build the project:

   ```sh
   dotnet build
   ```

5. Run the application:

   ```sh
   dotnet run
   ```

## Publishing and Running Standalone Executable

To generate a **standalone executable**, use the following command:

### **Windows**

```sh
   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The `.exe` file will be located in:

```sh
   bin\Release\net8.0\win-x64\publish\
```

Run the standalone executable:

```sh
   bin\Release\net8.0\win-x64\publish\cmaa.sevsnp.attest.sample.exe
```

### **Linux**

```sh
   dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true
```

The binary will be located in:

```sh
   bin/Release/net8.0/linux-x64/publish/
```

Run the standalone executable:

```sh
   bin/Release/net8.0/linux-x64/publish/cmaa.sevsnp.attest.sample
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

## Cleaning and Rebuilding the Project

If you encounter issues, try cleaning and rebuilding the project:

```sh
   dotnet clean
   dotnet build
```

If package restoration fails, clear the NuGet cache:

```sh
   dotnet nuget locals all --clear
   dotnet restore
```

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
