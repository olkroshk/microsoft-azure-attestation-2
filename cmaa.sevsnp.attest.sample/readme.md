# Attestation Client

This is a minimal .NET console application that interacts with the Microsoft Azure Attestation (MAA) service for SEV-SNP virtual machine attestation. It sends an attestation request, retrieves a signed token, and allows further validation steps.

## Features

- Uses `HttpClient` to interact with the `/attest/SevSnpVm` endpoint.

## Prerequisites

- **.NET SDK 8.0 or later** installed ([Download .NET](https://dotnet.microsoft.com/download))
- Internet access to reach the attestation endpoint
- An attestation instance URL (e.g., `https://instance.attest.azure.net`)

## Installation

### Project Location
This project is located in the `/cmaa.sevsnp.attest.sample` folder in the root of the repository.

### Ensure Dependencies

Ensure that `Newtonsoft.Json` is installed in your project. If it's missing, add it with:

```sh
dotnet add package Newtonsoft.Json
```

### Use the Provided Implementation

The provided code is already in `Program.cs`. Ensure that it contains the correct implementation.

## Setting Up in VS Code

### 1. Install VS Code and Required Extensions
- Download and install **[VS Code](https://code.visualstudio.com/)**
- Install the following extensions:
  - **C# Dev Kit**
  - **.NET Install Tool**
  - **C# (OmniSharp)**

### 2. Open the Project in VS Code
- Open **VS Code**
- Click **File > Open Folder** and select the `/cmaa.sevsnp.attest.sample` folder

### 3. Run the Application
- Open **Terminal (`Ctrl + ~`)**
- Run:
  ```sh
  dotnet run
  ```

### 4. Debugging in VS Code
- Open **Program.cs**
- Add a **breakpoint** by clicking on the left margin
- Press **F5** to start debugging

## Usage

### Running the Application

Navigate to the project directory:
```sh
cd /cmaa.sevsnp.attest.sample
```
Then run:
```sh
dotnet run
```

### Expected Output

If successful, the application will:

- Send an attestation request.
- Retrieve an attestation token.
- Print the token to the console.

```sh
Attestation Token: eyJhbGciOiJSUzI1NiIs...
Validation steps to be implemented...
```

### Error Handling

If there’s an issue with the request, you’ll see:

```sh
Error: [Detailed error message]
```

## Request and API Definitions

- A sample request for attestation is available in the **Swagger definition for MAA API version 2022-08-01**:
  - [Attestation Request Example](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/attestation/data-plane/Microsoft.Attestation/stable/2022-08-01/examples/AttestSevSnpVm.json)
- The full **API schema definitions** can be found here:
  - [API Swagger Definition](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/attestation/data-plane/Microsoft.Attestation/stable/2022-08-01/attestation.json)

## Modifications

- Implement **validation logic** where indicated.
- Update the **attestation instance URL** (`https://instance.attest.azure.net`).
- Modify request parameters (`report`, `runtimeData`, `nonce`) as needed.

## License

This project is licensed under the MIT License.

