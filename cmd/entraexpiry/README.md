# entraexpiry

`entraexpiry` verifies that the configured Entra client credentials can acquire a Microsoft Graph token and read the application password-credential expiry metadata.

The command never prints the client secret. Prefer the environment variable so the secret is not exposed in shell history or the process list:

```powershell
$env:ENTRA_CLIENT_SECRET = 'your-client-secret'
go run ./cmd/entraexpiry `
  -tenant-id 'your-tenant-id' `
  -client-id 'your-client-id'
```

For a one-off invocation, `-client-secret` is also supported:

```powershell
go run ./cmd/entraexpiry `
  -tenant-id 'your-tenant-id' `
  -client-id 'your-client-id' `
  -client-secret 'your-client-secret'
```

The command resolves the application object from `ClientID` by default. If the application has multiple password credentials, provide the credential key ID:

```powershell
go run ./cmd/entraexpiry `
  -tenant-id 'your-tenant-id' `
  -client-id 'your-client-id' `
  -key-id 'password-credential-key-id'
```

The client credentials must have sufficient Microsoft Graph application permission to read application metadata, typically `Application.Read.All` with administrator consent. The probe uses client credentials flow and requests the `https://graph.microsoft.com/.default` scope.

A successful run prints the application display name, object ID, selected password credential key ID, and its `endDateTime`.


