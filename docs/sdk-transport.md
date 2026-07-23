# Rust SDK Transport

## Contract

`a3s-oci-sdk` is the only lifecycle API that A3S Box should consume. The same
`OciRuntimeService` trait is used for in-process tests and out-of-process
runtime calls. The transport maps every trait method; it does not invoke the
CLI or expose WHPX, libkrun, or native Linux driver internals.

The current wire contract is protocol version 1:

1. the client sends its inclusive supported protocol range;
2. the server selects the highest common version or rejects the connection;
3. each message is UTF-8 JSON preceded by a four-byte big-endian length;
4. empty frames and frames larger than 64 MiB are rejected before payload
   allocation;
5. every request and response carries the negotiated version and a nonzero
   request ID;
6. stable SDK errors cross the boundary without being converted to strings;
7. framing, version, or correlation failures permanently poison the
   connection;
8. every decoded request is validated before service dispatch.

Calls from cloned clients are serialized on one connection. This guarantees
deterministic response correlation while retaining an async, `Send + Sync`
API. A later protocol version may add multiplexing without changing the
service trait.

## A3S Box Client

On Windows, use a local named pipe:

```rust
use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};

# async fn connect() -> a3s_oci_sdk::Result<()> {
let endpoint =
    LocalIpcEndpoint::windows_named_pipe(r"\\.\pipe\a3s-oci-runtime")?;
let client = RuntimeClient::connect(&endpoint).await?;
let info = client.features().await?;
# let _ = info;
# Ok(())
# }
```

On Linux and macOS, use an absolute Unix-domain-socket path:

```rust
use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};

# async fn connect() -> a3s_oci_sdk::Result<()> {
let endpoint = LocalIpcEndpoint::unix_socket("/run/a3s/oci-runtime.sock")?;
let client = RuntimeClient::connect(&endpoint).await?;
let info = client.features().await?;
# let _ = info;
# Ok(())
# }
```

The platform-specific constructors are compiled only on their corresponding
targets. Callers can also create `RuntimeTransportClient::from_io` over an
already authenticated async byte stream.

For an in-process host integration, A3S Box can wrap
`HostRuntimeService::open(state_root, driver)` in `RuntimeClient`. The
`RuntimeDriver` trait receives exact-generation requests and the immutable
durable bundle at both create and start. Its mutating methods are async,
`Send + Sync`, and idempotent by `OperationId`. Platform resources and guest
protocol types remain behind that boundary.

## Runtime Server

Listener creation and access control belong to the runtime process because
they are part of its security boundary. After accepting and authenticating a
local stream, the runtime serves it with:

```rust
use std::sync::Arc;

use a3s_oci_sdk::{serve_transport_connection, OciRuntimeService};
use tokio::io::{AsyncRead, AsyncWrite};

async fn serve<T>(
    service: Arc<dyn OciRuntimeService>,
    stream: T,
) -> a3s_oci_sdk::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    serve_transport_connection(service, stream).await
}
```

On Windows, the runtime must apply a restrictive named-pipe security
descriptor before accepting clients. On Unix, it must bind inside a protected
runtime directory and set the intended owner and mode. The SDK deliberately
does not silently choose those authorization policies.

## Validation Boundary

`CreateRequest` and `RestoreRequest` carry `OciBundle`. Its wire decoder
revalidates the absolute bundle path, exact `config.json`, supported OCI
version, official schema, unknown-property policy, and SHA-256 digest before
the service receives the request. The transport therefore cannot be used to
bypass the SDK's bundle checks.

Every request implements `ValidateRequest`. The in-process `RuntimeClient`,
transport client, and server call it independently. The server-side check is
the trust boundary: manually encoded wire requests cannot bypass OCI
process/resource semantics, terminal consistency, absolute checkpoint paths,
or the 4,096-event and 16 MiB output/stdin limits.

Bundle construction also applies the configuration phase of
`OciSemanticValidator`. The start phase adds the OCI requirement for a
runnable process and must be applied to the durable bundle snapshot by the
lifecycle implementation. Schema and initial semantic validity are not the
final conformance gate; complete normative-rule coverage, driver enforcement,
durable lifecycle behavior, and upstream OCI conformance remain tracked in
the project roadmap.
