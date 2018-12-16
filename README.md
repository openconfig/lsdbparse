# lsdbparse

This library contains a Go implementation which can parse an IS-IS LSP and
output it as gNMI Notifications containing OpenConfig encoded data.

Two public APIs are provided:

* `ISISBytesToLSP([]byte, int)`: takes an input byte array containing an IS-IS
  PDU beginning at the LSP ID field, and returns a ygot GoStruct containing the
  parsed LSP as per the OpenConfig schema, a bool indicating whether the LSP was
  succesfully parsed, and an error.
* `RenderNotifications(*oc.NetworkInstnace_Protocol_Isis_Level_Lsp,
  ISISRenderArgs)`: takes an input GoStruct corresponding to an IS-IS LSP, and
  returns a slice of gNMI notifications which correspond to the contents of the
  LSP, which can be used in streaming telemetry implementations.

## Note well

This is not an official Google product.

## Contributing
We welcome code contributions to the lsdbparse library. Please sign the Google
CLA and see the CONTRIBUTING document for further details.
