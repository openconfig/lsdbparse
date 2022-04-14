# lsdbparse

[![Build
Status](https://travis-ci.org/openconfig/lsdbparse.svg?branch=master)](https://travis-ci.org/openconfig/lsdbparse)
[![Coverage
Status](https://coveralls.io/repos/github/openconfig/lsdbparse/badge.svg?branch=master)](https://coveralls.io/github/openconfig/lsdbparse?branch=master)


This library contains a Go implementation which can parse an IS-IS LSP and
output it as gNMI Notifications containing OpenConfig encoded data.

Two public APIs are provided:

* `ISISBytesToLSP([]byte, int)`: takes an input byte array containing an IS-IS
  PDU beginning at the LSP ID field, and returns a ygot.ValidatedGoStruct containing the
  parsed LSP as per the OpenConfig schema, a bool indicating whether the LSP was
  succesfully parsed, and an error.

* `RenderNotifications(*oc.Lsp, ISISRenderArgs)`: takes an input GoStruct
  corresponding to an IS-IS LSP, and returns a slice of gNMI notifications which
  correspond to the contents of the LSP, which can be used in streaming telemetry
  implementations.

The generated code for the OpenConfig library uses a subset of the schema to
improve the efficiency for IS-IS LSP parsing operations.

## Note well

This is not an official Google product.

## Contributing
We welcome code contributions to the lsdbparse library. Please sign the Google
CLA and see the CONTRIBUTING document for further details.
