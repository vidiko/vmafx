- The CI pin check now validates each ONNX Runtime install on a shared shell
  line, flags ambiguous version assignments, and accepts unrelated NuGet
  downloads in steps that also define an ONNX Runtime package variable. Dynamic
  workflow version and NuGet package variables must now come from a single
  step `env:` key or whole-line literal assignment, and helper flags are
  checked against the installer's allow-list. Container helper calls with an
  inline `ORT_VERSION=` prefix are also refused, and an escaped space before
  `#` no longer starts a comment.
