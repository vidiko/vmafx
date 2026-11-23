- **vmafx-tune**: removed transitional Go import paths
  `pkg/tune/codec`, `pkg/tune/predictor` and `pkg/tune/pyjson`. Import
  `pkg/codecadapter`, `pkg/predictor` and `pkg/pyjson` instead (ADR-1137).

  - Replace `tune/predictor.New(path, log)` with `predictor.NewWithModel(ctx, path, log)`. Pass a context that lives as long as the predictor is in use. Pass `slog.Default()` where you previously passed `nil`.
  - Replace `tune/predictor.PickCRF(p, features, target, codec)` with `p.PickCRF(features, target, codec)`.
  - Replace `tune/pyjson.Marshal(v, indent)` with `pyjson.Marshal(v, pyjson.Options{SortKeys: true, Indent: strings.Repeat(" ", indent)})` for positive indents. The old indent helper used `indent` spaces per nesting level for positive values and selected compact output for `indent <= 0`. Pass `Indent: ""` for zero and negative values. The new function returns `([]byte, error)`. Use `string(out)` if you need the previous string result.
  - Replace `tune/pyjson.MustMarshal(v, indent)` with a call to `pyjson.Marshal` and handle the returned error.
  - The names `predictor.ResolutionClass`, `pyjson.MarshalStrict`, `pyjson.FormatFloat`, `pyjson.EncodeString`, `codecadapter.Get`, `codecadapter.Known` and `codecadapter.Adapter` stay the same.
