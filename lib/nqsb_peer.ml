open Ctypes
open Nqsb

let is_none = function
  | None -> true
  | Some _ -> false

let tls_peer_cert_provided p =
  let open Tls.Core in
  let ctx = to_voidp p |> Root.get in
  match ctx.state with
  | `Active tls ->
    (match Tls.Engine.epoch tls with
    | `Epoch epoch ->
      if is_none epoch.peer_certificate then -1 else 0
    | `InitialEpoch -> -1)
  | _ -> -1
