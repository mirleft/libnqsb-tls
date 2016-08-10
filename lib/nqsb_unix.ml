(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Nqsb
open Rresult
open Ctypes

exception Tls_want_pollin
exception Tls_want_pollout

(* Chunk size as defined in OpenSSL: src/ssl/ssl3.h *)
let max_chunk = 16384

module Utils = struct

  open Unix

  let o f g x = f (g x)

  let resolve host port =
    let proto = getprotobyname "tcp" in
    match getaddrinfo host port [AI_PROTOCOL proto.p_proto] with
    | exception _ -> Error (`UnixError "Error while resolving address")
    | [] -> Error (`UnixError "No matching host")
    | ai::_ -> Ok ai.ai_addr

  let write fd cs =
    let open Cstruct in
    let buf = Cstruct.to_string cs in
    match Unix.single_write fd buf 0 cs.len with
    | exception (Unix_error (Unix.EAGAIN, _, _)) -> Ok 0
    | exception (Unix_error (e, _, _)) -> Error (`UnixError (error_message e))
    | res -> Ok res >>= fun res ->
    match Unix.getsockopt_error fd with
    | None -> Ok res
    | Some err -> Error (`UnixError (error_message err))

  let read fd =
    let buf = Bytes.create 4096 in
    let res = Cstruct.(Unix.read fd buf 0 4096) in
    match Unix.getsockopt_error fd with
    | None -> if res = 0 then Error `Eof else Ok (Cstruct.of_string (String.sub buf 0 res))
    | Some err -> Error (`UnixError (error_message err))

  let rec write_full fd = function
    | cs when Cstruct.len cs = 0 -> Ok ()
    | cs -> write fd cs >>= o (write_full fd ) (Cstruct.shift cs) >>= fun () -> Ok ()

  let rec write_t t cs =
    match t.fd with
    | None -> Error (`Tls_other "No associated fd")
    | Some fd -> write_full fd cs

  let read_t t =
    match t.fd with
    | None -> Error (`Tls_other "No associated fd")
    | Some fd -> try read fd with _ -> raise Tls_want_pollin

  let connect host service =
    resolve host service >>= fun addr ->
    let fd = Unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    (match Unix.connect fd addr with
     | () -> Ok fd
     | exception _ -> Error (`UnixError "connect: Error"))

end

let tls_connect_aux ctx servername fd =

  (match ctx.config with
  | None -> Error (`Tls_other "Context not configured")
  | Some config -> Ok config)

  >>= fun (version, ciphers, authenticator, certificates) ->
  match authenticator with
  | None ->
    Error (`Tls_other "Client auth enabled but no CA provided")
  | Some authenticator ->
    let config = Tls.Config.client ?version ?ciphers ~authenticator ~certificates () in
    let peer = Tls.Config.peer config servername in
    let tls = Tls.Engine.client peer in
    Ok { ctx with fd = Some fd; state = (`Init tls); }

let tls_connect_servername p host service servername =
  let ctx = to_voidp p |> Root.get in
  Utils.connect host service >>|
  tls_connect_aux ctx host |>
  function
  | Error msg ->
    Root.set (to_voidp p) { ctx with error = Some msg }; -1
  | Ok state ->
    Root.set (to_voidp p) state; 0

let tls_connect p host service =
  tls_connect_servername p host service host

let tls_connect_socket p socket servername =
  let ctx = to_voidp p |> Root.get in
  let fd = Obj.magic socket in
  match tls_connect_aux ctx servername fd with
  | Error msg ->
    Root.set (to_voidp p) { ctx with error = Some msg }; -1
  | Ok state ->
    Root.set (to_voidp p) state; 0

let rec handle_tls t =

  let handle tls buf =
    match
      Tls.Engine.handle_tls tls buf
    with
    | `Ok (state, `Response resp, `Data data) ->
      let state' = match state with
        | `Ok tls -> `Active tls
        | `Eof -> `Error `Eof
        | `Alert a -> `Error (`Tls_alert a) in
      (match resp with
       | Some cs -> Utils.write_t t cs
       | None -> Ok ())
      >>= fun _ ->
      let () = t.state <- state' in
      Ok data
    | `Fail (alert, `Response resp) ->
      let () = (t.state <- `Error (`Tls_failure alert)) in
      Utils.write_t t resp >>= fun _ -> handle_tls t in

  match t.state with
  | `Error e -> Error e
  | `NotConfigured -> Error `NotConfigured
  | `Init (tls, cs) ->
    Utils.write_t t cs >>= fun _ ->
    let () = t.state <- `Active tls in handle_tls t
  | `Active tls -> Utils.read_t t >>= fun cs -> handle tls cs

let rec complete_handshake t =
  let push_linger t mcs =
    let open Tls.Utils.Cs in
    match (mcs, t.linger) with
    | (None, _) -> ()
    | (scs, None) -> t.linger <- scs
    | (Some cs, Some l) -> t.linger <- Some (l <+> cs)
  in
  match t.state with
  | `Active tls when Tls.Engine.can_handle_appdata tls -> Ok ()
  | `Error e -> Error e
  | `NotConfigured -> Error `NotConfigured
  | `Active tls
    | `Init (tls, _) ->
     handle_tls t >>= fun cs ->
     push_linger t cs; complete_handshake t

let tls_handshake p =
  try
    let ctx = to_voidp p |> Root.get in
    let completed = complete_handshake ctx in
    let () = Root.set (to_voidp p) ctx in
    match completed with
    | Ok () -> 0
    | Error e -> Root.set (to_voidp p) { ctx with error = Some e }; -1
  with
  | Tls_want_pollin -> -2
  | Tls_want_pollout -> -3

let rec read_bytes t buf =
  let writeout res =
    let open Cstruct in
    let rlen = len res in
    let n = min (len buf) rlen in
    blit res 0 buf 0 n ;
    t.linger <- (if n < rlen then Some (sub res n (rlen - n)) else None) ;
    Ok n in

  match t.linger with
  | Some res -> writeout res
  | None     ->
    handle_tls t >>= function
    | None -> read_bytes t buf
    | Some cs -> writeout cs

let rec write_bytes t cs =
  let len = if cs.Cstruct.len > max_chunk then max_chunk else cs.Cstruct.len in
  let chunk, cs = Cstruct.split cs len in
  match t.state with
  | `Error e -> Error e
  | `NotConfigured -> Error `NotConfigured
  | `Init _ -> complete_handshake t >>= fun () -> write_bytes t cs
  | `Active tls ->
    match Tls.Engine.send_application_data tls [chunk] with
    | Some (tls, data) ->
      Utils.write_t t data >>= fun () ->
      t.state <- `Active tls;
      Ok len
    | None -> Error (`Tls_other "socker not ready")

let cs_of_ptr ptr_type buffer_ptr size =
  let buffer_char = Ctypes.coerce ptr_type (ptr char) buffer_ptr in
  let barr = bigarray_of_ptr array1 size Bigarray.char buffer_char in
  Cstruct.of_bigarray barr

let tls_write p buf size =
  try
    let ctx = to_voidp p |> Root.get in
    let cs = cs_of_ptr (ptr void) buf (Unsigned.Size_t.to_int size) in
    let written = write_bytes ctx cs in
    let () = Root.set (to_voidp p) ctx in
    match written with
    | Ok written -> PosixTypes.Ssize.of_int written
    | Error e -> Root.set (to_voidp p) { ctx with error = Some e }; PosixTypes.Ssize.of_int (-1)
  with
  | Tls_want_pollin -> (PosixTypes.Ssize.of_int (-2))
  | Tls_want_pollout -> (PosixTypes.Ssize.of_int (-3))

let tls_read p buf size =
  try
    let ctx = to_voidp p |> Root.get in
    let cs = cs_of_ptr (ptr void) buf (Unsigned.Size_t.to_int size) in
    let read = read_bytes ctx cs in
    let () = Root.set (to_voidp p) ctx in
    match read with
    | Ok i -> i
    | Error e -> Root.set (to_voidp p) { ctx with error = Some e }; -1
  with
  | Tls_want_pollin -> -2
  | Tls_want_pollout -> -3

let tls_close p =
  (* FIXME: handle more closing cases, close the fd if we opened the socket *)
  let ctx = to_voidp p |> Root.get in
  try
    let closed =
      match ctx.state with
      | `Active tls ->
        let (_, cs) = Tls.Engine.send_close_notify tls in
        Utils.write_t ctx cs
      | _ -> Ok () in
    match closed with
    | Ok _ -> Root.set (to_voidp p) { ctx with state = `Error `Eof; }; 0
    | Error _ -> -1
  with
  | Tls_want_pollin -> -2
  | Tls_want_pollout -> -3

let tls_accept_socket p pp socket =
  let ctx = to_voidp p |> Root.get in
  let cctx =
    (match ctx.config with
     | None -> Error (`Tls_other "Context not configured")
     | Some config -> Ok config)
    >>= fun (version, ciphers, authenticator, certificates) ->
    let config = Tls.Config.server ?version ?ciphers ?authenticator ~certificates () in
    let tls = Tls.Engine.server config in
    Ok { ctx with fd = Some (Obj.magic socket); state = (`Active tls) } in
  match cctx with
  | Ok cctx ->
     let cctx_ptr = Root.create cctx in
     pp <-@ (from_voidp tls cctx_ptr); 0
  | Error msg ->
     Root.set (to_voidp p) { ctx with error = Some msg }; -1
