(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Foreign
open Tls
open Rresult

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

let tls_poll_enum =
  let open Int64 in
  [
    "TLS_WANT_POLLIN",  of_int (-2);
    "TLS_WANT_POLLOUT", of_int (-3);
  ]

type tls = [ `Tls ] structure

let tls : tls typ = structure "tls"


type tls_error = [ `Tls_alert of Tls.Packet.alert_type
                 | `Tls_failure of Tls.Engine.failure
                 | `Tls_other of string
                 | `Eof
                 | `NotConfigured
                 | `UnixError of string ]

type t = {
  mutable error : tls_error option;
  config : (
    (Tls.Core.tls_version * Tls.Core.tls_version) option *
    Tls.Ciphersuite.ciphersuite list option *
    X509.Authenticator.a option *
    Tls.Config.own_cert
  ) option ;
  mutable fd : Unix.file_descr option ;
  mutable linger : Cstruct.t option ;
  mutable state : [ `Active of Tls.Engine.state
                  | `Init of (Tls.Engine.state * Cstruct.t)
                  | `Error of tls_error
                  | `NotConfigured ] ;
}

let () = Nocrypto_entropy_unix.initialize ()

let tls_init _ = 0

let tls_error p =
  let ctx = to_voidp p |> Root.get in
  match ctx.error with
  | Some (`Tls_alert a) -> Tls.Packet.alert_type_to_string a
  | Some (`Tls_failure f) -> Tls.Engine.string_of_failure f
  | Some (`Tls_other msg) -> msg
  | Some `Eof -> "Connection closed"
  | Some `NotConfigured -> "struct tls not configured"
  | Some (`UnixError s) -> Format.sprintf "Unix error: %s" s
  | None -> ""

let tls_client _ =
  let tls_client = { error = None;
                     config = None;
                     fd = None;
                     state = `NotConfigured;
                     linger = None;
                   } in
  Root.create tls_client |> from_voidp tls

let tls_server _ =
  let tls_server = { error = None;
                     config = None;
                     fd = None;
                     state = `NotConfigured;
                     linger = None; } in
  Root.create tls_server |> from_voidp tls

let tls_free p =
  if (ptr_compare (to_voidp p) null) == 0 then
    ()
  else
    to_voidp p |> Root.release
