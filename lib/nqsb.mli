(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes

type tls_error = [ `Tls_alert of Tls.Packet.alert_type
                 | `Tls_failure of Tls.Engine.failure
                 | `Tls_other of string
                 | `Eof
                 | `NotConfigured
                 | `Configured
                 | `UnixError of string ]


type config_t =
  (Tls.Core.tls_version * Tls.Core.tls_version) option *
  Tls.Ciphersuite.ciphersuite list option *
  X509.Authenticator.a option *
  Tls.Config.own_cert

type t = {
  mutable error : tls_error option;
  mutable fd : Unix.file_descr option ;
  mutable linger : Cstruct.t option ;
  mutable state : [ `Active of Tls.Engine.state
                  | `Init of (Tls.Engine.state * Cstruct.t)
                  | `Error of tls_error
                  | `NotConfigured
                  | `Configured of config_t
                  ] ;
}

val tls_poll_enum : (string * int64) list

type tls = [ `Tls ] structure

val tls : tls typ

val tls_init : unit -> int

val tls_error : tls ptr -> string

val tls_client : unit -> tls ptr

val tls_server : unit -> tls ptr

val tls_free : tls ptr -> unit
