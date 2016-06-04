open Ctypes

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
    X509.Authenticator.a *
    Tls.Config.own_cert
  ) option ;
  mutable fd : Unix.file_descr option ;
  mutable linger : Cstruct.t option ;
  mutable state : [ `Active of Tls.Engine.state
                  | `Init of (Tls.Engine.state * Cstruct.t)
                  | `Error of tls_error
                  | `NotConfigured ] ;
}

val tls_poll_enum : (string * int64) list

type tls = [ `Tls ] structure

val tls : tls typ

val tls_init : unit -> int

val tls_error : tls ptr -> string

val tls_client : unit -> tls ptr

val tls_server : unit -> tls ptr
