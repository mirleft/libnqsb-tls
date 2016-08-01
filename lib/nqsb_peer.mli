(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Nqsb

val tls_peer_cert_provided : tls ptr -> int

val tls_conn_cipher : tls ptr -> string option

val tls_conn_version : tls ptr -> string option

val tls_peer_cert_subject : tls ptr -> string option

val tls_peer_cert_issuer : tls ptr -> string option

val tls_peer_cert_notbefore : tls ptr -> int

val tls_peer_cert_notafter : tls ptr -> int

val tls_peer_cert_hash : tls ptr -> string option
