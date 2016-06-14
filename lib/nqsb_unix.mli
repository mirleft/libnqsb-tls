(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Nqsb

exception Tls_want_pollin
exception Tls_want_pollout

val tls_connect : tls ptr -> string -> string -> int

val tls_handshake : tls ptr -> int

val tls_write : tls ptr -> unit ptr -> Unsigned.size_t -> int

val tls_read : tls ptr -> unit ptr -> Unsigned.size_t -> int

val tls_accept_socket : tls ptr -> tls ptr ptr -> int -> int

val tls_close : tls ptr -> int
