(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes

type t

val tls_protocol_version_enum : (string * int64) list

type tls_config = [ `Tls_config ] structure

val tls_config : tls_config typ

val tls_config_new : unit -> tls_config ptr

val tls_config_free : tls_config ptr -> unit

val tls_config_set_ca_file : tls_config ptr -> string -> int

val tls_config_set_ca_path : tls_config ptr -> string -> int

val tls_config_set_ca_mem :  tls_config ptr -> Unsigned.uint8 ptr -> int -> int

val tls_config_set_cert_file : tls_config ptr -> string -> int

val tls_config_set_cert_mem :  tls_config ptr -> Unsigned.uint8 ptr -> int -> int

val tls_config_set_ciphers :  tls_config ptr -> string -> int

val tls_config_set_key_file : tls_config ptr -> string -> int

val tls_config_set_key_mem :  tls_config ptr -> Unsigned.uint8 ptr -> int -> int

val tls_config_clear_keys : tls_config ptr -> unit

val tls_config_set_protocols :  tls_config ptr -> Unsigned.uint32 -> unit

val tls_config_set_verify_depth :  tls_config ptr -> Unsigned.uint32 -> unit

val tls_config_insecure_noverifycert : tls_config ptr -> unit

val tls_config_insecure_noverifyname : tls_config ptr -> unit

val tls_config_insecure_noverifytime : tls_config ptr -> unit

val tls_config_verify : tls_config ptr -> unit

val tls_config_verify_client : tls_config ptr -> unit

val tls_config_parse_protocols : Unsigned.uint32 ptr -> string -> int

val tls_configure : Nqsb.tls ptr -> tls_config ptr -> int

val tls_config_prefer_ciphers_server : tls_config ptr -> unit

val tls_load_file : string -> Unsigned.Size_t.t Ctypes.ptr -> string option -> Unsigned.uint8 Ctypes_static.ptr
