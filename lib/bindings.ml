(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Foreign
open Nqsb_config
open Nqsb_unix
open Nqsb_peer
open Nqsb

module Stubs (I : Cstubs_inverted.INTERNAL) =
struct

  let () = I.enum tls_protocol_version_enum (Ctypes.typedef Ctypes.int "enum TlsProtocolVersion")

  let () = I.enum tls_poll_enum (Ctypes.typedef Ctypes.int "enum TlsPoll")

  let () = I.structure tls_config

  let () = I.structure tls

  let () = I.internal
      "tls_init" (void @-> returning int) tls_init

  let () = I.internal
      "tls_error" (ptr tls @-> returning string) tls_error

  let () = I.internal
      "tls_config_new" (void @-> returning (ptr tls_config)) tls_config_new

  let () = I.internal
      "tls_config_free" (ptr tls_config @-> returning void) tls_config_free

  let () = I.internal
      "tls_config_set_ca_file" (ptr tls_config @-> string @-> returning int) tls_config_set_ca_file

  let () = I.internal
      "tls_config_set_ca_path" (ptr tls_config @-> string @-> returning int) tls_config_set_ca_path

  let () = I.internal
      "tls_config_set_ca_mem" (ptr tls_config @-> ptr uint8_t @-> int @-> returning int) tls_config_set_ca_mem

  let () = I.internal
      "tls_config_set_cert_file" (ptr tls_config @-> string @-> returning int) tls_config_set_cert_file

  let () = I.internal
      "tls_config_set_cert_mem" (ptr tls_config @-> ptr uint8_t @-> int @-> returning int) tls_config_set_cert_mem

  let () = I.internal
      "tls_config_set_ciphers" (ptr tls_config @-> string @-> returning int) tls_config_set_ciphers

  let () = I.internal
      "tls_config_set_key_file" (ptr tls_config @-> string @-> returning int) tls_config_set_key_file

  let () = I.internal
      "tls_config_set_key_mem" (ptr tls_config @-> ptr uint8_t @-> int @-> returning int) tls_config_set_key_mem

  let () = I.internal
      "tls_config_set_protocols" (ptr tls_config @-> uint32_t @-> returning void) tls_config_set_protocols

  let () = I.internal
      "tls_config_set_verify_depth" (ptr tls_config @-> uint32_t @-> returning void) tls_config_set_verify_depth

  let () = I.internal
      "tls_config_insecure_noverifycert" (ptr tls_config @-> returning void) tls_config_insecure_noverifycert

  let () = I.internal
      "tls_config_insecure_noverifytime" (ptr tls_config @-> returning void) tls_config_insecure_noverifytime

  let () = I.internal
      "tls_config_insecure_noverifyname" (ptr tls_config @-> returning void) tls_config_insecure_noverifyname

  let () = I.internal
      "tls_config_verify" (ptr tls_config @-> returning void) tls_config_verify

  let () = I.internal
      "tls_config_verify_client" (ptr tls_config @-> returning void) tls_config_verify_client

  let () = I.internal
      "tls_config_verify_client_optional" (ptr tls_config @-> returning void) tls_config_verify_client_optional

  let () = I.internal
      "tls_config_parse_protocols" (ptr uint32_t @-> string @-> returning int) tls_config_parse_protocols

  let () = I.internal
      "tls_config_prefer_ciphers_server" (ptr tls_config @-> returning void) tls_config_prefer_ciphers_server

  let () = I.internal
      "tls_config_prefer_ciphers_client" (ptr tls_config @-> returning void) tls_config_prefer_ciphers_client

  let () = I.internal
      "tls_server" (void @-> returning (ptr tls)) tls_server

  let () = I.internal
      "tls_client" (void @-> returning (ptr tls)) tls_client

  let () = I.internal
      "tls_configure" (ptr tls @-> ptr tls_config @-> returning int) tls_configure

  let () = I.internal
      "tls_connect" (ptr tls @-> string @-> string @-> returning int) tls_connect

  let () = I.internal
      "tls_connect_servername" (ptr tls @-> string @-> string @-> string @-> returning int) tls_connect_servername

  let () = I.internal
      "tls_connect_socket" (ptr tls @-> int @-> string @-> returning int) tls_connect_socket

  let () = I.internal
      "tls_handshake" (ptr tls @-> returning int) tls_handshake

  let () = I.internal
      "tls_write" (ptr tls @-> ptr void @-> size_t @-> returning PosixTypes.ssize_t) tls_write

  let () = I.internal
      "tls_read" (ptr tls @-> ptr void @-> size_t @-> returning int) tls_read

  let () = I.internal
      "tls_accept_socket" (ptr tls @-> ptr (ptr tls) @-> int @-> returning int) tls_accept_socket

  let () = I.internal
      "tls_config_set_dheparams" (ptr tls_config @-> string @-> returning int) (fun _ _ -> 0)

  let () = I.internal
      "tls_config_set_ecdhecurve" (ptr tls_config @-> string @-> returning int) (fun _ _ -> 0)

  let () = I.internal
      "tls_close" (ptr tls @-> returning int) tls_close

  let () = I.internal
      "tls_free" (ptr tls @-> returning void) tls_free

  let () = I.internal
      "tls_config_clear_keys" (ptr tls_config @-> returning void) tls_config_clear_keys

  let () = I.internal
      "tls_load_file" (string @-> ptr size_t @-> string_opt @-> returning (ptr uint8_t)) tls_load_file

  let () = I.internal
      "tls_peer_cert_provided" (ptr tls @-> returning int) tls_peer_cert_provided

  let () = I.internal
      "tls_conn_cipher" (ptr tls @-> returning string_opt) tls_conn_cipher

  let () = I.internal
      "tls_conn_version" (ptr tls @-> returning string_opt) tls_conn_version

  let () = I.internal
      "tls_peer_cert_subject" (ptr tls @-> returning string_opt) tls_peer_cert_subject

  let () = I.internal
      "tls_peer_cert_issuer" (ptr tls @-> returning string_opt) tls_peer_cert_issuer

  let () = I.internal
      "tls_peer_cert_notbefore" (ptr tls @-> returning int) tls_peer_cert_notbefore

  let () = I.internal
      "tls_peer_cert_notafter" (ptr tls @-> returning int) tls_peer_cert_notafter

  let () = I.internal
      "tls_peer_cert_hash" (ptr tls @-> returning string_opt) tls_peer_cert_hash
end
