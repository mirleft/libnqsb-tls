(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Tls

type t = {
  ca_file : string option;
  ca_path : string option;
  ca_mem : Cstruct.t option;
  cert_file : string option;
  cert_mem : Cstruct.t option;
  ciphers : string option;
  key_file : string option;
  key_mem : Cstruct.t option;
  protocols : Unsigned.UInt32.t option;
  verify_server_cert : bool;
  verify_client_cert : bool;
  verify_server_name : bool;
  verify_time : bool;
  verify_depth : Unsigned.UInt32.t option;
}

type tls_config = [ `Tls_config ] structure

let tls_config : tls_config typ = structure "tls_config"

let tls_protocol_version_enum =
  let open Int64 in
  let one = of_int 1 in
  let ( |~ ) = logor in
  let tlsv1_0 = shift_left one 1 in
  let tlsv1_1 = shift_left one 2 in
  let tlsv1_2 = shift_left one 3 in
  [
    "TLS_PROTOCOL_TLSv1_0",  tlsv1_0;
    "TLS_PROTOCOL_TLSv1_1",  tlsv1_1;
    "TLS_PROTOCOL_TLSv1_2",  tlsv1_2;
    "TLS_PROTOCOL_TLSv1",    tlsv1_0 |~ tlsv1_1 |~ tlsv1_2;
    "TLS_PROTOCOLS_ALL",     tlsv1_0 |~ tlsv1_1 |~ tlsv1_2;
    "TLS_PROTOCOLS_DEFAULT", tlsv1_2;
  ]

let tls_config_new _ =
  let config = {
    ca_file = None;
    ca_path = None;
    ca_mem = None;
    cert_file = None;
    cert_mem = None;
    ciphers = None;
    key_file = None;
    key_mem = None;
    protocols = None;
    verify_server_cert = true;
    verify_client_cert = true;
    verify_server_name = true;
    verify_time = true;
    verify_depth = None;
  } in
  Root.create config |> from_voidp tls_config

let tls_config_free p =
  if (ptr_compare (to_voidp p) null) == 0 then
    ()
  else
    to_voidp p |> Root.release

let update_config p f =
  let config = to_voidp p |> Root.get in
  Root.set (to_voidp p) (f config);
  0

let tls_config_set_ca_file p file =
  update_config p (fun c -> { c with ca_file = Some file })

let tls_config_set_ca_path p path =
  update_config p (fun c -> { c with ca_path = Some path })

let tls_config_set_ca_mem p buffer size =
  let buffer_char = Ctypes.coerce (ptr uint8_t) (ptr char) buffer in
  let barr = bigarray_of_ptr array1 size Bigarray.char buffer_char in
  let cs = Cstruct.of_bigarray barr in
  update_config p (fun c -> { c with ca_mem = Some cs })

let tls_config_set_cert_file p file =
  update_config p (fun c -> { c with cert_file = Some file })

let tls_config_set_cert_mem p buffer size =
  let buffer_char = Ctypes.coerce (ptr uint8_t) (ptr char) buffer in
  let barr = bigarray_of_ptr array1 size Bigarray.char buffer_char in
  let cs = Cstruct.of_bigarray barr in
  update_config p (fun c -> { c with cert_mem = Some cs })

let tls_config_set_key_file p file =
  update_config p (fun c -> { c with key_file = Some file })

let tls_config_set_key_mem p buffer size =
  let buffer_char = Ctypes.coerce (ptr uint8_t) (ptr char) buffer in
  let barr = bigarray_of_ptr array1 size Bigarray.char buffer_char in
  let cs = Cstruct.of_bigarray barr in
  update_config p (fun c -> { c with key_mem = Some cs })

let tls_config_clear_keys p =
  (* FIXME: The libtls doc says that this function should remove all key from memory, is that enough ? *)
  ignore @@ update_config p (fun c -> { c with key_mem = None })

let tls_config_set_ciphers p ciphers =
  update_config p (fun c -> { c with ciphers = Some ciphers })

let tls_config_set_protocols p proto =
  ignore @@ update_config p (fun c -> { c with protocols = Some proto })

let tls_config_set_verify_depth p depth =
  ignore @@ update_config p (fun c -> { c with verify_depth = Some depth })

let tls_config_insecure_noverifycert p =
  ignore @@ update_config p (fun c -> { c with verify_server_cert = false;
                                     verify_client_cert = false })

let tls_config_insecure_noverifyname p =
  ignore @@ update_config p (fun c -> { c with verify_server_name = false })

let tls_config_insecure_noverifytime p =
  ignore @@ update_config p (fun c -> { c with verify_time = false })

let tls_config_verify p =
  ignore @@ update_config p (fun c -> { c with verify_server_name = true;
                                               verify_server_cert = true })

let tls_config_verify_client p =
  ignore @@ update_config p (fun c -> { c with verify_client_cert = true })

let tls_config_parse_protocols protocol_result s =
  let open Int64 in
  let rec parse_string flags patterns =
    match patterns with
    | pattern::xs ->
      let len = String.length pattern in
      let neg, pattern =
        if String.get pattern 0 = '!' then
          true, String.sub pattern 1 (len - 1)
        else
          false, pattern in
      let flag =
        match String.lowercase pattern with
        | "all"
        | "legacy"  -> List.assoc "TLS_PROTOCOLS_ALL" tls_protocol_version_enum
        | "secure"
        | "default" -> List.assoc "TLS_PROTOCOLS_DEFAULT" tls_protocol_version_enum
        | "tlsv1"   -> List.assoc "TLS_PROTOCOL_TLSv1" tls_protocol_version_enum
        | "tlsv1.0" -> List.assoc "TLS_PROTOCOL_TLSv1_0" tls_protocol_version_enum
        | "tlsv1.1" -> List.assoc "TLS_PROTOCOL_TLSv1_1" tls_protocol_version_enum
        | "tlsv1.2" -> List.assoc "TLS_PROTOCOL_TLSv1_2" tls_protocol_version_enum
        | s -> zero in
      if flag = zero then
        None
      else
        let flags = if neg
          then logand flags (lognot flag)
          else logor flags flag
        in parse_string flags xs
    | [] -> Some flags
  in
  let splitted = Str.split (Str.regexp ",\\|:") s in
  let protocols = parse_string zero splitted in
  match protocols with
  | None ->  -1
  | Some protocols -> protocol_result <-@ (Unsigned.UInt32.of_int (to_int protocols)); 0

let tls_configure tls_ptr tls_conf_ptr =
  let open Rresult in

  let parse_versions protocols =
    let open Unsigned.UInt32 in
    let open Tls.Core in

    match protocols with
    | None -> Ok None
    | Some protocols ->
      let ok t = Ok (Some t) in
      let is_bit_set bit = (compare (logor protocols (shift_left one bit)) zero) != 0 in

      match (is_bit_set 1), (is_bit_set 2), (is_bit_set 3) with
      | (true, true, true)
      | (true, false, true)  -> ok (TLS_1_0, TLS_1_2)
      | (true, true, false)  -> ok (TLS_1_0, TLS_1_1)
      | (true, false, false) -> ok (TLS_1_0, TLS_1_0)
      | (false, true, false) -> ok (TLS_1_1, TLS_1_1)
      | (false, true, true)  -> ok (TLS_1_1, TLS_1_2)
      | (false, false, true) -> ok (TLS_1_2, TLS_1_2)
      | _ -> Error "TLS protocol version range is wrong" in

  let parse_ciphers = function
    | Some cipher ->
      ( match cipher with
        | "secure"
        | "default" -> Ok (Some Tls.Config.Ciphers.default)
        | "all"
        | "legacy" -> Ok (Some Tls.Config.Ciphers.supported)
        | _ -> Error "Invalid ciphersuite" )
    | None -> Ok None in

  let parse_authenticator c =
    (* FIXME: Need to handle no_verify_*_cert options *)
    if c.verify_client_cert || c.verify_client_cert then
      match c.ca_mem, c.ca_file, c.ca_path with
      | (Some content), _, _ -> Nqsb_x509.authenticator (`Ca_mem content)
      | _, (Some path), _ -> Nqsb_x509.authenticator (`Ca_file path)
      | _, _, (Some path) -> Nqsb_x509.authenticator (`Ca_dir path)
      | None, None, None -> Nqsb_x509.authenticator (`No_auth)
    else
      Ok X509.Authenticator.null in

  let parse_certificates c =
    let cert = match c.cert_file, c.cert_mem with
      | (Some path), None -> Some (`File path)
      | _, (Some path) -> Some (`Buffer path)
      | None, None -> None in
    let priv_key = match c.key_file, c.key_mem with
      | (Some path), None -> Some (`File path)
      | _, (Some path) -> Some (`Buffer path)
      | None, None -> None in
    match cert, priv_key with
    | None, _ -> Ok `None
    | Some cert, None -> Ok `None
    | Some cert, Some priv_key ->
       Nqsb_x509.private_of_pems ~cert ~priv_key in

  let config = to_voidp tls_conf_ptr |> Root.get in
  let (tls : Nqsb.t) = to_voidp tls_ptr |> Root.get in

  let ctx =
    parse_versions config.protocols >>= fun version ->
    parse_ciphers config.ciphers >>= fun ciphers ->
    parse_authenticator config >>= fun authenticator ->
    parse_certificates config >>= fun certificates ->
    try
      Ok (version, ciphers, authenticator, certificates)
    with
    | Invalid_argument msg -> Error msg
  in
  match ctx with
  | Ok ctx ->
    Root.set (to_voidp tls_ptr) { tls with Nqsb.config = Some ctx }; 0
  | Error msg ->
    Root.set (to_voidp tls_ptr) { tls with Nqsb.error = Some (`Tls_other msg) }; -1

let tls_config_prefer_ciphers_server p = (* FIXME: handle this option  *) ()

let tls_config_prefer_ciphers_client p = (* FIXME: handle this option  *) ()

let tls_load_file path len_ptr _ =
  (* FIXME: handle the password parameter when supplied *)
  let open Rresult in
  let open Cstruct in

  let loaded_file =
    Nqsb_x509.read_file path >>= fun (file : Cstruct.t) ->
    match Malloc.malloc (Unsigned.Size_t.of_int (file.len * (Ctypes.sizeof Ctypes.char))) with
    | p when (ptr_compare null p) = 0 -> Error "Couldn't allocate buffer"
    | p -> Ok p >>= fun buffer ->
      let src = Cstruct.to_bigarray file in
      let dst = CArray.from_ptr (Ctypes.coerce (ptr void) (ptr char) buffer) file.len in
      Memcpy.memcpy (Memcpy.bigarray Ctypes.array1 file.len Bigarray.char) Memcpy.carray
        ~src ~src_off:file.off ~dst ~dst_off:0 ~len:file.len;
      Ok (buffer, file.len) in

  match loaded_file with
  | Ok (buffer_ptr, len) ->
    let () = len_ptr <-@ (Unsigned.Size_t.of_int len) in
    Ctypes.coerce (ptr void) (ptr uint8_t) buffer_ptr
  | Error _ -> Ctypes.coerce (ptr void) (ptr uint8_t) null
