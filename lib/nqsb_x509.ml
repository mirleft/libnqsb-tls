(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Rresult

let (</>) a b = a ^ "/" ^ b

let concat l =
  let rec aux acc = function
    | (Error a)::_ -> Error a
    | (Ok a)::xs -> aux (a :: acc) xs
    | [] -> Ok acc in
  aux [] l

let read_file file =
  try
    let ic = open_in_gen [Open_rdonly] 0 file in
    let len = in_channel_length ic in
    let s = Bytes.create len in
    really_input ic s 0 len;
    close_in ic;
    Ok (Cstruct.of_string s)
  with
  | Sys_error s -> Error (Format.sprintf "X509 reading file: %s" s)

let read_dir path =
  let rec collect acc handle =
    let f =
      try
        Some (Unix.readdir handle)
      with
      | _ -> None in
    match f with
    | Some f -> collect (f :: acc) handle
    | None -> acc in
  try
    let handle = Unix.opendir path in
    let collected = collect [] handle in
    Unix.closedir handle;
    Ok collected
  with
  | Unix.Unix_error _ -> Error (Format.sprintf "X509 opening dir %s: failed" path)

let extension str =
  let n = String.length str in
  let rec scan = function
    | i when i = 0 -> None
    | i when str.[i - 1] = '.' ->
       Some (String.sub str i (n - i))
    | i -> scan (pred i) in
  scan n

let private_of_pems_buf ~cert ~priv_key =
  let open X509.Encoding.Pem in
  (try Ok (Certificate.of_pem_cstruct cert)
   with Invalid_argument msg -> Error msg)
  >>= fun cert ->
  (try
     (match Private_key.of_pem_cstruct1 priv_key with
      | `RSA key -> Ok key)
   with Invalid_argument msg -> Error msg) >>= fun priv_key ->
  Ok (`Single (cert, priv_key))

let private_of_pems ~cert ~priv_key =
  (match cert with
   | `Buffer cs -> Ok cs
   | `File path -> read_file path) >>= fun cert ->
  (match priv_key with
   | `Buffer cs -> Ok cs
   | `File path -> read_file path) >>= fun priv_key ->
  private_of_pems_buf ~cert ~priv_key

let certs_of_pem path =
  read_file path >>= fun cert_file ->
  try Ok (X509.Encoding.Pem.Certificate.of_pem_cstruct cert_file)
  with Invalid_argument msg -> Error msg

let certs_of_pem_mem cert_buffer =
  try Ok (X509.Encoding.Pem.Certificate.of_pem_cstruct cert_buffer)
  with Invalid_argument msg -> Error msg

let certs_of_pem_dir path =
  read_dir path >>= fun dir ->
  List.filter (fun file -> extension file = Some "crt") dir
  |> List.map (fun file -> certs_of_pem (path </> file))
  |> concat >>= function l -> Ok (List.concat l)

let authenticator param =
  let time = Unix.gettimeofday () in
  let of_cas cas =
    X509.Authenticator.chain_of_trust ~time cas in
  match param with
  | `Ca_file path -> certs_of_pem path >>= fun certs -> Ok (Some (of_cas certs))
  | `Ca_mem path -> certs_of_pem_mem path >>= fun certs -> Ok (Some (of_cas certs))
  | `Ca_dir path -> certs_of_pem_dir path >>= fun certs -> Ok (Some (of_cas certs))
  | `Insecure -> Ok (Some X509.Authenticator.null)
  | `No_auth -> Ok None
