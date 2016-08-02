(*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

open Ctypes
open Nqsb
open Rresult
open Tls.Core

let get_epoch ctx =
  match ctx.state with
  | `Active tls ->
    (match Tls.Engine.epoch tls with
    | `Epoch epoch -> Some epoch
    | `InitialEpoch -> None)
  | _ -> None

let get_cert ctx =
  match get_epoch ctx with
  | Some epoch ->
    (match epoch.peer_certificate with
    | Some cert -> Some cert
    | None -> None)
  | None -> None

let some v = Some v

let tls_peer_cert_provided p =
  let ctx = to_voidp p |> Root.get in
  match get_cert ctx with
  | Some cert -> 0
  | None -> -1

let tls_conn_cipher p =
  let ctx = to_voidp p |> Root.get in
  match get_epoch ctx with
  | Some epoch ->
    Tls.Ciphersuite.sexp_of_ciphersuite epoch.ciphersuite
    |> Sexplib.Conv.string_of_sexp |> some
  | None -> None

let tls_conn_version p =
  let ctx = to_voidp p |> Root.get in
  match get_epoch ctx with
  | Some epoch ->
    Tls.Core.sexp_of_tls_version epoch.protocol_version
    |> Sexplib.Conv.string_of_sexp |> some
  | None -> None

let tls_peer_cert_subject p =
  let ctx = to_voidp p |> Root.get in
  match get_cert ctx with
  | Some cert ->
    X509.subject cert |>
    X509.distinguished_name_to_string |> some
  | None -> None

let tls_peer_cert_issuer p =
  let ctx = to_voidp p |> Root.get in
  match get_cert ctx with
  | Some cert ->
    X509.issuer cert |>
    X509.distinguished_name_to_string |> some
  | None -> None

let tls_peer_cert_hash p =
  let ctx = to_voidp p |> Root.get in
  match get_cert ctx with
  | Some cert ->
    let hash = X509.fingerprint `SHA256 cert in
    (match Hex.of_cstruct hash with
    | `Hex hex -> Some ("SHA256:" ^ hex))
  | None -> None

let tls_peer_cert_notbefore p =
  (* FIXME: Strongly invalid. Placeholder implementation *) Unix.time () |> int_of_float

let tls_peer_cert_notafter p =
  (* FIXME: Strongly invalid. Placeholder implementation *) Unix.time () |> int_of_float
