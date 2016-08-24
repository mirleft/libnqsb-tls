open Nqsb
open Tls
open Rresult

let ocaml_tls_of_openssl_ciphers = function
  | "DHE-RSA-AES256-SHA256"     -> `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | "DHE-RSA-AES128-SHA256"     -> `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | "DHE-RSA-AES256-SHA"        -> `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | "DHE-RSA-AES128-SHA"        -> `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | "DHE-RSA-DES-CBC3-SHA"      -> `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | "AES256-SHA256"             -> `TLS_RSA_WITH_AES_256_CBC_SHA256
  | "AES128-SHA256"             -> `TLS_RSA_WITH_AES_128_CBC_SHA256
  | "AES256-SHA"                -> `TLS_RSA_WITH_AES_256_CBC_SHA
  | "AES128-SHA"                -> `TLS_RSA_WITH_AES_128_CBC_SHA
  | "DES-CBC3-SHA"              -> `TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | "RC4-SHA"                   -> `TLS_RSA_WITH_RC4_128_SHA
  | "RC4-MD5"                   -> `TLS_RSA_WITH_RC4_128_MD5
  | "AES128-CCM"                -> `TLS_RSA_WITH_AES_128_CCM
  | "AES256-CCM"                -> `TLS_RSA_WITH_AES_256_CCM
  | "DHE-RSA-AES128-CCM"        -> `TLS_DHE_RSA_WITH_AES_128_CCM
  | "DHE-RSA-AES256-CCM"        -> `TLS_DHE_RSA_WITH_AES_256_CCM
  | "AES128-GCM-SHA256"         -> `TLS_RSA_WITH_AES_128_GCM_SHA256
  | "AES256-GCM-SHA384"         -> `TLS_RSA_WITH_AES_256_GCM_SHA384
  | "DHE-RSA-AES128-GCM-SHA256" -> `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | "DHE-RSA-AES256-GCM-SHA384" -> `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  | _ -> raise (Invalid_argument "invalid ciphersuit")

let rec result_fold_left f acc l =
  acc >>= fun acc ->
  match l with
  | [] -> Ok acc
  | x::xs -> result_fold_left f (f acc x) xs

let cipherlist_of_cipherstring str =
  let aux acc = function
    | "secure"
    | "default" -> Ok (List.append acc Tls.Config.Ciphers.default)
    | "all"
    | "compat"
    | "insecure"
    | "legacy" -> Ok (List.append acc Tls.Config.Ciphers.supported)
    | str ->
      let len = String.length str in
      if len == 0 then
        Error "Wrong ciphersuit"
      else
        let head = String.get str 0 in
        let remove, actual_ciphersuite =
          match head with
          | '!'
          | '-' ->
            true, String.sub str 1 len
          | '+' ->
            false, String.sub str 1 len
          | _ ->
            false, str in
        try
          let ocaml_tls_ciphersuite = ocaml_tls_of_openssl_ciphers str in
          if remove then
            Ok (List.filter ((=) ocaml_tls_ciphersuite) acc)
          else
            Ok (ocaml_tls_ciphersuite::acc)
        with
        | Invalid_argument msg -> Error msg in
  let list = Str.split (Str.regexp ":") str in
  result_fold_left aux (Ok []) list
