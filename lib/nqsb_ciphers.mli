val ocaml_tls_of_openssl_ciphers : string -> Tls.Ciphersuite.ciphersuite

val cipherlist_of_cipherstring : string -> (Tls.Ciphersuite.ciphersuite list, string) Rresult.result
