open Ctypes

let _ =
  let root = Sys.argv.(1) in
  let fmt = Format.formatter_of_out_channel (open_out (root ^ "/malloc_stubs.c")) in
  Cstubs.write_c fmt ~prefix:"caml_" (module Malloc_binding.C);

  let fmt = Format.formatter_of_out_channel (open_out (root ^ "/malloc_generated.ml")) in
  Cstubs.write_ml fmt ~prefix:"caml_" (module Malloc_binding.C)
