/*
 * Copyright (c) 2016 Enguerrand Decorne
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 */

#include <caml/callback.h>

__attribute__ ((__constructor__))
void
init(void)
{
  char *caml_argv[1] = { NULL };
  caml_startup(caml_argv);
}
