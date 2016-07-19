open Ctypes

module C(F: Cstubs.FOREIGN) = struct
  open F

  let malloc = F.foreign "malloc" (size_t @-> returning (ptr void))

end
