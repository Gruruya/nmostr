## Private code utility - for nmostr.
# Copyright © 2023 Gruruya <gruruya.chi4c@slmails.com>
# SPDX-License-Identifier: AGPL-3.0-only

func toArray*[T](N: static int, data: openArray[T]): array[N, T] =
  ## Convert ``data`` to an array of N length, ``data`` must be `N` long or longer.
  assert data.len >= N
  copyMem(addr result[0], addr data[0], N)

template toArray*[T](N: static int, data: array[N, T]): auto =
  ## Returns the array ``data``, this exists to allow for generic procs using `toArray`
  ## which were given the correctly sized array to just use that array.
  data
