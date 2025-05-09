#!/usr/bin/env python3
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Does bad_build_check on all fuzz targets in $OUT."""

import contextlib
import multiprocessing
import os
import re
import subprocess
import stat
import sys
import tempfile

BASE_TMP_FUZZER_DIR = '/tmp/not-out'

EXECUTABLE = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH

IGNORED_TARGETS = [
    r'do_stuff_fuzzer', r'checksum_fuzzer', r'fuzz_dump', r'fuzz_keyring',
    r'xmltest', r'fuzz_compression_sas_rle', r'ares_*_fuzzer'
]

IGNORED_TARGETS_RE = re.compile('^' + r'$|^'.join(IGNORED_TARGETS) + '$')



def find_fuzz_targets(directory):
  """Returns paths to fuzz targets in |directory|."""
  # TODO(https://github.com/google/oss-fuzz/issues/4585): Use libClusterFuzz for
  # this.
  print('Finding fuzz targets in %s' % directory)
  fuzz_targets = []
  for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    if filename == 'llvm-symbolizer':
      continue
    if filename.startswith('afl-'):
      continue
    if filename.startswith('jazzer_'):
      continue
    if not os.path.isfile(path):
      continue
    if not os.stat(path).st_mode & EXECUTABLE:
      continue
    # Fuzz targets can either be ELF binaries or shell scripts (e.g. wrapper
    # scripts for Python and JVM targets or rules_fuzzing builds with runfiles
    # trees).

    if os.getenv('FUZZING_ENGINE') not in {'none', 'wycheproof'}:
      with open(path, 'rb') as file_handle:
        binary_contents = file_handle.read()
        if b'LLVMFuzzerTestOneInput' not in binary_contents:
          continue
    fuzz_targets.append(path)


  return fuzz_targets


if __name__ == '__main__':
    fuzz_targets = find_fuzz_targets("/home/yk/code/java_test_cases_apr7/httpcomponents-client-xx/fuzz_tooling/build/out/httpcomponents-client")
    print('Found fuzz target:',fuzz_targets)