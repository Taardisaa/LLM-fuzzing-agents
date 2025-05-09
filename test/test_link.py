error_msg = """
[ 87%] Building C object md2html/CMakeFiles/md2html.dir/md2html.c.o
[100%] Linking C executable md2html
[100%] Built target md2html
+ clang -O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -c ../test/fuzzers/fuzz-mdhtml.c -I../src
+ clang++ -O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -stdlib=libc++ -fsanitize=fuzzer fuzz-mdhtml.o -o /out/fuzz-mdhtml ./src/libmd4c-html.a ./src/libmd4c.a
/usr/bin/ld: /usr/bin/ld: DWARF error: invalid or unhandled FORM value: 0x25
fuzz-mdhtml.o: in function `LLVMFuzzerTestOneInput':
fuzz-mdhtml.c:(.text.LLVMFuzzerTestOneInput[LLVMFuzzerTestOneInput]+0x5a): undefined reference to `process_file'
clang++: error: linker command failed with exit code 1 (use -v to see invocation)
ERROR:__main__:Building fuzzers failed.
run_fuzzer cmd:['-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64', '-e', 'PROJECT_NAME=md4c_md_html_ztmhslyabsdqdoea', '-e', 'HELPER=True', '-e', 'FUZZING_LANGUAGE=c', '-v', '/home/yk/code/oss-fuzz/build/out/md4c_md_html_ztmhslyabsdqdoea/:/out', '-v', '/home/yk/code/oss-fuzz/build/work/md4c_md_html_ztmhslyabsdqdoea:/work', '-t', 'gcr.io/oss-fuzz/md4c_md_html_ztmhslyabsdqdoea']
"""
import re
# pattern = r"(\w+\.(?:c|o)):.*undefined reference to `([^']+)'"
pattern = r"([\w\-]+\.(?:c|o)):.*undefined reference to `([^']+)'"

matches = re.findall(pattern, error_msg)

harness_file_name = "fuzz-mdhtml.c"
# Print the results
for file_name, function_name in matches:
    # print(f"Error in file {file_name} for function {function_name}")
    if file_name.strip() != harness_file_name.strip():
        print(True)

# print(False)