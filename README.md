
# Submodules
```
git submodule update --init --recursive
```

# Compiling

Create a directory to run the build in. I create a build/ directory inside the openfhe-development project; or just do it from lib/ but you will need to change the path passed to cmake

## cmake

On macOS:
```bash
cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 ..
cmake ..
```

## make

```bash
make testall
```

## Copy build artifacts locally

Copy all the .dylib files

```bash
mv lib/ ../../
```

# Clean the build directory
```bash
cmake --build . --target clean
```
Or just delete it. `rm -rf build/`

