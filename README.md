# Parameter Files for *The Legend of Zelda: Tears of the Kingdom*

Disclaimer: this repository does not and will not contain any game assets such as models, textures, sounds, animations, etc nor does it contain the files necessary to play the game. Only parameter files are included.

This repository contains parameter files from version 1.2.1 of *The Legend of Zelda: Tears of the Kingdom*.

The `/data` directory contains data files not from the game's romfs (these are generated and provided as a supplemental resource).

The `/ghidra` directory contains the scripts used to generate the files in `/data` (for use in Ghidra).

The `/totk` directory contains the parameter files converted into a human-readable format.

## Subdirectories and Path Handling Overview

*Tears of the Kingdom* contains many archives of files which have been unpacked for ease of viewing. Notably, the `/Pack` and `/Pack/Actor` subdirectories are composed entirely of unpacked archives.

In many cases, parameter files may reference other files and the paths used can sometimes be difficult to decipher. Should the path begin with `Work/` or `?`, that indicates the path must be adjusted before loading the corresponding resource. This adjustment usually just involves removing said prefix and changing the extension to match. Additionally, the path can be relative to the root romfs directory, relative to the local archive, or relative to either the ResidentCommon or Bootup archives.

## TypedParam

Nintendo employs a library called `pp` for handling parameter files. Any file with the extension `.bgyml` is handled by `pp`. At runtime, these files are converted into parameter classes deriving from the base `TypedParam` class. A key feature of `TypedParam` classes is the idea of parent files and default values. This can save on memory by avoiding the requirement of storing the value for every single value in a `TypedParam` class and instead only storing the modified values. Parent files also allow commonly shared sets of values to be combined into a single file instead of being copied into every single file that uses them.

Every parameter in a `TypedParam` is one of three types: prop (short for property), embed, or composite. A prop is a simple key-value mapping. An embed is key-`TypedParam` mapping (i.e. a `TypedParam` that is embedded inside another). A composite is an array or map type which maps a key to either an array or map of values (Technically, embeds also fall under composites, but it's easier to treat them separately). There are six possible types of composites: `PropBuffer`, `PropMap`, `PropEnumMap`, `TypedParamBuffer`, `TypedParamMap`, and `TypedParamEnumMap`. The buffer types are arrays while the map types are maps. The enum version of the maps are the same as standard maps except that the keys of the map are the values of a specific enum. Embedded `TypedParam` classes and any `TypedParam` inside a composite can also be of any derived type of the original `TypedParam` class. If this is the case, the derived class' name is specified via the `$type` field. 

### Parent Resolution

If any value is not present in a `TypedParam` or its parent, then it falls back to the default value

(see `/data/pp__TypedParams.121.json` for relevant info)

Props:
  - If a prop in a `TypedParam` is not present, its value is the value of the same prop in the parent file
  - Otherwise, use the value that is present

Embeds:
  - If an embed in a `TypedParam` is not present, its value is the value of the same embed in the parent file
  - Otherwise, resolve the embed against its parent (if specified)

Composite:
  - If a composite in a `TypedParam` is not present, its value is the value of the same composite in the parent file - if there is no parent file, use the default composite value
  - Otherwise:
    - `PropBuffer`: if the resolve type is zero, ignore the value of the composite in the parent, otherwise, append the composite value from the current file to the end of the composite value from the parent file
    - `PropMap`/`PropEnumMap`: if the resolve type is zero, ignore the value of the composite in the parent, otherwise, merge with the composite value from the parent file (in the case of identical keys, choose the value from the current file)
    - `TypedParamBuffer`: resolve each `TypedParam` against its parent if specified then if the resolve type is one, append the composite value from the current file to the end of the composite value from the parent file
    - `TypedParamMap`/`TypedParamEnumMap`: if the resolve type is two, resolve each `TypedParam` against the `TypedParam` with the same key in the parent file, otherwise resolve each `TypedParam` against its parent (if specified), then, if the resolve type is not zero, merge with the composite value from the parent file (in the case of identical keys, chose the value from the current file)