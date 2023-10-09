```C
                              _____            _____                         
                             |  __ \          |  __ \                        
                             | |__) |__ ______| |__) |_ _ _ __ ___  ___ _ __ 
                             |  ___/ _ \______|  ___/ _` | '__/ __|/ _ \ '__|
                             | |  |  __/      | |  | (_| | |  \__ \  __/ |   
                             |_|   \___|      |_|   \__,_|_|  |___/\___|_|   
                                                 
                      Fully written in C++. Retrieve PE infoemations for x86 & x64 files 
                                                         
```

---

## About it 📕

Retrieve interesting informations in a x86 & x64 PE file format. This project was developped due to my interest for Windows internals & learning how to manipulate PE files with C++.

## Features 

🟢 **DOS HEADER informations** 

🟢 **NT HEADER informations**

🟢 **Loaded DLL's + functions**

🟢 **Relocations informations**

🟢 **Sections informations**

---

## Use it 

  1. git clone `https://github.com/Yekuuun/PE-Parser.git`.
  2. open project and run `mkdir build` in `/PE-Parser/Pe-Parser` dir.
  3. go to `/build` and run `cmake ..`.
  4. build project with `cmake --build .`.
  5. go to `/Debug` & run `./parser <path_to_exe_file.exe>`

---

## Greetings

-> **Thanks to <a href="https://github.com/hasherezade">Hasherezade</a> & <a href="https://github.com/arsium">Arsium</a> for code examples & infos**


