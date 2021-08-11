# RUSTENGINE

## Table of Contents 
- [RUSTENGINE](#rustengine)
  - [Table of Contents](#table-of-contents)
  - [About RUSTENGINE](#about-rustengine)
  - [Inspiration with Rust](#inspiration-with-rust)
  - [Features](#features)
  - [Compares with Nginx](#compares-with-nginx)
  - [Build & Run](#build--run)
  - [About this Repository (RUSTENGINE-http-modules)](#about-this-repository-rustengine-http-modules)
  - [Contact Us](#contact-us)

## About RUSTENGINE
RUSTENGINE = "Rust" + "Nginx" with ❤

RUSTENGINE has the exactly same performance as Nginx and higher software security.

## Inspiration with Rust
Rust is designed for high performance and safety, especially emphasized on memory-safety and thread-safety, also helps developer eliminate many classes of bugs at compile-time. 

According to these properties and potentials, we consider that porting software with Rust can be higher reliability and security than C language software.

## Features

TBD

## Compares with Nginx
### In a Nutshell
|Features                  |Nginx<br>(Open Source)|RUSTENGINE-OSS|RUSTENGINE-Freeware|RUSTENGINE-Cloud|RUSTENGINE-Enterprise
|:-------------------------|:--------------------:|:------------:|:-----------------:|:--------------:|:-------------------:
|100% compatible with Nginx|✅                     |✅            |✅                |✅              |✅
|Support Sandbox           |❌                    |❌           |❌                 |❌             |TODO
|Cloud Native              |❌                    |❌           |❌                 |TODO            |TODO

### Ported Modules (Minimum Viable Compiled)
**Notice** : This repository only conclude minimum viable compiled version of HTTP Module, [more detail](#about-this-repository-rustengine-http-modules)
|HTTP Module (src/http/modules)|Nginx<br>(Open Source)|RUSTENGINE-OSS|RUSTENGINE-Freeware|RUSTENGINE-Cloud|RUSTENGINE-Enterprise
|:-----------------------------|:--------------------:|:------------:|:-----------------:|:--------------:|:-------------------:
|Static                        |✅️                     |✅             |✅                 |✅               |✅
|Index                         |✅                     |✅             |✅                 |✅               |✅
|Log                           |✅                     |✅             |✅                 |✅               |✅
|Chunked Filter                |✅                     |✅             |✅                 |✅               |✅
|Headers Filter                |✅                     |✅             |✅                 |✅               |✅
|Range Filter                  |✅                     |✅             |✅                 |✅               |✅
|Not Modified Filter           |✅                     |✅             |✅                 |✅               |✅
|Try Files                     |✅                     |✅             |✅                 |✅               |✅

### Ported Modules (Extra)
|HTTP Module (src/http/modules)|Nginx<br>(Open Source)|RUSTENGINE-OSS|RUSTENGINE-Freeware|RUSTENGINE-Cloud|RUSTENGINE-Enterprise
|:-----------------------------|:--------------------:|:------------:|:-----------------:|:--------------:|:-------------------:
|Rewrite                       |✅                     |❌            |✅                 |✅               |✅
|Proxy                         |✅                     |❌            |❌                |TODO            |❌
|SSL                           |✅                     |❌            |❌                |TODO            |TODO
|Upstream Keepalive            |✅                     |❌            |❌                |TODO            |❌
|Fast CGI(PHP)                 |✅                     |❌            |TODO               |❌             |TODO
|WSGI (Python)                 |✅                     |              |                   |                |

### 🌶Special Sauce🌶
|                              |Nginx<br>(Open Source)|RUSTENGINE-OSS|RUSTENGINE-Freeware|RUSTENGINE-Cloud|RUSTENGINE-Enterprise
|:-----------------------------|:--------------------:|:------------:|:-----------------:|:--------------:|:-------------------:
|ASGI (Python)                 |❌                   |              |                   |                |
|FastLog                       |❌                   |❌            |TODO               |❌             |❌
|EarlyLog                      |❌                   |❌            |TODO               |❌             |❌
|Sandbox                       |❌                   |❌            |❌                 |❌             |TODO
|Cloud Native - GCP Support    |❌                   |❌            |❌                 |TODO           |TODO

## Build & Run

TBC

## About this Repository ([RUSTENGINE-http-modules](https://github.com/Funny-Systems-OSS/RUSTENGINE-http-modules))

Based on [Nginx-1.18](https://github.com/nginx/nginx/tree/branches/stable-1.18) 

This repository only conclude minimum viable compiled version of HTTP Module. ([/src/http/modules/](https://github.com/nginx/nginx/tree/branches/stable-1.18/src/http/modules))

## Contact Us
Mail us to [RUSTENGINE@funny.systems](mailto:RUSTENGINE@funny.systems)

