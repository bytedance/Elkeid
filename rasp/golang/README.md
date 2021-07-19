<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">go-probe</h3>

  <p align="center">
    Golang runtime application self-protection.
    <br />
    <br />
    <a href="sample">View Demo</a>
    ·
    <a href="https://github.com/bytedance/Elkeid/issues">Report Bug</a>
    ·
    <a href="https://github.com/bytedance/Elkeid/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Resolve golang symbol table from ```gopclntab``` section, then inline hook api, transfer api call arguments/stacktrace by unix socket, support golang 1.2 and above.

### Built With

* [GCC](https://gcc.gnu.org)
* [Make](https://www.gnu.org/software/make)
* [CMake](https://cmake.org)



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* CMake
  ```sh
  curl https://github.com/Kitware/CMake/releases/download/v3.21.0/cmake-3.21.0-linux-x86_64.sh | sh
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/bytedance/Elkeid.git
   ```
2. Update submodule
   ```sh
   git submodule update --init --recursive
   ```
3. Build
   ```sh
   mkdir -p build && cd build && cmake .. && make
   ```



<!-- USAGE EXAMPLES -->
## Usage

Start server:
```shell
# Each message is be composed of a 4-byte length header, and a json string.
socat UNIX-LISTEN:"/var/run/smith_agent.sock" -
```

Loader mode:
```sh
./go_loader go-program
```

Attach mode by using [pangolin](https://github.com/Hackerl/pangolin):
```
./pangolin -c $(pwd)/go_probe -p $(pidof go-program)
```



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/bytedance/Elkeid/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the Apache-2.0 License.



<!-- CONTACT -->
## Contact

Bytedance - [@bytedance](https://github.com/bytedance)

Project Link: [https://github.com/bytedance/Elkeid](https://github.com/bytedance/Elkeid)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [zydis](https://github.com/zyantific/zydis)
* [libevent](https://github.com/libevent/libevent)