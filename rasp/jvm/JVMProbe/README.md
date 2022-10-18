<!-- PROJECT LOGO -->
<p align="center">
  <h3 align="center">JVMProbe</h3>

  <p align="center">
    JVM runtime application self-protection.
    <br />
    <br />
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

Modify class bytecode by using [ASM](https://asm.ow2.io), transfer api call arguments/stacktrace by unix socket.

### Built With

* [OpenJDK](https://openjdk.java.net)
* [Gradle](https://gradle.org)



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* OpenJDK
  ```sh
  wget https://download.java.net/openjdk/jdk11/ri/openjdk-11+28_linux-x64_bin.tar.gz
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/bytedance/Elkeid.git
   ```
2. Build
   ```sh
   mkdir -p output && ./gradlew proguard && cp build/libs/JVMProbe-1.0-SNAPSHOT-pro.jar output/SmithAgent.jar
   ```



<!-- USAGE EXAMPLES -->
## Usage

Start server:
```sh
# each message is be composed of a 4-byte length header, and a json string.
socat UNIX-LISTEN:"/var/run/smith_agent.sock" -
```

Loader mode:
```sh
java -javaagent:SmithAgent.jar -jar application.jar
```

Attach mode by using [jattach](https://github.com/apangin/jattach):
```sh
jattach $(pidof java) load instrument false SmithAgent.jar
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
* [ASM](https://asm.ow2.io)
* [snakeyaml](https://github.com/asomov/snakeyaml)
* [jackson](https://github.com/FasterXML/jackson)
* [commons-lang](https://commons.apache.org/proper/commons-lang)
* [netty](https://netty.io)
* [Disruptor](https://github.com/LMAX-Exchange/disruptor)
* [Javassist](https://www.javassist.org)