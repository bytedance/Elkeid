<!-- PROJECT LOGO -->
<p align="center">
  <h3 align="center">node-probe</h3>

  <p align="center">
    Node.js runtime application self-protection.
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
    <li><a href="#about-the-project">About The Project</a></li>
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

Hook node.js runtime, transfer api call arguments/stacktrace by unix socket.



<!-- USAGE EXAMPLES -->
## Usage

Start server:
```sh
# each message is be composed of a 4-byte length header, and a json string.
socat UNIX-LISTEN:"/var/run/smith_agent.sock" -
```

Loader mode:
```sh
node -r smith.js app.js
```

Attach mode by using [node-inspector](https://github.com/node-inspector/node-inspector):
```sh
node injector.js $(pidof node) "require('./smith')"
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
* [node-inspector](https://github.com/node-inspector/node-inspector)