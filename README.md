# ML Project v0.0.1

Machine learning program to detect SSH Bruteforce attempts and Web attacks using packet traffic.

[![linting: flake8](https://img.shields.io/badge/linting-flake8-yellowgreen)](https://flake8.pycqa.org/en/latest/)
[![Newest Release](https://img.shields.io/github/v/release/UH-MountainLions/ML_Proyect_V1.svg)](https://github.com/UH-MountainLions/ML_Proyect_V1/releases)

## Getting Started

To build a development version of this software, refer to the [CONTRIBUTING.md](./CONTRIBUTING.md) file for development 
instructions.

## Folder Structure

```
.
├-- docs/                                   # References for design decision
|   └-- ard/                                # Architectural decision records
├-- src/
|   └-- ml_program/                         # main module for application
|       ├-- resources                       # collection of resources used through program
|       ├-- tests                           # all tests
|       ├-- __init__.py                     # collection of utility functions used through program
|       ├-- __main__.py                     # collection of utility functions used through program
|       └-- utilities.py                    # collection of utility functions used through program
├-- .bumpversion.cfg                        # bumpversion configuration for version incrementation
├-- .gitignore                              # Typical gitignore file
├-- CHANGELOG.md                            # running record (human readable) of version changes
├-- CONTRIBUTING.md                         # Directions and standards for contributing to this application
├-- humans.md                               # Running list of all contributors
├-- LICENSE.md                              # Source of truth for required LICENSE
├-- pyproject.toml                          # Python toml setup configurations
├-- README.md                               # This file
├-- requirements-dev.txt                    # Basic pip requirements file
├-- setup.py                                # simple python setup.py stub for backwards compatability
└-- tox.ini                                 # configuration file for testing via tox
```

## Deployment
TODO

## Built With

* [Python3.10](https://www.python.org/downloads/release/python-3100/)
* [Bump2Version](https://github.com/c4urself/bump2version)
* [scikit-learn](https://scikit-learn.org/)

## Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our code of conduct, installing, developing, and the 
process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the 
[tags on this repository](https://gitlab.com/dunns-valve-testers/report_generator/-/tags). 

## Authors

See the list of [contributors](./humans.md) who participated in this project.

## License

This project uses libraries and software listed in the [Built With](README.md#built-with) section. See the 
[LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc
