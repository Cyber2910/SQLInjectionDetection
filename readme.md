# SQLI Vulnerability Detection Tool

It is a tool that detects if the user-fed URL is vulnerable to SQL injection or not. Further, it exploits the possible SQL injections and affected databases using third party library called SQLMap.

## Getting Started

Following these instructions will help you get a copy of the project up and running on your local machine for testing purposes. 

## Prerequisites

Install python 3 with beautiful soup

```
apt-get install python3-dev python3-pip pip3 install bs4 psutil lxml
```

Install SQLMap

```
apt-get install sqlmap
```

## Setup Enviornment

*Set a virtual environment for python 3*


## Running the tests

Activate the virtual environment and run sqli.py with python 3
```
user$ python 3 $PATH/to/sqli.py
```

When asked for url input, provide a url with Get parameters
```
http://www.vulnerableurl.php?id=1
```


## Author

* **Astha Sharma** - *asharma6@uno.edu* 



## Acknowledgments

Thanks to Professor Dr. Minhaz Zibran for his help and support in finding the project base