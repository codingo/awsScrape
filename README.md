AWSScrape is a tool designed to scrape SSL certificates from all AWS IP ranges, searching for specific keywords in the certificates' Common Name (CN), Organization (O), and Organizational Unit (OU) fields.

## Installation

1. Clone this repository:

```
git clone https://github.com/jhaddix/awsscrape.git
cd awsscrape
```

## Usage

Run the script as follows:

```
go run awsscrape.go -keyword=<KEYWORD>  
```

Replace <KEYWORD> with the keyword you want to search for in the SSL certificates.

The script will parse the SSL certificates from the AWS IP ranges and display any matching your KEYWORD with the IP addresses of the matching certificates.

Please note that iterating through all AWS IP addresses and checking SSL certificates WILL take a long time to complete.
