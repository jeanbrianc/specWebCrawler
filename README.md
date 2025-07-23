# specWebCrawler

This project contains a simple Python web crawler that visits pages starting
from a given URL and collects information about them.

## Requirements

* Python 3.8+
* `requests`
* `beautifulsoup4`

Install the dependencies using pip:

```bash
pip install -r requirements.txt
```

## Usage

Run the crawler from the command line:

```bash
python crawler.py <start-url> --max-depth 2 \
    --domains example.com,example.org \
    --blacklist .jpg,.css
```

### Options

* `--max-depth`: Maximum depth of links to follow (default: 1).
* `--domains`: Comma separated list of allowed domains. If omitted, all domains
  are crawled.
* `--blacklist`: Comma separated list of file extensions to ignore.
* `--blacklist-file`: Path to a file containing extensions to ignore.
* `--user-agent`: Custom User-Agent header for requests.
* `--save-json`: Write crawl results to a JSON file.
* `--save-html-dir`: Directory to save downloaded HTML pages.

The crawler also detects login forms and reports pages missing common security headers.

The crawler outputs each visited URL with its HTTP status code, content size and
page title. At the end it prints summary statistics.
