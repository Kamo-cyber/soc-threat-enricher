#  Project 2: Automated Forensic Log Parser & Threat Intel Enricher

##  Project Overview

The goal of this project is to build a fast, memory-safe Python tool that scans through raw endpoint command logs, extracts hidden malware indicators (MD5 and SHA-256 hashes) using regular expressions, and automatically checks their reputation using the live VirusTotal API. This eliminates the tedious manual lookups that usually slow down incident response.

---

##  Core Technical Features

* **Memory-Efficient Streaming:** Processes massive log files line-by-line using context managers to keep the RAM footprint close to zero.
* **Strict Token Extraction:** Uses the native `re` module with word boundaries (`\b`) to cleanly isolate 32-character (MD5) and 64-character (SHA-256) hex strings without picking up random text noise.
* **Instant Deduplication:** Feeds raw extractions directly into Python sets (`set()`) to immediately filter out duplicate hashes and save memory.
* **Automated API Enrichment:** Uses the `requests` library to handle HTTP `GET` requests, automatically pulling live threat reputation metrics.
* **Structured Data Export:** Saves all enriched threat intelligence records into a structured layout (`data/enriched_threats.csv`) with cross-platform newline protection.

---

##  Background Research & Context

Before writing any code, I looked into actual security operations data to make sure this project solved real-world production bottlenecks rather than theoretical exercises:
* **The Log Deluge:** Large enterprise networks generate massive amounts of log data. A standard Security Operations Center (SOC) faces upwards of **11,000+ alerts daily**, leading to severe analyst burnout.
* **The Manual Task Strain:** Industry research shows that **78% of tier-1 analysts spend 10+ minutes triaging a single alert manually**. This delay is mostly caused by "swivel-chair forensics"—constantly switching screens to copy and paste hashes into external search engines.
* **The Enrichment Void:** Raw log parameters don't mean much on their own. Automating API lookups adds immediate behavioral context directly into the investigation pipeline, massively reducing the time to detection.

---

##  Architecture Upgrades (Moving Beyond Project 1)

This project represents a big step forward in my software engineering practices. After finishing Project 1, I reviewed my code layout against professional development standards and implemented three major upgrades:

### 1. Shifting to Modular Architecture

* **The Old Way:** The logic was built inside a single global scope, leading to deeply nested code that was rigid and hard to read.
* **The Upgrade:** Split the engine into independent functions (`extract_indicators`, `enrich_threat_data`, `export_threat_csv`) with clean inputs and return paths, all managed cleanly under an `if __name__ == "__main__":` execution block.

### 2. Isolated Error Handling

* **The Old Way:** Wrapped a massive chunk of code inside a generic `try-except` block, which masked runtime bugs and made debugging a nightmare.
* **The Upgrade:** Isolated error handling directly to the highest-risk threshold—the outbound API request. If the internet drops or the script hits an API rate limit, the program catches the specific error gracefully and skips to the next token instead of crashing the entire script.

### 3. Tightening Variable Scope

* **The Old Way:** Relied too heavily on global arrays, which risked carrying contaminated states across different sections of the script.
* **The Upgrade:** Designed a strict data pipeline where variables flow exclusively as arguments through function scopes, keeping data completely isolated.

---

##  Development Challenges & Breakthroughs

Stepping into a cleaner software architecture introduced some tough implementation challenges, but it forced me to develop much better diagnostic and problem-solving skills:

### 1. De-bugging Regex Triggers (Trusting the Logic)

* **The Challenge:** During testing, the script kept returning three unique hashes instead of the two I expected. I spent a while assuming my regex pattern was broken and splitting a 64-character SHA-256 hash in half.
* **The Breakthrough:** Instead of guessing, I manually audited the 88-line test log file. It turned out the logic was completely right—the regex wasn't splitting anything. The third hash was a real, standalone MD5 hash sitting further down on line 83. The script was actually working flawlessly.

### 2. Working with Network Protocols (Learning the VirusTotal API)

* **The Challenge:** I had never handled network protocols, HTTP methods, or remote JSON parsing before this project.
* **The Breakthrough:** While researching automation strategies, I learned how to use the **VirusTotal API**. I figured out how to pass custom authentication headers (`x-apikey`), interact with the network card, and drill down into deep JSON structures to extract the actual malware engine votes.

### 3. Resolving Data Field Mismatches

* **The Challenge:** My final CSV export kept throwing formatting errors because the fields in my header array didn't match the dictionary keys coming out of the data loop.
* **The Breakthrough:** I ran a naming audit across the pipeline functions and aligned the internal dictionary keys (`target_hash`, `hash_type`, `malicious_score`) directly with the `csv.DictWriter` parameters. This unjammed the stream and generated a perfectly formatted spreadsheet.
