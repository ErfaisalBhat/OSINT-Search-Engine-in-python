#!/usr/bin/env python3
"""
Advanced OSINT Search Engine
A comprehensive Open Source Intelligence gathering tool with multiple data sources
"""

import csv
import json
import os
import re
import time
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
import socket
import subprocess
import concurrent.futures

# Try to import optional dependencies
try:
    import shodan
except ImportError:
    shodan = None

try:
    from social_media_scraper import SocialMediaScraper
except ImportError:
    SocialMediaScraper = None

# Configuration
CONFIG = {
    "timeout": 30,
    "max_results": 20,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "max_threads": 5,
}


@dataclass
class SearchResult:
    """Data class for search results"""
    title: str
    url: str
    snippet: str
    source: str
    timestamp: str
    metadata: Optional[Dict] = None


class OSINTSearchEngine:
    def __init__(self):
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': CONFIG['user_agent']})
        self.api_keys = self.load_api_keys()

    def load_api_keys(self) -> Dict:
        """Load API keys from environment variables or config file"""
        keys = {}
        # Try to load from environment variables
        potential_keys = ['SHODAN_API_KEY', 'VIRUSTOTAL_API_KEY', 'HIBP_API_KEY',
                          'GOOGLE_API_KEY', 'GOOGLE_CSE_ID']

        for key in potential_keys:
            value = os.environ.get(key)
            if value:
                keys[key] = value

        # Try to load from config file
        config_path = os.path.expanduser('~/.osint_config.json')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    keys.update(file_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")

        return keys

    def search_google(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search using Google (requires API key)"""
        results = []

        if not self.api_keys.get('GOOGLE_API_KEY') or not self.api_keys.get('GOOGLE_CSE_ID'):
            print("Google search requires GOOGLE_API_KEY and GOOGLE_CSE_ID environment variables")
            return results

        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                'key': self.api_keys['GOOGLE_API_KEY'],
                'cx': self.api_keys['GOOGLE_CSE_ID'],
                'q': query,
                'num': min(max_results, 10)  # Google limits to 10 results per page
            }

            response = self.session.get(url, params=params, timeout=CONFIG['timeout'])
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    results.append(SearchResult(
                        title=item.get('title', ''),
                        url=item.get('link', ''),
                        snippet=item.get('snippet', ''),
                        source='Google',
                        timestamp=datetime.now().isoformat(),
                        metadata={'displayLink': item.get('displayLink')}
                    ))
        except Exception as e:
            print(f"Error searching Google: {e}")

        return results

    def search_bing(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search using Bing (web scraping approach)"""
        results = []
        try:
            url = f"https://www.bing.com/search?q={quote(query)}"
            response = self.session.get(url, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for result in soup.select('.b_algo')[:max_results]:
                    title_elem = result.select_one('h2')
                    link_elem = result.select_one('a')
                    desc_elem = result.select_one('.b_caption p')

                    if title_elem and link_elem:
                        results.append(SearchResult(
                            title=title_elem.get_text(),
                            url=link_elem.get('href', ''),
                            snippet=desc_elem.get_text() if desc_elem else '',
                            source='Bing',
                            timestamp=datetime.now().isoformat()
                        ))
        except Exception as e:
            print(f"Error searching Bing: {e}")

        return results

    def search_duckduckgo(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search using DuckDuckGo"""
        results = []
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            headers = {
                'User-Agent': CONFIG['user_agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }

            response = self.session.get(url, headers=headers, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for result in soup.select('.result')[:max_results]:
                    title_elem = result.select_one('.result__a')
                    link_elem = title_elem  # Link is in the title element
                    desc_elem = result.select_one('.result__snippet')

                    if title_elem:
                        # DuckDuckGo links are in a special format that needs processing
                        raw_url = title_elem.get('href', '') if title_elem else ''
                        if raw_url.startswith('//duckduckgo.com/l/?uddg='):
                            # Extract the actual URL from the redirect
                            parsed = urlparse(raw_url)
                            query_params = parse_qs(parsed.query)
                            actual_url = query_params.get('uddg', [''])[0]
                        else:
                            actual_url = raw_url

                        results.append(SearchResult(
                            title=title_elem.get_text(),
                            url=actual_url,
                            snippet=desc_elem.get_text() if desc_elem else '',
                            source='DuckDuckGo',
                            timestamp=datetime.now().isoformat()
                        ))
        except Exception as e:
            print(f"Error searching DuckDuckGo: {e}")

        return results

    def search_github(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search GitHub repositories"""
        results = []
        try:
            url = f"https://api.github.com/search/repositories?q={quote(query)}&sort=stars&order=desc"
            response = self.session.get(url, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                data = response.json()
                for repo in data.get('items', [])[:max_results]:
                    results.append(SearchResult(
                        title=f"{repo['full_name']} ⭐{repo['stargazers_count']}",
                        url=repo['html_url'],
                        snippet=repo.get('description', 'No description available'),
                        source='GitHub',
                        timestamp=datetime.now().isoformat(),
                        metadata={
                            'stars': repo['stargazers_count'],
                            'forks': repo['forks_count'],
                            'language': repo.get('language', 'Unknown')
                        }
                    ))
        except Exception as e:
            print(f"Error searching GitHub: {e}")

        return results

    def search_pastebin(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search Pastebin for pastes containing the query"""
        results = []
        try:
            # This is a simplified approach - actual Pastebin search requires proper API or scraping
            url = f"https://pastebin.com/search?q={quote(query)}"
            response = self.session.get(url, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # This selector might need adjustment as Pastebin changes their HTML
                for result in soup.select('.maintable tr')[1:max_results + 1]:  # Skip header row
                    cols = result.select('td')
                    if len(cols) >= 3:
                        title_elem = cols[0].select_one('a')
                        date_elem = cols[1]
                        syntax_elem = cols[2]

                        if title_elem:
                            results.append(SearchResult(
                                title=title_elem.get_text(),
                                url=f"https://pastebin.com{title_elem.get('href', '')}",
                                snippet=f"Posted: {date_elem.get_text()}, Syntax: {syntax_elem.get_text()}",
                                source='Pastebin',
                                timestamp=datetime.now().isoformat()
                            ))
        except Exception as e:
            print(f"Error searching Pastebin: {e}")

        return results

    def search_wayback_machine(self, url: str, max_results: int = 10) -> List[SearchResult]:
        """Search Wayback Machine for archived versions of a URL"""
        results = []
        try:
            api_url = f"https://web.archive.org/cdx/search/cdx?url={quote(url)}&output=json&limit={max_results}"
            response = self.session.get(api_url, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # Skip header row
                    for entry in data[1:max_results + 1]:
                        if len(entry) >= 3:
                            timestamp = entry[1]
                            original_url = entry[2]
                            archived_url = f"https://web.archive.org/web/{timestamp}/{original_url}"

                            results.append(SearchResult(
                                title=f"Archived: {original_url} ({timestamp[:8]})",
                                url=archived_url,
                                snippet=f"Archived version from {timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}",
                                source='Wayback Machine',
                                timestamp=datetime.now().isoformat(),
                                metadata={'original_url': original_url, 'archive_timestamp': timestamp}
                            ))
        except Exception as e:
            print(f"Error searching Wayback Machine: {e}")

        return results

    def search_shodan(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search Shodan for IoT devices and services (requires API key)"""
        results = []

        if not shodan:
            results.append(SearchResult(
                title="Shodan library not installed",
                url="https://pypi.org/project/shodan/",
                snippet="Install with: pip install shodan",
                source='Shodan',
                timestamp=datetime.now().isoformat()
            ))
            return results

        if not self.api_keys.get('SHODAN_API_KEY'):
            results.append(SearchResult(
                title="Shodan API key required",
                url="https://account.shodan.io/",
                snippet="Get an API key from https://account.shodan.io/",
                source='Shodan',
                timestamp=datetime.now().isoformat()
            ))
            return results

        try:
            api = shodan.Shodan(self.api_keys['SHODAN_API_KEY'])
            results_data = api.search(query, limit=max_results)

            for match in results_data['matches']:
                results.append(SearchResult(
                    title=f"{match['ip_str']}:{match.get('port', 'N/A')}",
                    url=f"https://www.shodan.io/host/{match['ip_str']}",
                    snippet=f"Service: {match.get('product', 'Unknown')} - {match.get('data', '')[:100]}...",
                    source='Shodan',
                    timestamp=datetime.now().isoformat(),
                    metadata={
                        'ip': match['ip_str'],
                        'port': match.get('port'),
                        'org': match.get('org', 'Unknown'),
                        'location': match.get('location', {}),
                        'tags': match.get('tags', [])
                    }
                ))
        except Exception as e:
            print(f"Error searching Shodan: {e}")

        return results

    def search_virustotal(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """Search VirusTotal for threat intelligence"""
        results = []

        if not self.api_keys.get('VIRUSTOTAL_API_KEY'):
            results.append(SearchResult(
                title="VirusTotal API key required",
                url="https://www.virustotal.com/gui/join-us",
                snippet="Get an API key from https://www.virustotal.com/gui/join-us",
                source='VirusTotal',
                timestamp=datetime.now().isoformat()
            ))
            return results

        try:
            # Check if query is IP, domain, or hash
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', query):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            elif re.match(r'^[a-fA-F0-9]{32,64}$', query):
                url = f"https://www.virustotal.com/api/v3/files/{query}"
            else:
                # Assume it's a domain
                url = f"https://www.virustotal.com/api/v3/domains/{query}"

            headers = {'x-apikey': self.api_keys['VIRUSTOTAL_API_KEY']}
            response = self.session.get(url, headers=headers, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})

                results.append(SearchResult(
                    title=f"VirusTotal Report for {query}",
                    url=f"https://www.virustotal.com/gui/search/{query}",
                    snippet=f"Last analysis: {attributes.get('last_analysis_date', 'N/A')}",
                    source='VirusTotal',
                    timestamp=datetime.now().isoformat(),
                    metadata={'attributes': attributes}
                ))
            else:
                results.append(SearchResult(
                    title=f"No VirusTotal results for {query}",
                    url=f"https://www.virustotal.com/gui/search/{query}",
                    snippet="No information found in VirusTotal database",
                    source='VirusTotal',
                    timestamp=datetime.now().isoformat()
                ))

        except Exception as e:
            print(f"Error searching VirusTotal: {e}")

        return results

    def search_social_media(self, username: str, max_results: int = 10) -> List[SearchResult]:
        """Search for a username across social media platforms"""
        results = []

        platforms = {
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'GitHub': f'https://github.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Tumblr': f'https://{username}.tumblr.com',
            'YouTube': f'https://youtube.com/user/{username}',
        }

        def check_platform(platform_name, url):
            try:
                response = self.session.head(url, timeout=10, allow_redirects=True)
                if response.status_code < 400:  # Not a 4xx or 5xx error
                    return SearchResult(
                        title=f"{platform_name} profile found",
                        url=url,
                        snippet=f"Potential {platform_name} profile for {username}",
                        source='Social Media Search',
                        timestamp=datetime.now().isoformat()
                    )
            except:
                pass
            return None

        # Use threading to check platforms concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
            future_to_platform = {
                executor.submit(check_platform, platform, url): platform
                for platform, url in platforms.items()
            }

            for future in concurrent.futures.as_completed(future_to_platform):
                result = future.result()
                if result:
                    results.append(result)
                    if len(results) >= max_results:
                        break

        return results

    def domain_analysis(self, domain: str) -> Dict:
        """Comprehensive domain analysis"""
        print(f"🌐 Analyzing domain: {domain}...")
        analysis = {
            'domain': domain,
            'whois': {},
            'dns': {},
            'subdomains': [],
            'technologies': [],
            'social_media': [],
            'security': {}
        }

        try:
            # WHOIS lookup
            print("  Running WHOIS lookup...")
            try:
                whois_info = whois.whois(domain)
                analysis['whois'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date),
                    'name_servers': whois_info.name_servers,
                }
            except Exception as e:
                analysis['whois']['error'] = str(e)

            # DNS records
            print("  Querying DNS records...")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    analysis['dns'][record_type] = [str(r) for r in answers]
                except:
                    analysis['dns'][record_type] = []

            # Common subdomains
            print("  Checking common subdomains...")
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'test']
            for subdomain in common_subdomains:
                try:
                    test_domain = f"{subdomain}.{domain}"
                    socket.gethostbyname(test_domain)
                    analysis['subdomains'].append(test_domain)
                except:
                    pass

            # Security headers
            print("  Checking security headers...")
            try:
                response = self.session.get(f"https://{domain}", timeout=10)
                security_headers = [
                    'Strict-Transport-Security', 'X-Frame-Options',
                    'X-Content-Type-Options', 'Content-Security-Policy'
                ]
                for header in security_headers:
                    if header in response.headers:
                        analysis['security'][header] = response.headers[header]
            except:
                analysis['security']['error'] = "Could not connect to domain"

        except Exception as e:
            analysis['error'] = f"Domain analysis failed: {str(e)}"

        return analysis

    def email_analysis(self, email: str) -> Dict:
        """Comprehensive email analysis"""
        print(f"📧 Analyzing email: {email}...")
        analysis = {
            'email': email,
            'breaches': {},
            'social_media': [],
            'domain_info': {},
            'disposable': False
        }

        # Check if email is from a disposable provider
        disposable_domains = [
            'tempmail', '10minutemail', 'guerrillamail', 'mailinator',
            'throwaway', 'fake', 'trashmail', 'disposable'
        ]
        domain = email.split('@')[1] if '@' in email else ''
        analysis['disposable'] = any(d in domain for d in disposable_domains)

        # Check data breaches
        if self.api_keys.get('HIBP_API_KEY'):
            try:
                headers = {'hibp-api-key': self.api_keys['HIBP_API_KEY']}
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    breaches = response.json()
                    analysis['breaches'] = {
                        'count': len(breaches),
                        'breaches': [b['Name'] for b in breaches]
                    }
            except:
                analysis['breaches']['error'] = "Could not check breaches"

        # Search for social media profiles
        if '@' in email:
            username = email.split('@')[0]
            analysis['social_media'] = self.search_social_media(username, 5)

        return analysis

    def search_multiple_sources(self, query: str, sources: List[str], max_results: int = 10) -> List[SearchResult]:
        """Search across multiple OSINT sources"""
        all_results = []
        source_methods = {
            'google': self.search_google,
            'bing': self.search_bing,
            'duckduckgo': self.search_duckduckgo,
            'github': self.search_github,
            'pastebin': self.search_pastebin,
            'wayback': self.search_wayback_machine,
            'shodan': self.search_shodan,
            'virustotal': self.search_virustotal,
        }

        for source in sources:
            if source in source_methods:
                print(f"🔍 Searching {source.upper()}...")
                try:
                    results = source_methods[source](query, max_results)
                    all_results.extend(results)
                    print(f"  ✅ Found {len(results)} results")
                    time.sleep(1)  # Rate limiting
                except Exception as e:
                    print(f"  ❌ Error searching {source}: {e}")

        return all_results

    def generate_report(self, query: str, results: List[SearchResult], output_file: str = None) -> str:
        """Generate a comprehensive OSINT report"""
        report = f"""
OSINT SEARCH REPORT
==================

Query: {query}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Results: {len(results)}

SUMMARY
-------
"""
        # Group results by source
        by_source = {}
        for result in results:
            if result.source not in by_source:
                by_source[result.source] = []
            by_source[result.source].append(result)

        for source, source_results in by_source.items():
            report += f"\n{source}: {len(source_results)} results"

        report += "\n\nDETAILED RESULTS\n" + "=" * 50 + "\n"

        for i, result in enumerate(results, 1):
            report += f"""
{i}. {result.title}
   Source: {result.source}
   URL: {result.url}
   Description: {result.snippet}
   Found: {result.timestamp}
"""

        # Extract and analyze patterns
        all_text = " ".join([r.snippet for r in results])
        emails = self.extract_emails_from_text(all_text)
        urls = self.extract_urls_from_text(all_text)
        ips = self.extract_ips_from_text(all_text)

        if emails or urls or ips:
            report += "\nEXTRACTED INTELLIGENCE\n" + "=" * 50 + "\n"

            if emails:
                report += f"\nEmail addresses found: {len(emails)}\n"
                for email in set(emails):
                    report += f" - {email}\n"

            if urls:
                report += f"\nURLs found: {len(set(urls))}\n"
                for url in list(set(urls))[:20]:  # Limit to 20 URLs
                    report += f" - {url}\n"

            if ips:
                report += f"\nIP addresses found: {len(set(ips))}\n"
                for ip in set(ips):
                    report += f" - {ip}\n"

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Report saved to {output_file}")

        return report

    def export_csv(self, results: List[SearchResult], filename: str):
        """Export results to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['title', 'url', 'snippet', 'source', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'title': result.title,
                    'url': result.url,
                    'snippet': result.snippet,
                    'source': result.source,
                    'timestamp': result.timestamp
                })
        print(f"📊 Results exported to {filename}")

    def extract_emails_from_text(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text, re.IGNORECASE)

    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def extract_ips_from_text(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)


def display_menu():
    """Display the main menu"""
    print("\n" + "=" * 60)
    print("🔍 ADVANCED OSINT SEARCH ENGINE")
    print("=" * 60)
    print("1. 🌐 General Web Search")
    print("2. 📧 Email Investigation")
    print("3. 🏢 Domain Analysis")
    print("4. 👤 Username Search")
    print("5. 📚 GitHub Repository Search")
    print("6. 🔐 Shodan IoT Search")
    print("7. ⚠️  VirusTotal Threat Check")
    print("8. ⏰ Wayback Machine Search")
    print("9. 📝 Pastebin Search")
    print("10. 🔧 Multi-source Search")
    print("11. 📊 Generate Report")
    print("12. ❌ Exit")
    print("=" * 60)


def get_user_choice():
    """Get user menu choice"""
    while True:
        try:
            choice = int(input("Enter your choice (1-12): "))
            if 1 <= choice <= 12:
                return choice
            else:
                print("❌ Invalid choice. Please enter a number between 1-12.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")


def get_sources_from_user():
    """Get source selection from user"""
    print("\nAvailable sources:")
    print("1. Google")
    print("2. Bing")
    print("3. DuckDuckGo")
    print("4. GitHub")
    print("5. Pastebin")
    print("6. Shodan")
    print("7. VirusTotal")
    print("8. Wayback Machine")

    source_map = {
        '1': 'google',
        '2': 'bing',
        '3': 'duckduckgo',
        '4': 'github',
        '5': 'pastebin',
        '6': 'shodan',
        '7': 'virustotal',
        '8': 'wayback'
    }

    sources = []
    while True:
        selection = input("Enter source numbers (comma-separated, e.g., 1,2,3): ").strip()
        if not selection:
            return ['google', 'bing', 'duckduckgo']  # Default sources

        try:
            selected_nums = [num.strip() for num in selection.split(',')]
            sources = [source_map[num] for num in selected_nums if num in source_map]
            if sources:
                return sources
            else:
                print("❌ No valid sources selected. Please try again.")
        except:
            print("❌ Invalid format. Please use comma-separated numbers (e.g., 1,2,3)")


def display_results(results: List[SearchResult]):
    """Display search results in a formatted way"""
    if not results:
        print("❌ No results found.")
        return

    print(f"\n📊 Found {len(results)} results:")
    print("=" * 80)

    for i, result in enumerate(results, 1):
        print(f"\n{i}. [{result.source}] {result.title}")
        print(f"   🔗 URL: {result.url}")
        print(f"   📝 Description: {result.snippet[:150]}{'...' if len(result.snippet) > 150 else ''}")
        print(f"   ⏰ Found: {result.timestamp}")


def save_results_option(engine: OSINTSearchEngine, query: str, results: List[SearchResult]):
    """Ask user if they want to save results"""
    if not results:
        return

    save = input("\n💾 Save results? (y/n): ").strip().lower()
    if save == 'y':
        print("\nSave options:")
        print("1. Text report")
        print("2. CSV file")
        print("3. Both")

        save_choice = input("Choose option (1-3): ").strip()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_query = "".join(c for c in query if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_query = safe_query[:30]  # Limit filename length

        if save_choice in ['1', '3']:
            filename = f"osint_report_{safe_query}_{timestamp}.txt"
            engine.generate_report(query, results, filename)

        if save_choice in ['2', '3']:
            filename = f"osint_results_{safe_query}_{timestamp}.csv"
            engine.export_csv(results, filename)

        print("✅ Results saved successfully!")


def main_interactive():
    """Main interactive function"""
    print("🚀 Starting Advanced OSINT Search Engine...")
    print("💡 Tip: Set API keys as environment variables for full functionality")
    print("   (SHODAN_API_KEY, VIRUSTOTAL_API_KEY, HIBP_API_KEY, GOOGLE_API_KEY, GOOGLE_CSE_ID)")

    engine = OSINTSearchEngine()

    while True:
        display_menu()
        choice = get_user_choice()

        if choice == 12:
            print("👋 Thank you for using OSINT Search Engine!")
            break

        elif choice == 1:
            # General Web Search
            query = input("\n🔍 Enter search query: ").strip()
            if query:
                max_results = int(input("Max results per source (default 10): ") or 10)
                print(f"\n🔍 Searching for: {query}")
                results = engine.search_duckduckgo(query, max_results)
                results.extend(engine.search_bing(query, max_results))
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 2:
            # Email Investigation
            email = input("\n📧 Enter email address: ").strip()
            if email and '@' in email:
                print(f"\n🔍 Investigating email: {email}")
                analysis = engine.email_analysis(email)
                print(f"\n📊 Email Analysis Results:")
                print(json.dumps(analysis, indent=2))

                # Also search for the email
                search_email = input(f"\nSearch for information about {email}? (y/n): ").strip().lower()
                if search_email == 'y':
                    results = engine.search_multiple_sources(
                        email, ['google', 'bing', 'duckduckgo', 'pastebin'], 5
                    )
                    display_results(results)
                    save_results_option(engine, email, results)
            else:
                print("❌ Invalid email address!")

        elif choice == 3:
            # Domain Analysis
            domain = input("\n🌐 Enter domain (e.g., example.com): ").strip()
            if domain:
                analysis = engine.domain_analysis(domain)
                print(f"\n📊 Domain Analysis Results:")
                print(json.dumps(analysis, indent=2))

                # Also search for the domain
                search_domain = input(f"\nSearch for information about {domain}? (y/n): ").strip().lower()
                if search_domain == 'y':
                    results = engine.search_multiple_sources(
                        domain, ['google', 'bing', 'duckduckgo', 'virustotal'], 10
                    )
                    display_results(results)
                    save_results_option(engine, domain, results)

        elif choice == 4:
            # Username Search
            username = input("\n👤 Enter username: ").strip()
            if username:
                print(f"\n🔍 Searching for username: {username}")
                results = engine.search_social_media(username, 10)
                results.extend(engine.search_github(username, 5))
                display_results(results)
                save_results_option(engine, username, results)

        elif choice == 5:
            # GitHub Search
            query = input("\n💻 Enter GitHub search query: ").strip()
            if query:
                max_results = int(input("Max results (default 10): ") or 10)
                print(f"\n🔍 Searching GitHub for: {query}")
                results = engine.search_github(query, max_results)
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 6:
            # Shodan Search
            query = input("\n🔐 Enter Shodan search query: ").strip()
            if query:
                max_results = int(input("Max results (default 10): ") or 10)
                print(f"\n🔍 Searching Shodan for: {query}")
                results = engine.search_shodan(query, max_results)
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 7:
            # VirusTotal Search
            query = input("\n⚠️  Enter IP, domain, or hash to check: ").strip()
            if query:
                print(f"\n🔍 Checking VirusTotal for: {query}")
                results = engine.search_virustotal(query, 5)
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 8:
            # Wayback Machine
            url = input("\n⏰ Enter URL to search in Wayback Machine: ").strip()
            if url:
                max_results = int(input("Max archived versions (default 10): ") or 10)
                print(f"\n🔍 Searching Wayback Machine for: {url}")
                results = engine.search_wayback_machine(url, max_results)
                display_results(results)
                save_results_option(engine, url, results)

        elif choice == 9:
            # Pastebin Search
            query = input("\n📝 Enter Pastebin search query: ").strip()
            if query:
                max_results = int(input("Max results (default 10): ") or 10)
                print(f"\n🔍 Searching Pastebin for: {query}")
                results = engine.search_pastebin(query, max_results)
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 10:
            # Multi-source Search
            query = input("\n🔍 Enter search query: ").strip()
            if query:
                sources = get_sources_from_user()
                max_results = int(input("Max results per source (default 10): ") or 10)
                print(f"\n🔍 Multi-source search for: {query}")
                print(f"Sources: {', '.join(sources)}")
                results = engine.search_multiple_sources(query, sources, max_results)
                display_results(results)
                save_results_option(engine, query, results)

        elif choice == 11:
            # Generate Report from existing results
            if not engine.results:
                print("❌ No results to generate report from. Perform a search first.")
            else:
                query = input("Enter query for report title: ").strip() or "OSINT Search"
                filename = input("Enter output filename (optional): ").strip()
                engine.generate_report(query, engine.results, filename or None)

        print()  # Add spacing between operations


if __name__ == "__main__":
    try:
        main_interactive()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        import traceback

        traceback.print_exc()
        print("Please check your internet connection and try again.")