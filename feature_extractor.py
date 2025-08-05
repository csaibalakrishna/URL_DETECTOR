import re
import socket
import whois
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import logging
from datetime import datetime, timedelta
import dns.resolver
import ssl
import subprocess
import os

class URLFeatureExtractor:
    def __init__(self):
        self.shortening_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'lnkd.in',
            'youtu.be', 'amzn.to', 'fb.me', 'po.st', 'tinycc.com',
            'shorte.st', 'linktr.ee'
        ]
        self.popular_sites = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'youtube',
            'twitter', 'instagram', 'linkedin', 'github', 'stackoverflow',
            'reddit', 'wikipedia', 'replit', 'codepen', 'netlify', 'vercel'
        ]
        self.timeout = 10
        
    def extract_features(self, url):
        """Extract all 30+ features from URL"""
        features = {}
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Basic URL features
            features['Index'] = 1  # Feature index
            features['UsingIP'] = self._using_ip(domain)
            features['LongURL'] = self._long_url(url)
            features['ShortURL'] = self._short_url(domain)
            features['Symbol@'] = self._symbol_at(url)
            features['Redirecting//'] = self._redirecting_double_slash(url)
            features['PrefixSuffix-'] = self._prefix_suffix_dash(domain)
            features['SubDomains'] = self._count_subdomains(domain)
            features['HTTPS'] = self._https_protocol(parsed_url.scheme)
            features['DomainRegLen'] = self._domain_registration_length(domain)
            features['NonStdPort'] = self._non_standard_port(parsed_url.port)
            
            # Try to fetch webpage content
            try:
                response = requests.get(url, timeout=self.timeout, verify=False, 
                                      allow_redirects=True, headers={
                                          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                                      })
                soup = BeautifulSoup(response.content, 'html.parser')
                final_url = response.url
                
                # Content-based features
                features['Favicon'] = self._favicon_analysis(soup, domain)
                features['HTTPSDomainURL'] = self._https_domain_url(soup, domain)
                features['RequestURL'] = self._request_url_analysis(soup, domain)
                features['AnchorURL'] = self._anchor_url_analysis(soup, domain)
                features['LinksInScriptTags'] = self._links_in_script_tags(soup, domain)
                features['ServerFormHandler'] = self._server_form_handler(soup, domain)
                features['InfoEmail'] = self._info_email(soup)
                features['AbnormalURL'] = self._abnormal_url(url, domain)
                features['WebsiteForwarding'] = self._website_forwarding(url, final_url)
                features['StatusBarCust'] = self._status_bar_customization(soup)
                features['DisableRightClick'] = self._disable_right_click(soup)
                features['UsingPopupWindow'] = self._using_popup_window(soup)
                features['IframeRedirection'] = self._iframe_redirection(soup)
                
            except Exception as e:
                logging.warning(f"Could not fetch webpage content: {e}")
                # Set default values for content-based features
                features.update({
                    'Favicon': 1, 'HTTPSDomainURL': 1, 'RequestURL': 1,
                    'AnchorURL': 1, 'LinksInScriptTags': 1, 'ServerFormHandler': 1,
                    'InfoEmail': 1, 'AbnormalURL': 1, 'WebsiteForwarding': 0,
                    'StatusBarCust': 1, 'DisableRightClick': 1, 'UsingPopupWindow': 1,
                    'IframeRedirection': 1
                })
            
            # Domain-based features
            features['AgeofDomain'] = self._age_of_domain(domain)
            features['DNSRecording'] = self._dns_recording(domain)
            features['WebsiteTraffic'] = self._website_traffic(domain)
            features['PageRank'] = self._page_rank(domain)
            features['GoogleIndex'] = self._google_index(domain)
            features['LinksPointingToPage'] = self._links_pointing_to_page(url)
            features['StatsReport'] = self._stats_report(domain)
            
            # Classification placeholder (will be predicted by ML model)
            features['class'] = -1
            
        except Exception as e:
            logging.error(f"Error extracting features: {e}")
            # Return default suspicious values if extraction fails
            features = self._get_default_features()
            
        return features
    
    def _using_ip(self, domain):
        """Check if URL uses IP address instead of domain name"""
        try:
            socket.inet_aton(domain.split(':')[0])
            return 1  # Using IP
        except:
            return 0  # Using domain name
    
    def _long_url(self, url):
        """Check if URL is longer than 75 characters"""
        return 1 if len(url) > 75 else 0
    
    def _short_url(self, domain):
        """Check if URL uses shortening service"""
        # Check for exact match or domain contains shortening service
        for service in self.shortening_services:
            if service == domain or domain.endswith('.' + service):
                return 1
        return 0
    
    def _symbol_at(self, url):
        """Check if URL contains @ symbol"""
        return 1 if '@' in url else 0
    
    def _redirecting_double_slash(self, url):
        """Check for // pattern indicating redirection"""
        return 1 if url.count('//') > 1 else 0
    
    def _prefix_suffix_dash(self, domain):
        """Check if domain has prefix-suffix pattern with dash"""
        return 1 if '-' in domain else 0
    
    def _count_subdomains(self, domain):
        """Count number of subdomains"""
        parts = domain.split('.')
        if len(parts) <= 2:
            return 0  # No subdomains
        elif len(parts) == 3:
            return 1  # One subdomain
        else:
            return 2  # Multiple subdomains (suspicious)
    
    def _https_protocol(self, scheme):
        """Check if URL uses HTTPS"""
        return 0 if scheme == 'https' else 1
    
    def _domain_registration_length(self, domain):
        """Get domain registration length (simplified heuristic)"""
        try:
            domain_lower = domain.lower()
            # Popular/established sites likely have long registrations
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # Long registration
            
            # Well-known TLDs and reasonable domain names likely have proper registration
            if (len(domain.split('.')) == 2 and 
                domain.split('.')[1] in ['com', 'org', 'net', 'edu', 'gov', 'mil'] and
                len(domain.split('.')[0]) > 3):
                return 0  # Likely long registration
            
            return 1  # Potentially short registration
        except:
            pass
        return 1
    
    def _non_standard_port(self, port):
        """Check if URL uses non-standard port"""
        if port is None:
            return 0  # Standard port
        return 1 if port not in [80, 443] else 0
    
    def _favicon_analysis(self, soup, domain):
        """Analyze favicon source"""
        try:
            favicon_links = soup.find_all('link', rel=lambda x: x and 'icon' in x.lower())
            for link in favicon_links:
                href = link.get('href', '')
                if href and not href.startswith('data:'):
                    favicon_domain = urlparse(urljoin('http://' + domain, href)).netloc
                    if favicon_domain != domain:
                        return 1  # External favicon (suspicious)
        except:
            pass
        return 0
    
    def _https_domain_url(self, soup, domain):
        """Check HTTPS usage in domain URLs"""
        try:
            links = soup.find_all(['a', 'img', 'script', 'link'])
            https_count = 0
            total_count = 0
            
            for link in links:
                href = link.get('href') or link.get('src')
                if href and href.startswith('http'):
                    total_count += 1
                    if href.startswith('https'):
                        https_count += 1
            
            if total_count > 0:
                https_ratio = https_count / total_count
                return 0 if https_ratio > 0.5 else 1
        except:
            pass
        return 1
    
    def _request_url_analysis(self, soup, domain):
        """Analyze request URLs from different domains"""
        try:
            external_requests = 0
            total_requests = 0
            
            for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src:
                    total_requests += 1
                    if src.startswith('http'):
                        req_domain = urlparse(src).netloc
                        if req_domain != domain:
                            external_requests += 1
            
            if total_requests > 0:
                external_ratio = external_requests / total_requests
                return 1 if external_ratio > 0.25 else 0
        except:
            pass
        return 1
    
    def _anchor_url_analysis(self, soup, domain):
        """Analyze anchor URLs pointing to different domains"""
        try:
            external_anchors = 0
            total_anchors = 0
            
            for anchor in soup.find_all('a', href=True):
                total_anchors += 1
                href = anchor['href']
                if href.startswith('http'):
                    anchor_domain = urlparse(href).netloc
                    if anchor_domain != domain:
                        external_anchors += 1
            
            if total_anchors > 0:
                external_ratio = external_anchors / total_anchors
                return 1 if external_ratio > 0.31 else 0
        except:
            pass
        return 1
    
    def _links_in_script_tags(self, soup, domain):
        """Analyze links in script tags"""
        try:
            scripts = soup.find_all('script', src=True)
            external_scripts = 0
            
            for script in scripts:
                src = script['src']
                if src.startswith('http'):
                    script_domain = urlparse(src).netloc
                    if script_domain != domain:
                        external_scripts += 1
            
            total_scripts = len(scripts)
            if total_scripts > 0:
                external_ratio = external_scripts / total_scripts
                return 1 if external_ratio > 0.17 else 0
        except:
            pass
        return 1
    
    def _server_form_handler(self, soup, domain):
        """Check if form handler is from different domain"""
        try:
            forms = soup.find_all('form', action=True)
            for form in forms:
                action = form['action']
                if action.startswith('http'):
                    form_domain = urlparse(action).netloc
                    if form_domain != domain:
                        return 1  # External form handler (suspicious)
        except:
            pass
        return 0
    
    def _info_email(self, soup):
        """Check for email addresses in webpage"""
        try:
            text = soup.get_text()
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, text)
            return 0 if emails else 1
        except:
            pass
        return 1
    
    def _abnormal_url(self, url, domain):
        """Check if URL appears abnormal (simplified heuristic)"""
        try:
            domain_lower = domain.lower()
            # Popular sites are not abnormal
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # Normal URL
            
            # Check for obviously suspicious patterns
            if (len(domain.replace('.', '').replace('-', '')) < 3 or  # Very short domain
                domain.count('-') > 3 or  # Too many dashes
                domain.count('.') > 4 or  # Too many subdomains
                any(char.isdigit() for char in domain.split('.')[0]) and len(domain.split('.')[0]) < 6):  # Numbers in short domain
                return 1  # Abnormal
            
            return 0  # Appears normal
        except:
            pass
        return 1
    
    def _website_forwarding(self, original_url, final_url):
        """Check if website forwards to different domain"""
        try:
            original_domain = urlparse(original_url).netloc
            final_domain = urlparse(final_url).netloc
            return 1 if original_domain != final_domain else 0
        except:
            pass
        return 0
    
    def _status_bar_customization(self, soup):
        """Check for status bar customization"""
        try:
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and ('status' in script.string.lower() or 'defaultstatus' in script.string.lower()):
                    return 1
        except:
            pass
        return 0
    
    def _disable_right_click(self, soup):
        """Check if right-click is disabled"""
        try:
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and ('contextmenu' in script.string.lower() or 'oncontextmenu' in script.string.lower()):
                    return 1
        except:
            pass
        return 0
    
    def _using_popup_window(self, soup):
        """Check for popup window usage"""
        try:
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and ('window.open' in script.string or 'popup' in script.string.lower()):
                    return 1
        except:
            pass
        return 0
    
    def _iframe_redirection(self, soup):
        """Check for iframe redirection"""
        try:
            iframes = soup.find_all('iframe')
            return 1 if iframes else 0
        except:
            pass
        return 0
    
    def _age_of_domain(self, domain):
        """Estimate age of domain (simplified heuristic)"""
        try:
            domain_lower = domain.lower()
            # Popular/established sites are definitely old
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # Old domain
            
            # Heuristics for potentially old domains
            if (domain.split('.')[1] in ['edu', 'gov', 'mil'] or  # Institutional domains
                (len(domain.split('.')) == 2 and 
                 len(domain.split('.')[0]) > 4 and 
                 domain.split('.')[1] in ['com', 'org', 'net'] and
                 '-' not in domain)):  # Clean, simple domains
                return 0  # Likely old
            
            return 1  # Potentially new
        except:
            pass
        return 1
    
    def _dns_recording(self, domain):
        """Check if DNS record exists"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return 0 if answers else 1
        except:
            return 1
    
    def _website_traffic(self, domain):
        """Estimate website traffic (simplified)"""
        try:
            # Check if domain contains popular site names
            domain_lower = domain.lower()
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # High traffic
            
            # Additional heuristics for legitimate sites
            if (len(domain.split('.')) == 2 and  # TLD + domain only
                len(domain.split('.')[0]) > 3 and  # Domain name longer than 3 chars
                '-' not in domain):  # No dashes
                return 0  # Likely legitimate
            
            return 1  # Low traffic (more suspicious)
        except:
            pass
        return 1
    
    def _page_rank(self, domain):
        """Get Google PageRank (simplified estimation)"""
        try:
            domain_lower = domain.lower()
            # Check if it's a popular/well-known site
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # High PageRank
            
            # Simple heuristic: clean domains without many subdomains or dashes
            if (len(domain.split('.')) <= 2 and 
                '-' not in domain and 
                len(domain.split('.')[0]) > 3):
                return 0  # Likely higher PageRank
            return 1  # Likely lower PageRank
        except:
            pass
        return 1
    
    def _google_index(self, domain):
        """Check if website is indexed by Google"""
        try:
            domain_lower = domain.lower()
            # Popular sites are definitely indexed
            for popular in self.popular_sites:
                if popular in domain_lower:
                    return 0  # Indexed
            
            # For other domains, assume indexed if they look legitimate
            if (len(domain.split('.')) == 2 and  # Simple domain structure
                len(domain.split('.')[0]) > 2 and  # Reasonable length
                domain.split('.')[1] in ['com', 'org', 'net', 'edu', 'gov']):  # Common TLD
                return 0  # Likely indexed
            
            return 1  # Likely not indexed
        except:
            pass
        return 1
    
    def _links_pointing_to_page(self, url):
        """Estimate number of external links pointing to page"""
        try:
            # This would typically use backlink analysis APIs
            # For now, return a heuristic based on domain authority
            domain = urlparse(url).netloc
            if any(popular in domain for popular in ['edu', 'gov', 'org']):
                return 0  # Likely has many backlinks
            return 1  # Likely has few backlinks
        except:
            pass
        return 1
    
    def _stats_report(self, domain):
        """Check availability of statistics report"""
        try:
            # Check if domain has statistics/analytics pages
            stats_urls = [f"http://{domain}/stats", f"http://{domain}/statistics", f"http://{domain}/analytics"]
            for stats_url in stats_urls:
                try:
                    response = requests.get(stats_url, timeout=5)
                    if response.status_code == 200:
                        return 0  # Stats available
                except:
                    continue
            return 1  # No stats available
        except:
            pass
        return 1
    
    def _get_default_features(self):
        """Return default suspicious feature values"""
        return {
            'Index': 1, 'UsingIP': 1, 'LongURL': 1, 'ShortURL': 1, 'Symbol@': 1,
            'Redirecting//': 1, 'PrefixSuffix-': 1, 'SubDomains': 2, 'HTTPS': 1,
            'DomainRegLen': 1, 'Favicon': 1, 'NonStdPort': 1, 'HTTPSDomainURL': 1,
            'RequestURL': 1, 'AnchorURL': 1, 'LinksInScriptTags': 1, 'ServerFormHandler': 1,
            'InfoEmail': 1, 'AbnormalURL': 1, 'WebsiteForwarding': 1, 'StatusBarCust': 1,
            'DisableRightClick': 1, 'UsingPopupWindow': 1, 'IframeRedirection': 1,
            'AgeofDomain': 1, 'DNSRecording': 1, 'WebsiteTraffic': 1, 'PageRank': 1,
            'GoogleIndex': 1, 'LinksPointingToPage': 1, 'StatsReport': 1, 'class': -1
        }
