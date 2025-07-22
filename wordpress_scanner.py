import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Function to check if the site is WordPress
def is_wordpress_site(url):
    try:
        # Send GET request to the URL
        response = requests.get(url, timeout=10)
        status_code = response.status_code
        # If status code is not 200, site might be inaccessible
        if status_code != 200:
            print(f"HTTP Status Code: {status_code}")
            print("Site is not accessible or returned non-200 status.")
            return False, status_code, None

        html = response.text
        # Check for WordPress indicators in the HTML content
        if 'wp-content' in html or 'wp-includes' in html or 'wp-json' in html:
            return True, status_code, html
        else:
            return False, status_code, html
    except requests.RequestException as e:
        print(f"Error accessing site: {e}")
        return False, None, None

# Function to get the theme name from the HTML
def get_theme(html):
    soup = BeautifulSoup(html, 'html.parser')
    theme = None
    # Check meta tag for generator info
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator and 'WordPress' in generator.get('content', ''):
        theme = generator.get('content')
    # Check link tags for theme stylesheet URL
    for link in soup.find_all('link', href=True):
        href = link['href']
        if 'wp-content/themes/' in href:
            # Extract theme folder name from URL
            theme = href.split('wp-content/themes/')[1].split('/')[0]
            break
    return theme

# Function to check for common plugins by accessing their directories
def get_plugins(url):
    common_plugins = [
        'akismet', 'contact-form-7', 'wordpress-seo', 'jetpack', 'woocommerce',
        'google-analytics-for-wordpress', 'wp-super-cache', 'all-in-one-seo-pack'
    ]
    found_plugins = []
    for plugin in common_plugins:
        plugin_url = urljoin(url, f'wp-content/plugins/{plugin}/')
        try:
            r = requests.get(plugin_url, timeout=5)
            if r.status_code == 200:
                found_plugins.append(plugin)
        except requests.RequestException:
            continue
    return found_plugins

# Main function to scan the WordPress site
def scan_wordpress_site(url):
    print(f"Scanning {url} ...")
    is_wp, status_code, html = is_wordpress_site(url)
    print(f"HTTP Status Code: {status_code}")
    if not is_wp:
        print("This site does not appear to be a WordPress site.")
        return

    print("WordPress site detected.")
    theme = get_theme(html)
    if theme:
        print(f"Theme detected: {theme}")
    else:
        print("Theme could not be detected.")

    plugins = get_plugins(url)
    if plugins:
        print(f"Plugins detected: {', '.join(plugins)}")
    else:
        print("No common plugins detected.")

# Entry point of the script
if __name__ == "__main__":
    target_url = input("Enter the website URL to scan: ").strip()
    # Add http scheme if missing
    if not urlparse(target_url).scheme:
        target_url = 'http://' + target_url
    scan_wordpress_site(target_url)
