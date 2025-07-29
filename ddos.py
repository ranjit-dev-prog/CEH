import requests
import threading
import time

def send_requests(url, requests_per_thread, timeout):
    for _ in range(requests_per_thread):
        try:
            response = requests.get(url, timeout=timeout)
            print(f"[+] Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")

def main():
    print("== HTTP Load Testing Tool (Ethical Use Only) ==")

    # 🔧 Get user input
    target_url = input("Enter target URL (with http:// or https://): ").strip()
    num_threads = int(input("Enter number of threads (simulated users): ").strip())
    requests_per_thread = int(input("Enter number of requests per thread: ").strip())
    timeout = int(input("Enter request timeout in seconds (default 5): ") or 5)

    print("\n[!] Starting load test. Do not use on unauthorized targets!\n")
    start_time = time.time()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=send_requests, args=(target_url, requests_per_thread, timeout))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = time.time()
    print(f"\n[✓] Load test completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
