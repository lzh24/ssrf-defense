package com.saferequest;
import java.io.IOException;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;
import javax.net.ssl.*;
import java.security.SecureRandom;

/**
 * SafeRequestV2: Secure HTTP request utility preventing SSRF.
 */
public class SafeRequestV2 {

    public static void main(String[] args) throws SSRFException, IOException {
        Response response = new SafeRequestV2().request("https://example.com/sample.png",new RequestOptions().method("GET"));
        System.out.println(response.getStatusCode());
    }

    // Configuration constants
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of("http", "https");
    private static final int MAX_REDIRECTS = 5;

    // Exception class
    public static class SSRFException extends Exception {
        public SSRFException(String message) {
            super(message);
        }
    }

    // Request Options
    public static class RequestOptions {
        private String method = "GET";
        private Map<String, String> headers = new HashMap<>();
        private String body = null;
        private int timeoutSeconds = 30;
        private boolean followRedirects = true;
        private boolean verifySSL = false;

        public RequestOptions method(String method) { this.method = method; return this; }
        public RequestOptions header(String name, String value) { this.headers.put(name, value); return this; }
        public RequestOptions body(String body) { this.body = body; return this; }
        public RequestOptions timeout(int seconds) { this.timeoutSeconds = seconds; return this; }
        public RequestOptions followRedirects(boolean follow) { this.followRedirects = follow; return this; }
        public RequestOptions verifySSL(boolean verify) { this.verifySSL = verify; return this; }

        public String getMethod() { return method; }
        public Map<String, String> getHeaders() { return headers; }
        public String getBody() { return body; }
        public int getTimeoutSeconds() { return timeoutSeconds; }
        public boolean isFollowRedirects() { return followRedirects; }
        public boolean isVerifySSL() { return verifySSL; }
    }

    // Response class
    public static class Response {
        private final int statusCode;
        private final Map<String, List<String>> headers;
        private final String body;

        public Response(int statusCode, Map<String, List<String>> headers, String body) {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }

        public int getStatusCode() { return statusCode; }
        public String getBody() { return body; }
    }

    /**
     * Resolve domain and validate IP
     */
    private static String resolveAndValidate(String host) throws SSRFException {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isUnsafeIP(addr)) {
                    throw new SSRFException("Blocked private or unsafe IP: " + addr.getHostAddress());
                }
            }
            // Return the first valid IP
            return addresses[0].getHostAddress();
        } catch (UnknownHostException e) {
            throw new SSRFException("Unknown host: " + host);
        }
    }

    /**
     * Strict IP validation
     */
    private static boolean isUnsafeIP(InetAddress addr) {
        if (addr.isAnyLocalAddress() ||  // 0.0.0.0
                addr.isLoopbackAddress() ||  // 127.0.0.1
                addr.isLinkLocalAddress() || // 169.254.x.x
                addr.isSiteLocalAddress() || // 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                addr.isMulticastAddress()) {
            return true;
        }

        // Extra check for potential IPv6 mapped addresses or edge cases
        byte[] address = addr.getAddress();
        // 0.0.0.0 (IPv4)
        if (address.length == 4) {
            if (address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0) return true;
            // 如需拦截其他自定义内网网段，在此追加判断即可
        }

        return false;
    }

    /**
     * Validates URL and returns a safe URL (with IP) and the original host
     */
    private static String[] validateURL(String rawURL) throws SSRFException {
        try {
            URL url = new URL(rawURL);

            if (!ALLOWED_PROTOCOLS.contains(url.getProtocol().toLowerCase())) {
                throw new SSRFException("Unsupported protocol");
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                throw new SSRFException("Invalid URL");
            }

            // Resolve and check IP
            String ip = resolveAndValidate(host);

            // Reconstruct URL with IP to prevent DNS rebinding during connection
            // Note: This relies on using the IP for connection but Host header for virtual hosting
            String newURL = rawURL.replaceFirst(Pattern.quote(host), ip);
            return new String[]{newURL, host};

        } catch (MalformedURLException e) {
            throw new SSRFException("Invalid URL format");
        }
    }

    /**
     * Disable SSL Verification (Same as V1)
     */
    private static void disableSSLVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) { return true; }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) { /* Ignore */ }
    }

    /**
     * Custom SSLSocketFactory to force connection to a specific IP while preserving SNI for the hostname.
     */
    private static class SafeSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String forceIp;

        public SafeSSLSocketFactory(SSLSocketFactory delegate, String forceIp) {
            this.delegate = delegate;
            this.forceIp = forceIp;
        }

        @Override
        public String[] getDefaultCipherSuites() { return delegate.getDefaultCipherSuites(); }
        @Override
        public String[] getSupportedCipherSuites() { return delegate.getSupportedCipherSuites(); }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            // This is the key method for SNI. 's' is usually null or a layered socket.
            // If we want to force IP, we should create a socket to IP first?
            // BUT HttpsURLConnection often calls createSocket(Socket s, String host, int port, boolean autoClose)
            // on an existing socket for PROXYING.
            // For direct connections, it calls createSocket(host, port) or createSocket(inetAddr, port).

            // Wait, for HttpsURLConnection, if we set the SSLSocketFactory, it uses it to create the socket.
            // We want to override the connection target.
            return delegate.createSocket(s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            // Override DNS: Connect to forceIp instead of host
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(forceIp, port));

            // Layer SSL over it with SNI host
            return delegate.createSocket(socket, host, port, true);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localHost, localPort));
            socket.connect(new InetSocketAddress(forceIp, port));
            return delegate.createSocket(socket, host, port, true);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            // Should not happen if we use URL with hostname, but safe fallback
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(forceIp, port));
            return delegate.createSocket(socket, host.getHostName(), port, true);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, localPort));
            socket.connect(new InetSocketAddress(forceIp, port));
            return delegate.createSocket(socket, address.getHostName(), port, true);
        }
    }

    public static Response get(String url) throws SSRFException, IOException {
        return request(url, new RequestOptions().method("GET"));
    }

    public static Response request(String initialUrl, RequestOptions options) throws SSRFException, IOException {
        int redirectCount = 0;
        String currentUrlStr = initialUrl;

        if (options == null) options = new RequestOptions();

        // Ensure we have a delegate factory (either system default or trust-all)
        SSLSocketFactory baseSSLSocketFactory;
        if (!options.isVerifySSL()) {
            disableSSLVerification(); // Sets default factory to trust-all
            baseSSLSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        } else {
            baseSSLSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        while (true) {
            // Validate current URL
            String[] validResult = validateURL(currentUrlStr);
            String safeIp = validResult[0]; // Wait, validateURL returns [safeUrl, host] or something?
            // Let's refactor validateURL to return validated IP and Hostname separately?
            // The old validateURL returned [newURL(with IP), originalHost].
            // But for HTTPS we need newURL to be ORIGINAL URL (with Host).

            // Let's modify logic here slightly relying on existing validateURL...
            // Old: safeUrlStr = "https://<IP>/...", originalHost = "<Hostname>"
            // New Logic:
            // 1. Resolve & Check IP.
            // 2. If HTTPS: safeUrlStr = "https://<Hostname>/...", Set SSLSocketFactory(IP).
            // 3. If HTTP: safeUrlStr = "http://<IP>/...", Set Host Header.

            // We need to re-parse because validateURL was doing replacement.
            // Converting implementation of validateURL to helper 'resolveSafeIP' would be cleaner,
            // but to minimize changes, let's extract IP from the "safeUrlStr" if it was replaced.

            // Actually, let's just parse the currentUrlStr again here for clarity and safety.
            URL parsedObj = new URL(currentUrlStr);
            String host = parsedObj.getHost();
            if (host == null || host.isEmpty()) throw new SSRFException("Invalid URL");

            String resolvedIP = resolveAndValidate(host); // Doing the security check

            URL connectionUrl;
            HttpURLConnection connection;

            if ("https".equalsIgnoreCase(parsedObj.getProtocol())) {
                // HTTPS: Use domain in URL for SNI, use custom Factory for IP pinning
                connectionUrl = new URL(currentUrlStr);
                connection = (HttpURLConnection) connectionUrl.openConnection();
                if (connection instanceof HttpsURLConnection) {
                    ((HttpsURLConnection) connection).setSSLSocketFactory(new SafeSSLSocketFactory(baseSSLSocketFactory, resolvedIP));
                    // Also set HostnameVerifier if verifySSL is false (already done globally by disableSSLVerification,
                    // but good to ensure if we want per-connection)
                }
            } else {
                // HTTP: Replace Host with IP in URL to force connection, set Host header
                // (Existing logic effectively)
                String ipUrl = currentUrlStr.replaceFirst(Pattern.quote(host), resolvedIP);
                connectionUrl = new URL(ipUrl);
                connection = (HttpURLConnection) connectionUrl.openConnection();
            }

            // CRITICAL: Disable automatic redirect following
            connection.setInstanceFollowRedirects(false);

            // Setup connection
            connection.setRequestMethod(options.getMethod());
            connection.setConnectTimeout(options.getTimeoutSeconds() * 1000);
            connection.setReadTimeout(options.getTimeoutSeconds() * 1000);

            // Headers
            for (Map.Entry<String, String> header : options.getHeaders().entrySet()) {
                connection.setRequestProperty(header.getKey(), header.getValue());
            }
            // Ensure Host header matches original hostname
            // (Important for HTTP IP-URL, and doesn't hurt for HTTPS Domain-URL)
            connection.setRequestProperty("Host", host);

            // Body
            if (options.getBody() != null && !options.getBody().isEmpty()) {
                connection.setDoOutput(true);
                connection.getOutputStream().write(options.getBody().getBytes("UTF-8"));
            }

            // Execute
            int statusCode = connection.getResponseCode();

            // Handle Redirects
            if (options.isFollowRedirects() && (statusCode >= 300 && statusCode < 400)) {
                if (redirectCount >= MAX_REDIRECTS) {
                    throw new SSRFException("Too many redirects");
                }

                String location = connection.getHeaderField("Location");
                if (location == null) {
                    throw new SSRFException("Redirect without Location header");
                }

                // Handle relative URLs
                URL baseUrl = new URL(currentUrlStr);
                URL nextUrl = new URL(baseUrl, location);
                currentUrlStr = nextUrl.toString();

                redirectCount++;
                connection.disconnect();
                continue; // Loop again to validate the new URL
            }

            // Read Response
            String responseBody;
            try {
                Scanner scanner = new Scanner(
                        statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream(),
                        "UTF-8"
                );
                responseBody = scanner.useDelimiter("\\A").hasNext() ? scanner.next() : "";
                scanner.close();
            } catch (Exception e) {
                responseBody = "";
            }

            return new Response(statusCode, connection.getHeaderFields(), responseBody);
        }
    }
}
