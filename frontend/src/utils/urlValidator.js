/**
 * AihaX Frontend Concrete Target URL Validator
 *
 * Guarantees that only valid concrete HTTP/HTTPS URLs are accepted as assessment targets.
 * Scope wildcard rules (e.g. *.shopify.com) and non-HTTP schemes are strictly rejected.
 */

export function validateConcreteTargetUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      valid: false,
      error: 'Enter a concrete HTTP/HTTPS target URL, for example https://example.com.',
    };
  }

  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return {
      valid: false,
      error: 'Target URL cannot be empty or whitespace only.',
    };
  }

  // Reject wildcards explicitly
  if (trimmed.includes('*')) {
    return {
      valid: false,
      error: 'Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.',
    };
  }

  // Require explicit http:// or https:// scheme (reject bare hostnames like example.com or *.example.com)
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    return {
      valid: false,
      error: 'Target URL must start with http:// or https:// (e.g. https://example.com).',
    };
  }

  try {
    const parsed = new URL(trimmed);

    // Protocol check
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: `Protocol '${parsed.protocol}' is not allowed. Only HTTP and HTTPS are permitted.`,
      };
    }

    // Hostname check
    const hostname = parsed.hostname?.trim()?.toLowerCase();
    if (!hostname || hostname.includes('*')) {
      return {
        valid: false,
        error: 'Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.',
      };
    }

    // Userinfo / credentials check
    if (parsed.username || parsed.password) {
      return {
        valid: false,
        error: 'User credentials in target URL are not permitted.',
      };
    }

    // Port check
    if (parsed.port) {
      const portNum = parseInt(parsed.port, 10);
      if (isNaN(portNum) || portNum <= 0 || portNum > 65535) {
        return {
          valid: false,
          error: 'Port number must be between 1 and 65535.',
        };
      }
    }

    return {
      valid: true,
      host: hostname,
      url: trimmed,
      normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
    };
  } catch {
    return {
      valid: false,
      error: 'Enter a complete HTTP/HTTPS target URL, for example https://example.com.',
    };
  }
}
